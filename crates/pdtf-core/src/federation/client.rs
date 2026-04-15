//! Federation Registry Resolver — fetches and caches a static JSON registry.
//!
//! This is the bootstrap approach wrapped in the `TrustResolver` trait.
//! Default source: `registry.propdata.org.uk/v1/federation`.

use async_trait::async_trait;

use crate::error::{PdtfError, Result};
use crate::federation::TrustResolver;
use crate::types::{
    FederationAccountProvider, FederationIssuerEntry, FederationRegistry, IssuerStatus, TrustMark,
    TrustResolutionResult,
};
use std::sync::Mutex;

/// Federation registry resolver backed by an in-memory JSON registry cache.
pub struct FederationRegistryResolver {
    cached: Mutex<Option<FederationRegistry>>,
}

impl FederationRegistryResolver {
    /// Create a new empty resolver.
    pub fn new() -> Self {
        Self {
            cached: Mutex::new(None),
        }
    }

    /// Create a resolver pre-loaded with a registry (useful for testing).
    pub fn with_registry(registry: FederationRegistry) -> Self {
        Self {
            cached: Mutex::new(Some(registry)),
        }
    }

    /// Load a registry from a JSON string.
    pub fn load_from_json(&self, json: &str) -> Result<FederationRegistry> {
        let registry: FederationRegistry = serde_json::from_str(json)?;
        *self
            .cached
            .lock()
            .map_err(|_| PdtfError::FederationError("Registry cache lock poisoned".into()))? =
            Some(registry.clone());
        Ok(registry)
    }

    /// Fetch registry from a URL.
    #[cfg(feature = "network")]
    pub async fn fetch(&self, url: &str) -> Result<FederationRegistry> {
        let client = reqwest::Client::new();
        let response = client
            .get(url)
            .header("Accept", "application/json")
            .timeout(std::time::Duration::from_secs(10))
            .send()
            .await
            .map_err(|e| PdtfError::FederationError(format!("Failed to fetch registry: {e}")))?;

        if !response.status().is_success() {
            return Err(PdtfError::FederationError(format!(
                "Registry fetch failed: HTTP {}",
                response.status()
            )));
        }

        let registry: FederationRegistry = response
            .json()
            .await
            .map_err(|e| PdtfError::FederationError(format!("Invalid registry JSON: {e}")))?;

        *self
            .cached
            .lock()
            .map_err(|_| PdtfError::FederationError("Registry cache lock poisoned".into()))? =
            Some(registry.clone());
        Ok(registry)
    }

    /// Get the current federation registry.
    pub async fn get_registry(&self) -> Result<FederationRegistry> {
        let cached = self
            .cached
            .lock()
            .map_err(|_| PdtfError::FederationError("Registry cache lock poisoned".into()))?
            .clone();
        match cached {
            Some(reg) => Ok(reg),
            None => Err(PdtfError::FederationError(
                "No federation registry loaded. Call load_from_json() or fetch() first.".into(),
            )),
        }
    }

    /// Look up an issuer by DID.
    pub async fn find_issuer_by_did(&self, did: &str) -> Result<Option<(String, FederationIssuerEntry)>> {
        let registry = self.get_registry().await?;
        for (slug, entry) in &registry.issuers {
            if entry.did == did {
                return Ok(Some((slug.clone(), entry.clone())));
            }
        }
        Ok(None)
    }

    /// Look up an account provider by DID.
    pub async fn find_account_provider_by_did(
        &self,
        did: &str,
    ) -> Result<Option<(String, FederationAccountProvider)>> {
        let registry = self.get_registry().await?;
        for (slug, entry) in &registry.user_account_providers {
            if entry.did == did {
                return Ok(Some((slug.clone(), entry.clone())));
            }
        }
        Ok(None)
    }

    /// Get the cached registry, if any.
    pub fn get_cached(&self) -> Option<FederationRegistry> {
        self.cached.lock().ok()?.clone()
    }

    /// Clear the cache.
    pub fn clear_cache(&self) {
        if let Ok(mut cached) = self.cached.lock() {
            *cached = None;
        }
    }
}

impl Default for FederationRegistryResolver {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl TrustResolver for FederationRegistryResolver {
    async fn resolve_trust(
        &self,
        issuer_did: &str,
        _trust_anchor_did: Option<&str>,
    ) -> TrustResolutionResult {
        let registry = match self.get_registry().await {
            Ok(r) => r,
            Err(e) => {
                return TrustResolutionResult {
                    trusted: false,
                    issuer_slug: None,
                    trust_marks: vec![],
                    warnings: vec![format!("Failed to load registry: {e}")],
                };
            }
        };

        // Find issuer by DID
        let issuer = registry.issuers.values().find(|e| e.did == issuer_did);

        let issuer = match issuer {
            Some(i) => i,
            None => {
                return TrustResolutionResult {
                    trusted: false,
                    issuer_slug: None,
                    trust_marks: vec![],
                    warnings: vec![format!("Issuer not found in registry: {issuer_did}")],
                };
            }
        };

        let mut warnings = Vec::new();
        let mut trusted = true;

        // Check status
        match issuer.status {
            IssuerStatus::Active => {}
            IssuerStatus::Deprecated => {
                warnings.push(format!(
                    "Issuer '{}' status is deprecated — may be removed in future",
                    issuer.slug
                ));
            }
            IssuerStatus::Planned => {
                warnings.push(format!(
                    "Issuer '{}' status is planned — not yet active",
                    issuer.slug
                ));
                trusted = false;
            }
            IssuerStatus::Revoked => {
                warnings.push(format!("Issuer '{}' has been revoked", issuer.slug));
                trusted = false;
            }
        }

        // Check validity window
        let now = chrono::Utc::now();

        if let Some(ref valid_from) = issuer.valid_from {
            match chrono::DateTime::parse_from_rfc3339(valid_from) {
                Ok(from_dt) => {
                    if from_dt > now {
                        warnings.push(format!(
                            "Issuer '{}' is not yet active (validFrom: {})",
                            issuer.slug, valid_from
                        ));
                        trusted = false;
                    }
                }
                Err(_) => {
                    warnings.push(format!(
                        "Issuer '{}' has unparseable validFrom '{}' — treating as untrusted",
                        issuer.slug, valid_from
                    ));
                    trusted = false;
                }
            }
        }

        if let Some(ref valid_until) = issuer.valid_until {
            match chrono::DateTime::parse_from_rfc3339(valid_until) {
                Ok(until_dt) => {
                    if until_dt < now {
                        warnings.push(format!(
                            "Issuer '{}' has expired (validUntil: {})",
                            issuer.slug, valid_until
                        ));
                        trusted = false;
                    }
                }
                Err(_) => {
                    warnings.push(format!(
                        "Issuer '{}' has unparseable validUntil '{}' — treating as untrusted",
                        issuer.slug, valid_until
                    ));
                    trusted = false;
                }
            }
        }

        // Status must be Active for trust (deprecated is still a non-Active status)
        if issuer.status != IssuerStatus::Active {
            trusted = false;
        }

        let trust_mark = TrustMark {
            trust_level: issuer.trust_level.clone(),
            authorised_paths: issuer.authorised_paths.clone(),
        };

        TrustResolutionResult {
            trusted,
            issuer_slug: Some(issuer.slug.clone()),
            trust_marks: vec![trust_mark],
            warnings,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::*;
    use std::collections::HashMap;

    fn sample_registry() -> FederationRegistry {
        let mut issuers = HashMap::new();
        issuers.insert(
            "moverly-epc".to_string(),
            FederationIssuerEntry {
                slug: "moverly-epc".to_string(),
                did: "did:web:epc.moverly.com".to_string(),
                name: "Moverly EPC Adapter".to_string(),
                trust_level: TrustLevel::TrustedProxy,
                status: IssuerStatus::Active,
                authorised_paths: vec!["Property:/energyEfficiency/*".to_string()],
                proxy_for: None,
                valid_from: None,
                valid_until: None,
                regulatory_registration: None,
                extra: HashMap::new(),
            },
        );

        FederationRegistry {
            version: "1.0".to_string(),
            last_updated: "2024-01-01T00:00:00Z".to_string(),
            issuers,
            user_account_providers: HashMap::new(),
        }
    }

    #[tokio::test]
    async fn test_with_registry() {
        let resolver = FederationRegistryResolver::with_registry(sample_registry());
        let reg = resolver.get_registry().await.unwrap();
        assert_eq!(reg.version, "1.0");
    }

    #[tokio::test]
    async fn test_find_issuer_by_did() {
        let resolver = FederationRegistryResolver::with_registry(sample_registry());
        let result = resolver
            .find_issuer_by_did("did:web:epc.moverly.com")
            .await
            .unwrap();
        assert!(result.is_some());
        let (slug, _) = result.unwrap();
        assert_eq!(slug, "moverly-epc");
    }

    #[tokio::test]
    async fn test_find_issuer_not_found() {
        let resolver = FederationRegistryResolver::with_registry(sample_registry());
        let result = resolver
            .find_issuer_by_did("did:web:unknown.com")
            .await
            .unwrap();
        assert!(result.is_none());
    }

    #[tokio::test]
    async fn test_no_registry_loaded() {
        let resolver = FederationRegistryResolver::new();
        assert!(resolver.get_registry().await.is_err());
    }

    #[test]
    fn test_load_from_json() {
        let json = serde_json::to_string(&sample_registry()).unwrap();
        let resolver = FederationRegistryResolver::new();
        let reg = resolver.load_from_json(&json).unwrap();
        assert_eq!(reg.version, "1.0");
        assert!(resolver.get_cached().is_some());
    }

    #[tokio::test]
    async fn test_resolve_trust_active_issuer() {
        let resolver = FederationRegistryResolver::with_registry(sample_registry());
        let result = resolver
            .resolve_trust("did:web:epc.moverly.com", None)
            .await;
        assert!(result.trusted);
        assert_eq!(result.issuer_slug, Some("moverly-epc".to_string()));
        assert_eq!(result.trust_marks.len(), 1);
        assert_eq!(result.trust_marks[0].trust_level, TrustLevel::TrustedProxy);
    }

    #[tokio::test]
    async fn test_resolve_trust_unknown_issuer() {
        let resolver = FederationRegistryResolver::with_registry(sample_registry());
        let result = resolver.resolve_trust("did:web:unknown.com", None).await;
        assert!(!result.trusted);
        assert!(result.issuer_slug.is_none());
    }
}
