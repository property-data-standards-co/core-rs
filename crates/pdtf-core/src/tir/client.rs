//! TIR Client — fetches and caches the Trusted Issuer Registry.
//!
//! The TIR is a static JSON file published as a signed VC.
//! Default source: `tir.moverly.com/v1/registry`.

use crate::error::{PdtfError, Result};
use crate::types::{TirAccountProvider, TirIssuerEntry, TirRegistry};
use std::sync::Mutex;

/// TIR client with in-memory cache.
pub struct TirClient {
    cached: Mutex<Option<TirRegistry>>,
}

impl TirClient {
    /// Create a new empty TIR client.
    pub fn new() -> Self {
        Self {
            cached: Mutex::new(None),
        }
    }

    /// Create a TIR client pre-loaded with a registry (useful for testing).
    pub fn with_registry(registry: TirRegistry) -> Self {
        Self {
            cached: Mutex::new(Some(registry)),
        }
    }

    /// Load a registry from a JSON string.
    pub fn load_from_json(&self, json: &str) -> Result<TirRegistry> {
        let registry: TirRegistry = serde_json::from_str(json)?;
        *self.cached.lock().unwrap() = Some(registry.clone());
        Ok(registry)
    }

    /// Fetch registry from a URL.
    #[cfg(feature = "network")]
    pub async fn fetch(&self, url: &str) -> Result<TirRegistry> {
        let client = reqwest::Client::new();
        let response = client
            .get(url)
            .header("Accept", "application/json")
            .timeout(std::time::Duration::from_secs(10))
            .send()
            .await
            .map_err(|e| PdtfError::TirError(format!("Failed to fetch TIR: {e}")))?;

        if !response.status().is_success() {
            return Err(PdtfError::TirError(format!(
                "TIR fetch failed: HTTP {}",
                response.status()
            )));
        }

        let registry: TirRegistry = response
            .json()
            .await
            .map_err(|e| PdtfError::TirError(format!("Invalid TIR JSON: {e}")))?;

        *self.cached.lock().unwrap() = Some(registry.clone());
        Ok(registry)
    }

    /// Get the current TIR registry.
    pub async fn get_registry(&self) -> Result<TirRegistry> {
        let cached = self.cached.lock().unwrap().clone();
        match cached {
            Some(reg) => Ok(reg),
            None => Err(PdtfError::TirError(
                "No TIR registry loaded. Call load_from_json() or fetch() first.".into(),
            )),
        }
    }

    /// Look up an issuer by DID.
    pub async fn find_issuer_by_did(
        &self,
        did: &str,
    ) -> Result<Option<(String, TirIssuerEntry)>> {
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
    ) -> Result<Option<(String, TirAccountProvider)>> {
        let registry = self.get_registry().await?;
        for (slug, entry) in &registry.user_account_providers {
            if entry.did == did {
                return Ok(Some((slug.clone(), entry.clone())));
            }
        }
        Ok(None)
    }

    /// Get the cached registry, if any.
    pub fn get_cached(&self) -> Option<TirRegistry> {
        self.cached.lock().unwrap().clone()
    }

    /// Clear the cache.
    pub fn clear_cache(&self) {
        *self.cached.lock().unwrap() = None;
    }
}

impl Default for TirClient {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::*;
    use std::collections::HashMap;

    fn sample_registry() -> TirRegistry {
        let mut issuers = HashMap::new();
        issuers.insert(
            "moverly-epc".to_string(),
            TirIssuerEntry {
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

        TirRegistry {
            version: "1.0".to_string(),
            last_updated: "2024-01-01T00:00:00Z".to_string(),
            issuers,
            user_account_providers: HashMap::new(),
        }
    }

    #[tokio::test]
    async fn test_with_registry() {
        let client = TirClient::with_registry(sample_registry());
        let reg = client.get_registry().await.unwrap();
        assert_eq!(reg.version, "1.0");
    }

    #[tokio::test]
    async fn test_find_issuer_by_did() {
        let client = TirClient::with_registry(sample_registry());
        let result = client
            .find_issuer_by_did("did:web:epc.moverly.com")
            .await
            .unwrap();
        assert!(result.is_some());
        let (slug, _) = result.unwrap();
        assert_eq!(slug, "moverly-epc");
    }

    #[tokio::test]
    async fn test_find_issuer_not_found() {
        let client = TirClient::with_registry(sample_registry());
        let result = client
            .find_issuer_by_did("did:web:unknown.com")
            .await
            .unwrap();
        assert!(result.is_none());
    }

    #[tokio::test]
    async fn test_no_registry_loaded() {
        let client = TirClient::new();
        assert!(client.get_registry().await.is_err());
    }

    #[test]
    fn test_load_from_json() {
        let json = serde_json::to_string(&sample_registry()).unwrap();
        let client = TirClient::new();
        let reg = client.load_from_json(&json).unwrap();
        assert_eq!(reg.version, "1.0");
        assert!(client.get_cached().is_some());
    }
}
