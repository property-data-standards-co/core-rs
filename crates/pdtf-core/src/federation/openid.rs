//! OpenID Federation Trust Resolver — stub implementation.
//!
//! This resolver will implement trust resolution via OpenID Federation 1.0:
//! - Entity statement chain walking from leaf to trust anchor
//! - Trust mark verification (signed JWTs from a Trust Mark Issuer)
//! - Metadata policy application along the chain
//!
//! ## Future implementation notes
//!
//! The full implementation will need:
//! - JWT verification (e.g. `jsonwebtoken` crate or similar)
//! - Entity statement fetching from `/.well-known/openid-federation`
//! - Trust mark JWT parsing and signature verification
//! - Metadata policy merge (subset_of, superset_of, one_of, etc.)
//! - Subordinate statement fetching from `federation_fetch_endpoint`
//!
//! For now this is a stub that always returns untrusted with a message
//! indicating that OpenID Federation resolution is not yet implemented.

use async_trait::async_trait;

use crate::federation::TrustResolver;
use crate::types::TrustResolutionResult;

/// OpenID Federation trust resolver (stub).
///
/// When fully implemented, this will:
/// 1. Fetch the leaf entity's entity configuration from `{issuer}/.well-known/openid-federation`
/// 2. Walk the authority_hints chain up to the trust anchor
/// 3. Verify subordinate statements at each hop
/// 4. Check trust marks against the Trust Mark Issuer
/// 5. Return the resolved trust level and authorised paths from metadata
pub struct OpenIdFederationResolver {
    /// The trust anchor entity identifier (typically a DID or URL).
    /// If set, only chains terminating at this anchor are accepted.
    pub trust_anchor: Option<String>,
}

impl OpenIdFederationResolver {
    /// Create a new resolver with no specific trust anchor.
    pub fn new() -> Self {
        Self {
            trust_anchor: None,
        }
    }

    /// Create a new resolver scoped to a specific trust anchor.
    pub fn with_trust_anchor(anchor: String) -> Self {
        Self {
            trust_anchor: Some(anchor),
        }
    }
}

impl Default for OpenIdFederationResolver {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl TrustResolver for OpenIdFederationResolver {
    async fn resolve_trust(
        &self,
        issuer_did: &str,
        trust_anchor_did: Option<&str>,
    ) -> TrustResolutionResult {
        let anchor = trust_anchor_did
            .or(self.trust_anchor.as_deref())
            .unwrap_or("(none)");

        TrustResolutionResult {
            trusted: false,
            issuer_slug: None,
            trust_marks: vec![],
            warnings: vec![format!(
                "OpenID Federation resolution not yet implemented. \
                 Issuer: {issuer_did}, trust anchor: {anchor}"
            )],
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_stub_returns_untrusted() {
        let resolver = OpenIdFederationResolver::new();
        let result = resolver
            .resolve_trust("did:web:example.com", Some("did:web:anchor.example.com"))
            .await;
        assert!(!result.trusted);
        assert!(result.warnings[0].contains("not yet implemented"));
    }

    #[tokio::test]
    async fn test_stub_with_trust_anchor() {
        let resolver =
            OpenIdFederationResolver::with_trust_anchor("did:web:anchor.example.com".to_string());
        let result = resolver.resolve_trust("did:web:leaf.example.com", None).await;
        assert!(!result.trusted);
        assert!(result.warnings[0].contains("anchor.example.com"));
    }
}
