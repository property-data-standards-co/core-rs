//! Federation — trust resolution, path matching, and verification.
//!
//! Provides a trait-based trust resolution model supporting both bootstrap
//! (JSON registry) and OpenID Federation resolution strategies.

pub mod client;
pub mod openid;
pub mod path_match;
pub mod verify;

// Re-export the trait and implementations for convenience
pub use client::FederationRegistryResolver;
pub use openid::OpenIdFederationResolver;

use async_trait::async_trait;

/// Trait for resolving trust in an issuer.
///
/// Implementations may use a static JSON registry (bootstrap), OpenID Federation
/// entity statements and trust marks, or any other trust resolution mechanism.
#[async_trait]
pub trait TrustResolver: Send + Sync {
    /// Resolve trust for the given issuer DID.
    ///
    /// - `issuer_did`: The DID of the credential issuer to evaluate.
    /// - `trust_anchor_did`: Optional trust anchor DID to scope resolution.
    ///   For bootstrap resolution this is ignored; for OpenID Federation it
    ///   identifies the trust anchor whose entity statement chain to walk.
    async fn resolve_trust(
        &self,
        issuer_did: &str,
        trust_anchor_did: Option<&str>,
    ) -> crate::types::TrustResolutionResult;
}
