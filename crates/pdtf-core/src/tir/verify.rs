//! TIR verification — check issuer authorisation against the registry.

use crate::tir::path_match::any_path_matches;
use crate::types::{IssuerStatus, TirRegistry, TirVerificationResult};

/// Verify that an issuer DID is authorised for a set of claimed paths.
///
/// Looks up the issuer in the registry by DID, checks status is active,
/// and verifies all claimed paths are covered by authorised path patterns.
pub fn verify_tir(
    registry: &TirRegistry,
    issuer_did: &str,
    claimed_paths: &[String],
) -> TirVerificationResult {
    // Find issuer by DID
    let issuer = registry
        .issuers
        .values()
        .find(|entry| entry.did == issuer_did);

    let issuer = match issuer {
        Some(i) => i,
        None => {
            return TirVerificationResult {
                trusted: false,
                issuer_slug: None,
                trust_level: None,
                status: None,
                paths_covered: vec![],
                uncovered_paths: claimed_paths.to_vec(),
                warnings: vec![format!("Issuer not found in TIR: {issuer_did}")],
            };
        }
    };

    let mut warnings = Vec::new();

    // Check status
    if issuer.status != IssuerStatus::Active {
        warnings.push(format!(
            "Issuer '{}' status is {:?}, not active",
            issuer.slug, issuer.status
        ));
    }

    // Check path coverage
    let mut paths_covered = Vec::new();
    let mut uncovered_paths = Vec::new();

    for path in claimed_paths {
        if any_path_matches(&issuer.authorised_paths, path) {
            paths_covered.push(path.clone());
        } else {
            uncovered_paths.push(path.clone());
        }
    }

    let trusted = issuer.status == IssuerStatus::Active
        && uncovered_paths.is_empty()
        && !claimed_paths.is_empty();

    TirVerificationResult {
        trusted,
        issuer_slug: Some(issuer.slug.clone()),
        trust_level: Some(issuer.trust_level.clone()),
        status: Some(issuer.status.clone()),
        paths_covered,
        uncovered_paths,
        warnings,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::*;
    use std::collections::HashMap;

    fn make_registry() -> TirRegistry {
        let mut issuers = HashMap::new();
        issuers.insert(
            "moverly".to_string(),
            TirIssuerEntry {
                slug: "moverly".to_string(),
                did: "did:web:propdata.org.uk:issuers:moverly".to_string(),
                name: "Moverly".to_string(),
                trust_level: TrustLevel::TrustedProxy,
                status: IssuerStatus::Active,
                authorised_paths: vec!["Property:*".to_string(), "Title:*".to_string()],
                proxy_for: None,
                valid_from: None,
                valid_until: None,
                regulatory_registration: None,
                extra: HashMap::new(),
            },
        );
        issuers.insert(
            "epc-provider".to_string(),
            TirIssuerEntry {
                slug: "epc-provider".to_string(),
                did: "did:web:epc.example.com".to_string(),
                name: "EPC Provider".to_string(),
                trust_level: TrustLevel::RootIssuer,
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
            version: "1.0.0".to_string(),
            last_updated: "2024-01-01T00:00:00Z".to_string(),
            issuers,
            user_account_providers: HashMap::new(),
        }
    }

    #[test]
    fn test_trusted_issuer() {
        let registry = make_registry();
        let result = verify_tir(
            &registry,
            "did:web:propdata.org.uk:issuers:moverly",
            &["Property:/tenure".to_string(), "Title:/number".to_string()],
        );
        assert!(result.trusted);
        assert_eq!(result.paths_covered.len(), 2);
        assert!(result.uncovered_paths.is_empty());
    }

    #[test]
    fn test_partial_coverage() {
        let registry = make_registry();
        let result = verify_tir(
            &registry,
            "did:web:epc.example.com",
            &[
                "Property:/energyEfficiency/rating".to_string(),
                "Property:/tenure".to_string(),
            ],
        );
        assert!(!result.trusted);
        assert_eq!(result.paths_covered.len(), 1);
        assert_eq!(result.uncovered_paths, vec!["Property:/tenure"]);
    }

    #[test]
    fn test_unknown_issuer() {
        let registry = make_registry();
        let result = verify_tir(
            &registry,
            "did:web:unknown.com",
            &["Property:/tenure".to_string()],
        );
        assert!(!result.trusted);
        assert!(result.issuer_slug.is_none());
    }

    #[test]
    fn test_empty_paths() {
        let registry = make_registry();
        let result = verify_tir(
            &registry,
            "did:web:propdata.org.uk:issuers:moverly",
            &[],
        );
        assert!(!result.trusted);
    }
}
