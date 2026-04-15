//! Federation verification — check issuer authorisation against a TrustResolutionResult.
//!
//! Also provides the legacy `verify_tir()` function for backward compatibility
//! with code that still works with `TirRegistry` directly.

use crate::federation::path_match::any_path_matches;
use crate::types::{IssuerStatus, TirRegistry, TirVerificationResult, TrustResolutionResult};
use chrono::{DateTime, Utc};

/// Check whether a resolved trust result covers the claimed entity:paths.
///
/// This is the new verification entry point that works with `TrustResolutionResult`
/// from any `TrustResolver` implementation.
pub fn verify_trust_coverage(
    resolution: &TrustResolutionResult,
    claimed_paths: &[String],
) -> TirVerificationResult {
    if !resolution.trusted {
        return TirVerificationResult {
            trusted: false,
            issuer_slug: resolution.issuer_slug.clone(),
            trust_level: resolution.trust_marks.first().map(|tm| tm.trust_level.clone()),
            status: None,
            paths_covered: vec![],
            uncovered_paths: claimed_paths.to_vec(),
            warnings: resolution.warnings.clone(),
        };
    }

    // Collect all authorised paths from all trust marks
    let all_authorised: Vec<&String> = resolution
        .trust_marks
        .iter()
        .flat_map(|tm| &tm.authorised_paths)
        .collect();

    let all_authorised_owned: Vec<String> = all_authorised.iter().map(|s| s.to_string()).collect();

    let mut paths_covered = Vec::new();
    let mut uncovered_paths = Vec::new();

    for path in claimed_paths {
        if any_path_matches(&all_authorised_owned, path) {
            paths_covered.push(path.clone());
        } else {
            uncovered_paths.push(path.clone());
        }
    }

    let trusted = uncovered_paths.is_empty() && !claimed_paths.is_empty();

    TirVerificationResult {
        trusted,
        issuer_slug: resolution.issuer_slug.clone(),
        trust_level: resolution.trust_marks.first().map(|tm| tm.trust_level.clone()),
        status: None,
        paths_covered,
        uncovered_paths,
        warnings: resolution.warnings.clone(),
    }
}

/// Legacy: Verify that an issuer DID is authorised for a set of claimed paths
/// using a static TIR registry directly.
///
/// This function is preserved for backward compatibility with bindings and
/// code that passes a `TirRegistry` directly rather than going through a
/// `TrustResolver`.
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
    let mut hard_fail = false;

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
            hard_fail = true;
        }
        IssuerStatus::Revoked => {
            warnings.push(format!("Issuer '{}' has been revoked", issuer.slug));
            hard_fail = true;
        }
    }

    // Check validity window
    let now = Utc::now();

    if let Some(ref valid_from) = issuer.valid_from {
        match DateTime::parse_from_rfc3339(valid_from) {
            Ok(from_dt) => {
                if from_dt > now {
                    warnings.push(format!(
                        "Issuer '{}' is not yet active (validFrom: {})",
                        issuer.slug, valid_from
                    ));
                    hard_fail = true;
                }
            }
            Err(_) => {
                warnings.push(format!(
                    "Issuer '{}' has unparseable validFrom '{}' — treating as untrusted",
                    issuer.slug, valid_from
                ));
                hard_fail = true;
            }
        }
    }

    if let Some(ref valid_until) = issuer.valid_until {
        match DateTime::parse_from_rfc3339(valid_until) {
            Ok(until_dt) => {
                if until_dt < now {
                    warnings.push(format!(
                        "Issuer '{}' has expired (validUntil: {})",
                        issuer.slug, valid_until
                    ));
                    hard_fail = true;
                }
            }
            Err(_) => {
                warnings.push(format!(
                    "Issuer '{}' has unparseable validUntil '{}' — treating as untrusted",
                    issuer.slug, valid_until
                ));
                hard_fail = true;
            }
        }
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

    let trusted = !hard_fail
        && issuer.status == IssuerStatus::Active
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
        let result = verify_tir(&registry, "did:web:propdata.org.uk:issuers:moverly", &[]);
        assert!(!result.trusted);
    }

    #[test]
    fn test_revoked_issuer() {
        let mut registry = make_registry();
        if let Some(issuer) = registry.issuers.get_mut("moverly") {
            issuer.status = IssuerStatus::Revoked;
        }
        let result = verify_tir(
            &registry,
            "did:web:propdata.org.uk:issuers:moverly",
            &["Property:/tenure".to_string()],
        );
        assert!(!result.trusted, "Revoked issuer should not be trusted");
        assert!(result.warnings.iter().any(|w| w.contains("revoked")));
    }

    #[test]
    fn test_planned_issuer() {
        let mut registry = make_registry();
        if let Some(issuer) = registry.issuers.get_mut("moverly") {
            issuer.status = IssuerStatus::Planned;
        }
        let result = verify_tir(
            &registry,
            "did:web:propdata.org.uk:issuers:moverly",
            &["Property:/tenure".to_string()],
        );
        assert!(!result.trusted, "Planned issuer should not be trusted");
        assert!(result.warnings.iter().any(|w| w.contains("planned")));
    }

    #[test]
    fn test_deprecated_issuer_still_trusted() {
        let mut registry = make_registry();
        if let Some(issuer) = registry.issuers.get_mut("moverly") {
            issuer.status = IssuerStatus::Deprecated;
        }
        let result = verify_tir(
            &registry,
            "did:web:propdata.org.uk:issuers:moverly",
            &["Property:/tenure".to_string()],
        );
        assert!(!result.trusted);
        assert!(result.warnings.iter().any(|w| w.contains("deprecated")));
    }

    #[test]
    fn test_expired_issuer() {
        let mut registry = make_registry();
        if let Some(issuer) = registry.issuers.get_mut("moverly") {
            issuer.valid_until = Some("2020-01-01T00:00:00Z".to_string());
        }
        let result = verify_tir(
            &registry,
            "did:web:propdata.org.uk:issuers:moverly",
            &["Property:/tenure".to_string()],
        );
        assert!(!result.trusted, "Expired issuer should not be trusted");
        assert!(result.warnings.iter().any(|w| w.contains("expired")));
    }

    #[test]
    fn test_not_yet_active_issuer() {
        let mut registry = make_registry();
        if let Some(issuer) = registry.issuers.get_mut("moverly") {
            issuer.valid_from = Some("2099-01-01T00:00:00Z".to_string());
        }
        let result = verify_tir(
            &registry,
            "did:web:propdata.org.uk:issuers:moverly",
            &["Property:/tenure".to_string()],
        );
        assert!(
            !result.trusted,
            "Not-yet-active issuer should not be trusted"
        );
        assert!(result.warnings.iter().any(|w| w.contains("not yet active")));
    }

    #[test]
    fn test_unparseable_valid_from_fails_closed() {
        let mut registry = make_registry();
        if let Some(issuer) = registry.issuers.get_mut("moverly") {
            issuer.valid_from = Some("not-a-date".to_string());
        }
        let result = verify_tir(
            &registry,
            "did:web:propdata.org.uk:issuers:moverly",
            &["Property:/tenure".to_string()],
        );
        assert!(!result.trusted, "Unparseable validFrom must fail closed");
        assert!(result.warnings.iter().any(|w| w.contains("unparseable")));
    }

    #[test]
    fn test_fractional_second_valid_from() {
        let mut registry = make_registry();
        if let Some(issuer) = registry.issuers.get_mut("moverly") {
            issuer.valid_from = Some("2024-01-01T00:00:00.500Z".to_string());
        }
        let result = verify_tir(
            &registry,
            "did:web:propdata.org.uk:issuers:moverly",
            &["Property:/tenure".to_string()],
        );
        assert!(result.trusted, "Fractional-second timestamps should be accepted");
    }

    #[test]
    fn test_offset_valid_from() {
        let mut registry = make_registry();
        if let Some(issuer) = registry.issuers.get_mut("moverly") {
            issuer.valid_from = Some("2024-01-01T00:00:00+00:00".to_string());
        }
        let result = verify_tir(
            &registry,
            "did:web:propdata.org.uk:issuers:moverly",
            &["Property:/tenure".to_string()],
        );
        assert!(result.trusted, "Offset timestamps should be accepted");
    }

    // ── verify_trust_coverage tests ──

    #[test]
    fn test_verify_trust_coverage_trusted() {
        let resolution = TrustResolutionResult {
            trusted: true,
            issuer_slug: Some("moverly".to_string()),
            trust_marks: vec![TrustMark {
                trust_level: TrustLevel::TrustedProxy,
                authorised_paths: vec!["Property:*".to_string()],
            }],
            warnings: vec![],
        };
        let result = verify_trust_coverage(&resolution, &["Property:/tenure".to_string()]);
        assert!(result.trusted);
        assert_eq!(result.paths_covered, vec!["Property:/tenure"]);
    }

    #[test]
    fn test_verify_trust_coverage_untrusted_resolution() {
        let resolution = TrustResolutionResult {
            trusted: false,
            issuer_slug: None,
            trust_marks: vec![],
            warnings: vec!["Not found".to_string()],
        };
        let result = verify_trust_coverage(&resolution, &["Property:/tenure".to_string()]);
        assert!(!result.trusted);
        assert_eq!(result.uncovered_paths, vec!["Property:/tenure"]);
    }

    #[test]
    fn test_verify_trust_coverage_partial() {
        let resolution = TrustResolutionResult {
            trusted: true,
            issuer_slug: Some("epc".to_string()),
            trust_marks: vec![TrustMark {
                trust_level: TrustLevel::RootIssuer,
                authorised_paths: vec!["Property:/energyEfficiency/*".to_string()],
            }],
            warnings: vec![],
        };
        let result = verify_trust_coverage(
            &resolution,
            &[
                "Property:/energyEfficiency/rating".to_string(),
                "Property:/tenure".to_string(),
            ],
        );
        assert!(!result.trusted);
        assert_eq!(result.paths_covered, vec!["Property:/energyEfficiency/rating"]);
        assert_eq!(result.uncovered_paths, vec!["Property:/tenure"]);
    }
}
