//! Federation verification — check issuer authorisation against a TrustResolutionResult.

use crate::federation::path_match::any_path_matches;
use crate::types::{TrustResolutionResult, TrustVerificationResult};

/// Check whether a resolved trust result covers the claimed entity:paths.
///
/// This is the verification entry point that works with `TrustResolutionResult`
/// from any `TrustResolver` implementation.
pub fn verify_trust_coverage(
    resolution: &TrustResolutionResult,
    claimed_paths: &[String],
) -> TrustVerificationResult {
    if !resolution.trusted {
        return TrustVerificationResult {
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
    let all_authorised: Vec<String> = resolution
        .trust_marks
        .iter()
        .flat_map(|tm| tm.authorised_paths.clone())
        .collect();

    let mut paths_covered = Vec::new();
    let mut uncovered_paths = Vec::new();

    for path in claimed_paths {
        if any_path_matches(&all_authorised, path) {
            paths_covered.push(path.clone());
        } else {
            uncovered_paths.push(path.clone());
        }
    }

    let trusted = uncovered_paths.is_empty() && !claimed_paths.is_empty();

    TrustVerificationResult {
        trusted,
        issuer_slug: resolution.issuer_slug.clone(),
        trust_level: resolution.trust_marks.first().map(|tm| tm.trust_level.clone()),
        status: None,
        paths_covered,
        uncovered_paths,
        warnings: resolution.warnings.clone(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::*;

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
