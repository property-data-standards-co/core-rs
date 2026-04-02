//! Glob-style path matching for TIR authorised paths.
//!
//! Patterns:
//! - `Property:*` matches `Property:/any/path/here`
//! - `Property:/energyEfficiency/*` matches `Property:/energyEfficiency/rating`
//! - Exact match: `Property:/tenure` matches only `Property:/tenure`

/// Check if a TIR authorised path pattern matches a claimed path.
///
/// # Examples
/// ```
/// use pdtf_core::tir::path_match::path_matches;
///
/// assert!(path_matches("Property:*", "Property:/tenure"));
/// assert!(path_matches("Property:/energyEfficiency/*", "Property:/energyEfficiency/rating"));
/// assert!(path_matches("Property:/tenure", "Property:/tenure"));
/// assert!(!path_matches("Property:/tenure", "Property:/other"));
/// ```
pub fn path_matches(pattern: &str, path: &str) -> bool {
    // Split into entity:path parts
    let (pat_entity, pat_path) = match pattern.split_once(':') {
        Some((e, p)) => (e, p),
        None => return pattern == path,
    };

    let (path_entity, path_path) = match path.split_once(':') {
        Some((e, p)) => (e, p),
        None => return false,
    };

    // Entity must match exactly
    if pat_entity != path_entity {
        return false;
    }

    // Wildcard matching on the path part
    if pat_path == "*" {
        // Entity:* matches everything under that entity
        return true;
    }

    if let Some(prefix) = pat_path.strip_suffix("/*") {
        // Entity:/prefix/* matches only children like Entity:/prefix/anything
        // It does NOT match the parent Entity:/prefix itself
        path_path.starts_with(&format!("{prefix}/"))
    } else {
        // Exact match
        pat_path == path_path
    }
}

/// Check if any pattern in a list matches the given path.
pub fn any_path_matches(patterns: &[String], path: &str) -> bool {
    patterns.iter().any(|p| path_matches(p, path))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_wildcard_all() {
        assert!(path_matches("Property:*", "Property:/tenure"));
        assert!(path_matches(
            "Property:*",
            "Property:/energyEfficiency/rating"
        ));
        assert!(path_matches("Property:*", "Property:/anything/at/all"));
    }

    #[test]
    fn test_wildcard_subtree() {
        assert!(path_matches(
            "Property:/energyEfficiency/*",
            "Property:/energyEfficiency/rating"
        ));
        assert!(path_matches(
            "Property:/energyEfficiency/*",
            "Property:/energyEfficiency/certificate"
        ));
        // Wildcard should NOT match the parent path itself
        assert!(!path_matches(
            "Property:/energyEfficiency/*",
            "Property:/energyEfficiency"
        ));
        assert!(!path_matches(
            "Property:/energyEfficiency/*",
            "Property:/tenure"
        ));
    }

    #[test]
    fn test_exact_match() {
        assert!(path_matches("Property:/tenure", "Property:/tenure"));
        assert!(!path_matches("Property:/tenure", "Property:/other"));
    }

    #[test]
    fn test_entity_mismatch() {
        assert!(!path_matches("Property:*", "Title:/number"));
        assert!(!path_matches("Title:*", "Property:/tenure"));
    }

    #[test]
    fn test_any_path_matches() {
        let patterns = vec![
            "Property:/tenure".to_string(),
            "Property:/energyEfficiency/*".to_string(),
        ];
        assert!(any_path_matches(&patterns, "Property:/tenure"));
        assert!(any_path_matches(
            &patterns,
            "Property:/energyEfficiency/rating"
        ));
        assert!(!any_path_matches(&patterns, "Property:/other"));
    }
}
