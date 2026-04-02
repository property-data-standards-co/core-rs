//! did:web DID document resolution.
//!
//! Resolution rules (W3C did:web Method Specification):
//! - `did:web:example.com` → `https://example.com/.well-known/did.json`
//! - `did:web:example.com:path:to` → `https://example.com/path/to/did.json`
//!
//! HTTPS only.

use crate::error::{PdtfError, Result};
use crate::types::DidDocument;

/// Convert a did:web identifier to its HTTPS resolution URL.
pub fn did_web_to_url(did: &str) -> Result<String> {
    if !did.starts_with("did:web:") {
        return Err(PdtfError::DidError(format!(
            "Not a did:web identifier: {did}"
        )));
    }

    let rest = &did["did:web:".len()..];
    let parts: Vec<&str> = rest.split(':').collect();

    let domain = urlencoding::decode(parts[0])
        .map_err(|e| PdtfError::DidError(format!("Invalid domain encoding: {e}")))?;

    if parts.len() == 1 {
        Ok(format!("https://{domain}/.well-known/did.json"))
    } else {
        let path: Vec<String> = parts[1..]
            .iter()
            .map(|p| {
                urlencoding::decode(p)
                    .map(|s| s.into_owned())
                    .unwrap_or_else(|_| p.to_string())
            })
            .collect();
        Ok(format!("https://{domain}/{}/did.json", path.join("/")))
    }
}

/// Resolve a did:web identifier to its DID document.
#[cfg(feature = "network")]
pub async fn resolve_did_web(did: &str) -> Result<DidDocument> {
    let url = did_web_to_url(did)?;

    let client = reqwest::Client::new();
    let response = client
        .get(&url)
        .header("Accept", "application/did+json, application/json")
        .timeout(std::time::Duration::from_secs(10))
        .send()
        .await
        .map_err(|e| PdtfError::DidResolutionFailed(format!("HTTP request failed: {e}")))?;

    if !response.status().is_success() {
        return Err(PdtfError::DidResolutionFailed(format!(
            "Failed to resolve {did}: HTTP {}",
            response.status()
        )));
    }

    let doc: DidDocument = response
        .json()
        .await
        .map_err(|e| PdtfError::DidResolutionFailed(format!("Invalid DID document: {e}")))?;

    if doc.id != did {
        return Err(PdtfError::DidResolutionFailed(format!(
            "DID document id mismatch: expected {did}, got {}",
            doc.id
        )));
    }

    Ok(doc)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_did_web_to_url_root() {
        let url = did_web_to_url("did:web:example.com").unwrap();
        assert_eq!(url, "https://example.com/.well-known/did.json");
    }

    #[test]
    fn test_did_web_to_url_with_path() {
        let url = did_web_to_url("did:web:example.com:path:to").unwrap();
        assert_eq!(url, "https://example.com/path/to/did.json");
    }

    #[test]
    fn test_did_web_to_url_encoded_domain() {
        let url = did_web_to_url("did:web:example.com%3A8080").unwrap();
        assert_eq!(url, "https://example.com:8080/.well-known/did.json");
    }

    #[test]
    fn test_did_web_to_url_invalid() {
        assert!(did_web_to_url("did:key:z6Mk...").is_err());
    }
}
