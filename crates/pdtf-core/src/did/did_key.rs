//! did:key DID document resolution.
//!
//! did:key documents are deterministic — derived entirely from the public key.
//! No network request needed.

use crate::error::{PdtfError, Result};
use crate::keys::ed25519::{did_key_to_public_key, public_key_to_multibase};
use crate::types::{DidDocument, VerificationMethod};

/// Resolve a did:key to its implicit DID document.
///
/// The document contains a single Ed25519VerificationKey2020 verification method
/// referenced by authentication and assertionMethod.
pub fn resolve_did_key(did: &str) -> Result<DidDocument> {
    if !did.starts_with("did:key:z6Mk") {
        return Err(PdtfError::DidError(format!(
            "Expected Ed25519 did:key (z6Mk prefix), got: {did}"
        )));
    }

    let public_key = did_key_to_public_key(did)?;
    let multibase = public_key_to_multibase(&public_key)?;
    let key_id = format!("{did}#{multibase}");

    let verification_method = VerificationMethod {
        id: key_id.clone(),
        method_type: "Ed25519VerificationKey2020".to_string(),
        controller: did.to_string(),
        public_key_multibase: Some(multibase),
    };

    Ok(DidDocument {
        context: vec![
            "https://www.w3.org/ns/did/v1".to_string(),
            "https://w3id.org/security/suites/ed25519-2020/v1".to_string(),
        ],
        id: did.to_string(),
        controller: None,
        also_known_as: None,
        verification_method: Some(vec![verification_method]),
        authentication: Some(vec![key_id.clone()]),
        assertion_method: Some(vec![key_id]),
        key_agreement: None,
        service: None,
        deactivated: None,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::keys::ed25519::{derive_did_key, generate_keypair};

    #[test]
    fn test_resolve_did_key() {
        let kp = generate_keypair();
        let did = derive_did_key(kp.verifying_key.as_bytes()).unwrap();

        let doc = resolve_did_key(&did).unwrap();
        assert_eq!(doc.id, did);
        assert!(doc.verification_method.is_some());

        let vms = doc.verification_method.unwrap();
        assert_eq!(vms.len(), 1);
        assert_eq!(vms[0].method_type, "Ed25519VerificationKey2020");
        assert_eq!(vms[0].controller, did);
        assert!(vms[0].id.starts_with(&did));
    }

    #[test]
    fn test_resolve_invalid_did_key() {
        assert!(resolve_did_key("did:web:example.com").is_err());
        assert!(resolve_did_key("did:key:z6LSbysY").is_err());
    }

    #[test]
    fn test_did_key_document_structure() {
        let kp = generate_keypair();
        let did = derive_did_key(kp.verifying_key.as_bytes()).unwrap();
        let doc = resolve_did_key(&did).unwrap();

        assert_eq!(doc.context.len(), 2);
        assert!(doc.authentication.is_some());
        assert!(doc.assertion_method.is_some());
        assert_eq!(doc.authentication.unwrap(), doc.assertion_method.unwrap());
    }
}
