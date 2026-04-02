//! Ed25519 key generation and did:key encoding.
//!
//! Encoding: `0xed01` multicodec prefix + 32-byte public key → base58-btc → `z` prefix.
//! All PDTF did:key identifiers start with `did:key:z6Mk`.

use crate::error::{PdtfError, Result};
use ed25519_dalek::{SigningKey, VerifyingKey};
use rand::rngs::OsRng;

/// Multicodec prefix for Ed25519 public key (varint-encoded 0xed).
const ED25519_MULTICODEC: [u8; 2] = [0xed, 0x01];

/// Generated Ed25519 key pair.
#[derive(Debug, Clone)]
pub struct Ed25519KeyPair {
    pub signing_key: SigningKey,
    pub verifying_key: VerifyingKey,
}

/// Generate a new Ed25519 key pair.
pub fn generate_keypair() -> Ed25519KeyPair {
    let signing_key = SigningKey::generate(&mut OsRng);
    let verifying_key = signing_key.verifying_key();
    Ed25519KeyPair {
        signing_key,
        verifying_key,
    }
}

/// Encode a raw Ed25519 public key as a multibase base58-btc string (with `z` prefix).
pub fn public_key_to_multibase(public_key: &[u8]) -> Result<String> {
    if public_key.len() != 32 {
        return Err(PdtfError::InvalidKey(format!(
            "Expected 32-byte Ed25519 public key, got {} bytes",
            public_key.len()
        )));
    }

    let mut prefixed = Vec::with_capacity(2 + 32);
    prefixed.extend_from_slice(&ED25519_MULTICODEC);
    prefixed.extend_from_slice(public_key);

    Ok(format!("z{}", bs58::encode(&prefixed).into_string()))
}

/// Derive a did:key identifier from a raw Ed25519 public key.
///
/// # Example
/// ```
/// use pdtf_core::keys::ed25519::{generate_keypair, derive_did_key};
/// let kp = generate_keypair();
/// let did = derive_did_key(kp.verifying_key.as_bytes()).unwrap();
/// assert!(did.starts_with("did:key:z6Mk"));
/// ```
pub fn derive_did_key(public_key: &[u8]) -> Result<String> {
    let multibase = public_key_to_multibase(public_key)?;
    Ok(format!("did:key:{multibase}"))
}

/// Extract the raw Ed25519 public key from a did:key identifier.
/// Validates the multicodec prefix.
pub fn did_key_to_public_key(did: &str) -> Result<[u8; 32]> {
    if !did.starts_with("did:key:z") {
        return Err(PdtfError::InvalidKey(format!(
            "Invalid did:key format: {did}"
        )));
    }

    let multibase = &did["did:key:".len()..];
    // Strip the 'z' prefix and decode base58
    let decoded = bs58::decode(&multibase[1..])
        .into_vec()
        .map_err(|e| PdtfError::EncodingError(format!("Base58 decode error: {e}")))?;

    if decoded.len() < 2 || decoded[0] != 0xed || decoded[1] != 0x01 {
        return Err(PdtfError::InvalidKey(
            "Not an Ed25519 did:key (unexpected multicodec prefix)".into(),
        ));
    }

    let key_bytes = &decoded[2..];
    if key_bytes.len() != 32 {
        return Err(PdtfError::InvalidKey(format!(
            "Expected 32 key bytes after multicodec prefix, got {}",
            key_bytes.len()
        )));
    }

    let mut arr = [0u8; 32];
    arr.copy_from_slice(key_bytes);
    Ok(arr)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_generate_keypair() {
        let kp = generate_keypair();
        assert_eq!(kp.verifying_key.as_bytes().len(), 32);
    }

    #[test]
    fn test_derive_did_key() {
        let kp = generate_keypair();
        let did = derive_did_key(kp.verifying_key.as_bytes()).unwrap();
        assert!(did.starts_with("did:key:z6Mk"));
    }

    #[test]
    fn test_roundtrip_did_key() {
        let kp = generate_keypair();
        let original = kp.verifying_key.as_bytes().to_vec();
        let did = derive_did_key(&original).unwrap();
        let recovered = did_key_to_public_key(&did).unwrap();
        assert_eq!(original.as_slice(), &recovered);
    }

    #[test]
    fn test_invalid_did_key_format() {
        assert!(did_key_to_public_key("did:web:example.com").is_err());
    }

    #[test]
    fn test_multibase_encoding() {
        let kp = generate_keypair();
        let mb = public_key_to_multibase(kp.verifying_key.as_bytes()).unwrap();
        assert!(mb.starts_with("z"));
    }

    #[test]
    fn test_wrong_key_length() {
        assert!(public_key_to_multibase(&[0u8; 16]).is_err());
    }
}
