//! DataIntegrityProof creation and verification using eddsa-jcs-2022.
//!
//! Flow (per W3C Data Integrity EdDSA Cryptosuites v1.0):
//! 1. JCS-canonicalize the proof options (without proofValue)
//! 2. SHA-256 hash the canonicalized proof options
//! 3. JCS-canonicalize the document (without proof)
//! 4. SHA-256 hash the canonicalized document
//! 5. Concatenate: hash(proofOptions) + hash(document) → 64 bytes
//! 6. Sign the concatenated hash with Ed25519 (raw bytes, NOT pre-hashed)
//! 7. Encode signature as base58-btc multibase

use crate::error::{PdtfError, Result};
use crate::keys::provider::KeyProvider;
use crate::types::{DataIntegrityProof, VerifiableCredential};
use ed25519_dalek::{Signature, VerifyingKey};
use sha2::{Digest, Sha256};

/// Options for creating a DataIntegrityProof.
pub struct CreateProofOptions<'a> {
    /// The VC to sign (proof field will be ignored).
    pub document: &'a VerifiableCredential,
    /// Key identifier for the signing key.
    pub key_id: &'a str,
    /// The verification method URI (e.g. `did:key:z6Mk...#z6Mk...`).
    pub verification_method: &'a str,
    /// Key provider for signing.
    pub key_provider: &'a dyn KeyProvider,
    /// ISO timestamp for proof creation. Defaults to now if None.
    pub created: Option<&'a str>,
}

/// Create a DataIntegrityProof for a Verifiable Credential.
pub async fn create_proof(options: CreateProofOptions<'_>) -> Result<DataIntegrityProof> {
    let timestamp = options
        .created
        .map(|s| s.to_string())
        .unwrap_or_else(utc_now);

    // Build proof options (everything except proofValue)
    let proof_options = serde_json::json!({
        "type": "DataIntegrityProof",
        "cryptosuite": "eddsa-jcs-2022",
        "verificationMethod": options.verification_method,
        "proofPurpose": "assertionMethod",
        "created": timestamp,
    });

    // Step 1-2: Hash canonicalized proof options
    let proof_options_canonical = json_canon::to_string(&proof_options)
        .map_err(|e| PdtfError::SerialisationError(e.to_string()))?;
    let proof_options_hash = Sha256::digest(proof_options_canonical.as_bytes());

    // Step 3-4: Hash canonicalized document (without proof)
    let doc_without_proof = document_without_proof(options.document)?;
    let doc_canonical = json_canon::to_string(&doc_without_proof)
        .map_err(|e| PdtfError::SerialisationError(e.to_string()))?;
    let document_hash = Sha256::digest(doc_canonical.as_bytes());

    // Step 5: Concatenate hashes
    let mut combined = Vec::with_capacity(64);
    combined.extend_from_slice(&proof_options_hash);
    combined.extend_from_slice(&document_hash);

    // Step 6: Sign with Ed25519
    let signature = options.key_provider.sign(options.key_id, &combined).await?;

    // Step 7: Encode as base58-btc multibase (z prefix)
    let proof_value = format!("z{}", bs58::encode(&signature).into_string());

    Ok(DataIntegrityProof {
        proof_type: "DataIntegrityProof".to_string(),
        cryptosuite: "eddsa-jcs-2022".to_string(),
        verification_method: options.verification_method.to_string(),
        proof_purpose: "assertionMethod".to_string(),
        created: timestamp,
        proof_value,
    })
}

/// Verify a DataIntegrityProof on a Verifiable Credential.
///
/// Returns `true` if the signature is valid, `false` otherwise.
pub fn verify_proof(document: &VerifiableCredential, public_key: &[u8; 32]) -> bool {
    let proof = match &document.proof {
        Some(p) => p,
        None => return false,
    };

    if proof.proof_type != "DataIntegrityProof" || proof.cryptosuite != "eddsa-jcs-2022" {
        return false;
    }

    (|| -> std::result::Result<bool, Box<dyn std::error::Error>> {
        // Reconstruct proof options (without proofValue)
        let proof_options = serde_json::json!({
            "type": proof.proof_type,
            "cryptosuite": proof.cryptosuite,
            "verificationMethod": proof.verification_method,
            "proofPurpose": proof.proof_purpose,
            "created": proof.created,
        });

        // Hash proof options
        let proof_options_canonical = json_canon::to_string(&proof_options)?;
        let proof_options_hash = Sha256::digest(proof_options_canonical.as_bytes());

        // Hash document without proof
        let doc_without_proof = document_without_proof(document)?;
        let doc_canonical = json_canon::to_string(&doc_without_proof)?;
        let document_hash = Sha256::digest(doc_canonical.as_bytes());

        // Concatenate
        let mut combined = Vec::with_capacity(64);
        combined.extend_from_slice(&proof_options_hash);
        combined.extend_from_slice(&document_hash);

        // Decode signature (strip 'z' multibase prefix)
        let proof_value = &proof.proof_value;
        if !proof_value.starts_with('z') {
            return Ok(false);
        }
        let sig_bytes = bs58::decode(&proof_value[1..]).into_vec()?;
        if sig_bytes.len() != 64 {
            return Ok(false);
        }

        let signature = Signature::from_bytes(sig_bytes.as_slice().try_into()?);
        let verifying_key = VerifyingKey::from_bytes(public_key)?;

        Ok(verifying_key.verify_strict(&combined, &signature).is_ok())
    })()
    .unwrap_or(false)
}

/// Generate a current UTC ISO 8601 timestamp.
fn utc_now() -> String {
    use std::time::{SystemTime, UNIX_EPOCH};
    let secs = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    format_epoch_timestamp(secs)
}

/// Format epoch seconds as ISO 8601 UTC timestamp.
pub fn format_epoch_timestamp(epoch_secs: u64) -> String {
    let days = epoch_secs / 86400;
    let time_secs = epoch_secs % 86400;
    let hours = time_secs / 3600;
    let minutes = (time_secs % 3600) / 60;
    let seconds = time_secs % 60;

    let (year, month, day) = days_to_ymd(days);
    format!(
        "{:04}-{:02}-{:02}T{:02}:{:02}:{:02}Z",
        year, month, day, hours, minutes, seconds
    )
}

fn days_to_ymd(mut days: u64) -> (u64, u64, u64) {
    let mut year = 1970u64;
    loop {
        let days_in_year = if is_leap(year) { 366 } else { 365 };
        if days < days_in_year {
            break;
        }
        days -= days_in_year;
        year += 1;
    }
    let days_in_months: Vec<u64> = if is_leap(year) {
        vec![31, 29, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31]
    } else {
        vec![31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31]
    };
    let mut month = 1u64;
    for dim in days_in_months {
        if days < dim {
            break;
        }
        days -= dim;
        month += 1;
    }
    (year, month, days + 1)
}

fn is_leap(y: u64) -> bool {
    (y.is_multiple_of(4) && !y.is_multiple_of(100)) || y.is_multiple_of(400)
}

/// Serialize a VC without the proof field.
fn document_without_proof(vc: &VerifiableCredential) -> Result<serde_json::Value> {
    let mut value = serde_json::to_value(vc)?;
    if let Some(obj) = value.as_object_mut() {
        obj.remove("proof");
    }
    Ok(value)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::keys::provider::memory::MemoryKeyProvider;
    use crate::types::*;
    use std::collections::HashMap;

    fn make_test_vc(issuer_did: &str) -> VerifiableCredential {
        VerifiableCredential {
            context: vec![
                "https://www.w3.org/ns/credentials/v2".to_string(),
                "https://propdata.org.uk/credentials/v2".to_string(),
            ],
            vc_type: vec![
                "VerifiableCredential".to_string(),
                "PropertyDataCredential".to_string(),
            ],
            id: Some("urn:uuid:test-123".to_string()),
            issuer: Issuer::Did(issuer_did.to_string()),
            valid_from: "2024-01-01T00:00:00Z".to_string(),
            valid_until: None,
            credential_subject: CredentialSubject {
                id: "urn:pdtf:uprn:123456789".to_string(),
                claims: HashMap::new(),
            },
            credential_status: None,
            proof: None,
            evidence: None,
            terms_of_use: None,
        }
    }

    #[tokio::test]
    async fn test_create_and_verify_proof() {
        let provider = MemoryKeyProvider::new();
        let record = provider
            .generate_key("test-signer", crate::types::KeyCategory::Adapter)
            .await
            .unwrap();

        let verification_method = format!("{}#{}", record.did, &record.did["did:key:".len()..]);
        let vc = make_test_vc(&record.did);

        let proof = create_proof(CreateProofOptions {
            document: &vc,
            key_id: "test-signer",
            verification_method: &verification_method,
            key_provider: &provider,
            created: Some("2024-01-01T00:00:00Z"),
        })
        .await
        .unwrap();

        assert_eq!(proof.proof_type, "DataIntegrityProof");
        assert_eq!(proof.cryptosuite, "eddsa-jcs-2022");
        assert!(proof.proof_value.starts_with('z'));

        // Verify
        let mut signed_vc = vc;
        signed_vc.proof = Some(proof);

        let pk: [u8; 32] = record.public_key.try_into().unwrap();
        assert!(verify_proof(&signed_vc, &pk));
    }

    #[tokio::test]
    async fn test_verify_fails_with_wrong_key() {
        let provider = MemoryKeyProvider::new();
        let record = provider
            .generate_key("key-a", crate::types::KeyCategory::Adapter)
            .await
            .unwrap();

        let other = provider
            .generate_key("key-b", crate::types::KeyCategory::Adapter)
            .await
            .unwrap();

        let verification_method = format!("{}#{}", record.did, &record.did["did:key:".len()..]);
        let vc = make_test_vc(&record.did);

        let proof = create_proof(CreateProofOptions {
            document: &vc,
            key_id: "key-a",
            verification_method: &verification_method,
            key_provider: &provider,
            created: Some("2024-01-01T00:00:00Z"),
        })
        .await
        .unwrap();

        let mut signed_vc = vc;
        signed_vc.proof = Some(proof);

        // Verify with wrong key should fail
        let wrong_pk: [u8; 32] = other.public_key.try_into().unwrap();
        assert!(!verify_proof(&signed_vc, &wrong_pk));
    }

    #[test]
    fn test_verify_no_proof() {
        let vc = make_test_vc("did:key:z6MkTest");
        assert!(!verify_proof(&vc, &[0u8; 32]));
    }
}
