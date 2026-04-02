//! 4-stage Verifiable Credential verification.
//!
//! 1. Structure check — required fields, valid types
//! 2. Signature verification — resolve DID → get public key → verify_proof
//! 3. TIR check — issuer authorised for claimed paths
//! 4. Status check — credential not revoked

use crate::did::resolver::DidResolver;
use crate::error::{PdtfError, Result};
use crate::signer::proof::verify_proof;
use crate::status::bitstring::{decode_status_list, get_bit};
use crate::tir::verify::verify_tir;
use crate::types::*;
use serde::{Deserialize, Serialize};

/// Clock skew tolerance for timestamp checks (5 minutes).
const CLOCK_SKEW_TOLERANCE_SECS: u64 = 300;

/// Result of VC verification.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VcVerificationResult {
    pub valid: bool,
    pub structure_ok: bool,
    pub signature_ok: bool,
    pub tir_result: Option<TirVerificationResult>,
    pub status_ok: Option<bool>,
    pub errors: Vec<String>,
    pub warnings: Vec<String>,
}

/// Options for VC verification.
pub struct VerifyVcOptions<'a> {
    pub vc: &'a VerifiableCredential,
    pub resolver: &'a DidResolver,
    /// TIR registry for authorisation check. If None, TIR check is skipped.
    pub tir_registry: Option<&'a TirRegistry>,
    /// Claimed entity:path list for TIR verification.
    pub claimed_paths: Vec<String>,
    /// Pre-fetched status list encoded bitstring. If None and credential has status, validation fails (fail-closed).
    pub status_list_bitstring: Option<&'a str>,
}

/// Verify a Verifiable Credential through the 4-stage pipeline.
pub async fn verify_vc(options: VerifyVcOptions<'_>) -> VcVerificationResult {
    let mut result = VcVerificationResult {
        valid: false,
        structure_ok: false,
        signature_ok: false,
        tir_result: None,
        status_ok: None,
        errors: vec![],
        warnings: vec![],
    };

    // Stage 1: Structure check
    if let Err(e) = check_structure(options.vc) {
        result.errors.push(format!("Structure: {e}"));
        return result;
    }
    result.structure_ok = true;

    // Stage 2: Signature verification
    match verify_signature(options.vc, options.resolver).await {
        Ok(true) => result.signature_ok = true,
        Ok(false) => {
            result.errors.push("Signature verification failed".into());
            return result;
        }
        Err(e) => {
            result.errors.push(format!("Signature: {e}"));
            return result;
        }
    }

    // Stage 3: TIR check (fail-closed: untrusted issuer fails validation)
    if let Some(registry) = options.tir_registry {
        let tir_result = verify_tir(registry, options.vc.issuer.id(), &options.claimed_paths);
        if !tir_result.trusted {
            result.errors.push(format!(
                "TIR: issuer not authorised. Uncovered: {:?}",
                tir_result.uncovered_paths
            ));
        }
        result.tir_result = Some(tir_result);
    }

    // Stage 4: Status check (fail-closed: missing bitstring fails validation)
    if let Some(status) = &options.vc.credential_status {
        if let Some(bitstring_b64) = options.status_list_bitstring {
            match check_credential_status(status, bitstring_b64) {
                Ok(revoked) => {
                    if revoked {
                        result.errors.push("Credential has been revoked".into());
                        result.status_ok = Some(false);
                    } else {
                        result.status_ok = Some(true);
                    }
                }
                Err(e) => {
                    result.errors.push(format!("Status check error: {e}"));
                    result.status_ok = Some(false);
                }
            }
        } else {
            // Fail-closed: credential has status but no bitstring supplied
            result.errors.push(
                "Credential has credentialStatus but no status list provided — cannot verify revocation status".into(),
            );
            result.status_ok = Some(false);
        }
    }

    result.valid = result.structure_ok && result.signature_ok && result.errors.is_empty();
    result
}

/// Stage 1: Check VC structure.
fn check_structure(vc: &VerifiableCredential) -> Result<()> {
    // Must have W3C VC v2 context
    if vc.context.is_empty() {
        return Err(PdtfError::VerificationError("Missing @context".into()));
    }

    let has_vc_context = vc.context.iter().any(|c| c.contains("credentials"));
    if !has_vc_context {
        return Err(PdtfError::VerificationError(
            "Missing W3C Verifiable Credentials context".into(),
        ));
    }

    // Must include VerifiableCredential type
    if !vc.vc_type.contains(&"VerifiableCredential".to_string()) {
        return Err(PdtfError::VerificationError(
            "Missing 'VerifiableCredential' type".into(),
        ));
    }

    // Must have issuer
    if vc.issuer.id().is_empty() {
        return Err(PdtfError::VerificationError("Missing issuer".into()));
    }

    // Must have validFrom
    if vc.valid_from.is_empty() {
        return Err(PdtfError::VerificationError("Missing validFrom".into()));
    }

    // Must have proof for verification
    if vc.proof.is_none() {
        return Err(PdtfError::VerificationError("Missing proof".into()));
    }

    // credentialSubject.id must not be empty
    if vc.credential_subject.id.is_empty() {
        return Err(PdtfError::VerificationError(
            "credentialSubject.id must not be empty".into(),
        ));
    }

    // Check validFrom is not in the future (with clock skew tolerance)
    if let Ok(now) = current_epoch_secs() {
        if let Some(valid_from_epoch) = parse_iso_epoch(&vc.valid_from) {
            if valid_from_epoch > now + CLOCK_SKEW_TOLERANCE_SECS {
                return Err(PdtfError::VerificationError(format!(
                    "validFrom '{}' is in the future",
                    vc.valid_from
                )));
            }
        }

        // Check validUntil is not in the past (credential expired)
        if let Some(ref valid_until) = vc.valid_until {
            if let Some(valid_until_epoch) = parse_iso_epoch(valid_until) {
                if valid_until_epoch + CLOCK_SKEW_TOLERANCE_SECS < now {
                    return Err(PdtfError::VerificationError(format!(
                        "Credential expired: validUntil '{}'",
                        valid_until
                    )));
                }
            }
        }
    }

    Ok(())
}

/// Stage 2: Verify the signature by resolving the issuer DID.
async fn verify_signature(vc: &VerifiableCredential, resolver: &DidResolver) -> Result<bool> {
    let proof = vc
        .proof
        .as_ref()
        .ok_or_else(|| PdtfError::VerificationError("No proof to verify".into()))?;

    // Extract DID from verification method
    let did = proof
        .verification_method
        .split('#')
        .next()
        .unwrap_or(&proof.verification_method);

    // Resolve DID document
    let doc = resolver.resolve(did).await?;

    // Find verification method and extract public key — exact match required (no fallback)
    let vms = doc.verification_method.ok_or_else(|| {
        PdtfError::VerificationError("DID document has no verification methods".into())
    })?;

    let vm = vms
        .iter()
        .find(|v| v.id == proof.verification_method)
        .ok_or_else(|| {
            PdtfError::VerificationError(format!(
                "Verification method '{}' not found in DID document",
                proof.verification_method
            ))
        })?;

    let multibase = vm.public_key_multibase.as_ref().ok_or_else(|| {
        PdtfError::VerificationError("Verification method missing publicKeyMultibase".into())
    })?;

    // Decode multibase public key
    let public_key = decode_multibase_public_key(multibase)?;

    Ok(verify_proof(vc, &public_key))
}

/// Decode a multibase-encoded Ed25519 public key.
fn decode_multibase_public_key(multibase: &str) -> Result<[u8; 32]> {
    if !multibase.starts_with('z') {
        return Err(PdtfError::EncodingError(
            "Expected base58-btc multibase (z prefix)".into(),
        ));
    }

    let decoded = bs58::decode(&multibase[1..])
        .into_vec()
        .map_err(|e| PdtfError::EncodingError(format!("Base58 decode error: {e}")))?;

    // Check for Ed25519 multicodec prefix (0xed 0x01)
    if decoded.len() >= 34 && decoded[0] == 0xed && decoded[1] == 0x01 {
        let mut arr = [0u8; 32];
        arr.copy_from_slice(&decoded[2..34]);
        return Ok(arr);
    }

    // Raw 32-byte key
    if decoded.len() == 32 {
        let mut arr = [0u8; 32];
        arr.copy_from_slice(&decoded);
        return Ok(arr);
    }

    Err(PdtfError::EncodingError(format!(
        "Unexpected multibase key length: {}",
        decoded.len()
    )))
}

/// Stage 4: Check credential status against a pre-fetched bitstring.
fn check_credential_status(status: &CredentialStatus, bitstring_b64: &str) -> Result<bool> {
    let index: usize = status
        .status_list_index
        .parse()
        .map_err(|e| PdtfError::StatusListError(format!("Invalid status list index: {e}")))?;

    let bitstring = decode_status_list(bitstring_b64)?;
    get_bit(&bitstring, index)
}

/// Get current epoch seconds.
fn current_epoch_secs() -> std::result::Result<u64, ()> {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .map_err(|_| ())
}

/// Parse a simple ISO 8601 timestamp to epoch seconds.
/// Supports format: YYYY-MM-DDTHH:MM:SSZ
fn parse_iso_epoch(ts: &str) -> Option<u64> {
    let ts = ts.trim_end_matches('Z');
    let (date, time) = ts.split_once('T')?;
    let parts: Vec<&str> = date.split('-').collect();
    if parts.len() != 3 {
        return None;
    }
    let year: u64 = parts[0].parse().ok()?;
    let month: u64 = parts[1].parse().ok()?;
    let day: u64 = parts[2].parse().ok()?;

    let time_parts: Vec<&str> = time.split(':').collect();
    if time_parts.len() != 3 {
        return None;
    }
    let hours: u64 = time_parts[0].parse().ok()?;
    let minutes: u64 = time_parts[1].parse().ok()?;
    let seconds: u64 = time_parts[2].parse().ok()?;

    // Approximate days from epoch
    let mut days: u64 = 0;
    for y in 1970..year {
        days += if is_leap(y) { 366 } else { 365 };
    }
    let days_in_months: Vec<u64> = if is_leap(year) {
        vec![31, 29, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31]
    } else {
        vec![31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31]
    };
    for m in 0..(month.saturating_sub(1) as usize) {
        if m < days_in_months.len() {
            days += days_in_months[m];
        }
    }
    days += day.saturating_sub(1);

    Some(days * 86400 + hours * 3600 + minutes * 60 + seconds)
}

fn is_leap(y: u64) -> bool {
    (y.is_multiple_of(4) && !y.is_multiple_of(100)) || y.is_multiple_of(400)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::keys::provider::memory::MemoryKeyProvider;
    use crate::keys::provider::KeyProvider;
    use crate::signer::{BuildVcOptions, VcSigner};
    use crate::status::bitstring::{
        create_status_list, encode_status_list, set_bit, MIN_BITSTRING_SIZE,
    };
    use std::collections::HashMap;

    async fn make_signed_vc() -> (VerifiableCredential, MemoryKeyProvider) {
        let provider = MemoryKeyProvider::new();
        provider
            .generate_key("test-key", KeyCategory::Adapter)
            .await
            .unwrap();

        let signer = VcSigner::from_key_id(&provider, "test-key").await.unwrap();

        let vc = signer
            .sign(BuildVcOptions {
                vc_type: vec!["PropertyDataCredential".to_string()],
                credential_subject: CredentialSubject {
                    id: "urn:pdtf:uprn:123456789".to_string(),
                    claims: HashMap::new(),
                },
                id: Some("urn:uuid:test-vc".to_string()),
                valid_from: Some("2024-06-01T12:00:00Z".to_string()),
                valid_until: None,
                credential_status: None,
                evidence: None,
                terms_of_use: None,
            })
            .await
            .unwrap();

        (vc, provider)
    }

    #[tokio::test]
    async fn test_verify_valid_vc() {
        let (vc, _provider) = make_signed_vc().await;
        let resolver = DidResolver::default();

        let result = verify_vc(VerifyVcOptions {
            vc: &vc,
            resolver: &resolver,
            tir_registry: None,
            claimed_paths: vec![],
            status_list_bitstring: None,
        })
        .await;

        assert!(result.valid);
        assert!(result.structure_ok);
        assert!(result.signature_ok);
    }

    #[tokio::test]
    async fn test_verify_no_proof() {
        let (mut vc, _provider) = make_signed_vc().await;
        vc.proof = None;
        let resolver = DidResolver::default();

        let result = verify_vc(VerifyVcOptions {
            vc: &vc,
            resolver: &resolver,
            tir_registry: None,
            claimed_paths: vec![],
            status_list_bitstring: None,
        })
        .await;

        assert!(!result.valid);
        assert!(!result.structure_ok);
    }

    #[tokio::test]
    async fn test_verify_with_tir() {
        let (vc, _provider) = make_signed_vc().await;
        let resolver = DidResolver::default();

        let mut issuers = HashMap::new();
        issuers.insert(
            "test".to_string(),
            TirIssuerEntry {
                slug: "test".to_string(),
                did: vc.issuer.id().to_string(),
                name: "Test".to_string(),
                trust_level: TrustLevel::TrustedProxy,
                status: IssuerStatus::Active,
                authorised_paths: vec!["Property:*".to_string()],
                proxy_for: None,
                valid_from: None,
                valid_until: None,
                regulatory_registration: None,
                extra: HashMap::new(),
            },
        );

        let registry = TirRegistry {
            version: "1.0.0".to_string(),
            last_updated: "2024-01-01T00:00:00Z".to_string(),
            issuers,
            user_account_providers: HashMap::new(),
        };

        let result = verify_vc(VerifyVcOptions {
            vc: &vc,
            resolver: &resolver,
            tir_registry: Some(&registry),
            claimed_paths: vec!["Property:/tenure".to_string()],
            status_list_bitstring: None,
        })
        .await;

        assert!(result.valid);
        assert!(result.tir_result.as_ref().unwrap().trusted);
    }

    #[tokio::test]
    async fn test_verify_tir_failure_fails_validation() {
        let (vc, _provider) = make_signed_vc().await;
        let resolver = DidResolver::default();

        // Registry with a different issuer — vc's issuer won't be found
        let registry = TirRegistry {
            version: "1.0.0".to_string(),
            last_updated: "2024-01-01T00:00:00Z".to_string(),
            issuers: HashMap::new(),
            user_account_providers: HashMap::new(),
        };

        let result = verify_vc(VerifyVcOptions {
            vc: &vc,
            resolver: &resolver,
            tir_registry: Some(&registry),
            claimed_paths: vec!["Property:/tenure".to_string()],
            status_list_bitstring: None,
        })
        .await;

        assert!(!result.valid, "TIR failure should fail overall validation");
        assert!(result.errors.iter().any(|e| e.contains("TIR")));
    }

    #[tokio::test]
    async fn test_verify_missing_status_list_fails() {
        let provider = MemoryKeyProvider::new();
        provider
            .generate_key("status-key", KeyCategory::Adapter)
            .await
            .unwrap();

        let signer = VcSigner::from_key_id(&provider, "status-key")
            .await
            .unwrap();

        let vc = signer
            .sign(BuildVcOptions {
                vc_type: vec!["PropertyDataCredential".to_string()],
                credential_subject: CredentialSubject {
                    id: "urn:pdtf:uprn:999999999".to_string(),
                    claims: HashMap::new(),
                },
                id: Some("urn:uuid:status-vc".to_string()),
                valid_from: Some("2024-06-01T12:00:00Z".to_string()),
                valid_until: None,
                credential_status: Some(CredentialStatus {
                    id: "https://example.com/status/1#42".to_string(),
                    status_type: "BitstringStatusListEntry".to_string(),
                    status_purpose: StatusPurpose::Revocation,
                    status_list_index: "42".to_string(),
                    status_list_credential: "https://example.com/status/1".to_string(),
                }),
                evidence: None,
                terms_of_use: None,
            })
            .await
            .unwrap();

        let resolver = DidResolver::default();

        // No status list bitstring provided — should fail (fail-closed)
        let result = verify_vc(VerifyVcOptions {
            vc: &vc,
            resolver: &resolver,
            tir_registry: None,
            claimed_paths: vec![],
            status_list_bitstring: None,
        })
        .await;

        assert!(!result.valid, "Missing status list should fail validation");
        assert_eq!(result.status_ok, Some(false));
    }

    #[tokio::test]
    async fn test_verify_revoked_credential() {
        let provider = MemoryKeyProvider::new();
        provider
            .generate_key("rev-key", KeyCategory::Adapter)
            .await
            .unwrap();

        let signer = VcSigner::from_key_id(&provider, "rev-key").await.unwrap();

        let vc = signer
            .sign(BuildVcOptions {
                vc_type: vec!["PropertyDataCredential".to_string()],
                credential_subject: CredentialSubject {
                    id: "urn:pdtf:uprn:999999999".to_string(),
                    claims: HashMap::new(),
                },
                id: Some("urn:uuid:revoked-vc".to_string()),
                valid_from: Some("2024-06-01T12:00:00Z".to_string()),
                valid_until: None,
                credential_status: Some(CredentialStatus {
                    id: "https://example.com/status/1#42".to_string(),
                    status_type: "BitstringStatusListEntry".to_string(),
                    status_purpose: StatusPurpose::Revocation,
                    status_list_index: "42".to_string(),
                    status_list_credential: "https://example.com/status/1".to_string(),
                }),
                evidence: None,
                terms_of_use: None,
            })
            .await
            .unwrap();

        // Create status list with bit 42 set (revoked)
        let mut bitstring = create_status_list(MIN_BITSTRING_SIZE).unwrap();
        set_bit(&mut bitstring, 42).unwrap();
        let encoded = encode_status_list(&bitstring).unwrap();

        let resolver = DidResolver::default();

        let result = verify_vc(VerifyVcOptions {
            vc: &vc,
            resolver: &resolver,
            tir_registry: None,
            claimed_paths: vec![],
            status_list_bitstring: Some(&encoded),
        })
        .await;

        assert!(!result.valid);
        assert_eq!(result.status_ok, Some(false));
        assert!(result.errors.iter().any(|e| e.contains("revoked")));
    }

    #[tokio::test]
    async fn test_empty_subject_id_fails() {
        let provider = MemoryKeyProvider::new();
        provider
            .generate_key("subj-key", KeyCategory::Adapter)
            .await
            .unwrap();

        let signer = VcSigner::from_key_id(&provider, "subj-key").await.unwrap();

        let vc = signer
            .sign(BuildVcOptions {
                vc_type: vec!["PropertyDataCredential".to_string()],
                credential_subject: CredentialSubject {
                    id: String::new(), // empty!
                    claims: HashMap::new(),
                },
                id: Some("urn:uuid:empty-subj".to_string()),
                valid_from: Some("2024-06-01T12:00:00Z".to_string()),
                valid_until: None,
                credential_status: None,
                evidence: None,
                terms_of_use: None,
            })
            .await
            .unwrap();

        let resolver = DidResolver::default();

        let result = verify_vc(VerifyVcOptions {
            vc: &vc,
            resolver: &resolver,
            tir_registry: None,
            claimed_paths: vec![],
            status_list_bitstring: None,
        })
        .await;

        assert!(!result.valid);
        assert!(result
            .errors
            .iter()
            .any(|e| e.contains("credentialSubject.id")));
    }
}
