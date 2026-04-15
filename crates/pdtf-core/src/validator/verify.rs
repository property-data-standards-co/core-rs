//! 4-stage Verifiable Credential verification.
//!
//! 1. Structure check — required fields, valid types, proof type/cryptosuite
//! 2. Signature verification — resolve DID → issuer binding → assertionMethod → verify_proof
//! 3. TIR check — issuer authorised for claimed paths
//! 4. Status check — credential not revoked

use crate::did::resolver::DidResolver;
use crate::error::{PdtfError, Result};
use crate::federation::verify::{verify_tir, verify_trust_coverage};
use crate::federation::TrustResolver;
use crate::signer::proof::verify_proof;
use crate::status::bitstring::{decode_status_list, get_bit};
use crate::types::*;
use chrono::DateTime;
use serde::{Deserialize, Serialize};
use std::sync::Arc;

/// Required W3C VC v2 context URI.
const W3C_VC_V2_CONTEXT: &str = "https://www.w3.org/ns/credentials/v2";

/// Clock skew tolerance for timestamp checks (5 minutes).
const CLOCK_SKEW_TOLERANCE_SECS: i64 = 300;

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
    /// TIR registry for authorisation check (legacy). If None, TIR check is skipped
    /// unless `trust_resolver` is provided.
    pub tir_registry: Option<&'a TirRegistry>,
    /// Trust resolver for federation-based authorisation check.
    /// Takes precedence over `tir_registry` when both are set.
    pub trust_resolver: Option<Arc<dyn TrustResolver>>,
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

    // Stage 2: Signature verification (includes issuer binding + assertionMethod)
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

    // Stage 3: Trust check (fail-closed: untrusted issuer fails validation)
    // Prefer trust_resolver over legacy tir_registry when both are set.
    if let Some(ref trust_resolver) = options.trust_resolver {
        let resolution = trust_resolver
            .resolve_trust(options.vc.issuer.id(), None)
            .await;
        let tir_result = verify_trust_coverage(&resolution, &options.claimed_paths);
        if !tir_result.trusted {
            result.errors.push(format!(
                "Trust: issuer not authorised. Uncovered: {:?}",
                tir_result.uncovered_paths
            ));
        }
        result.tir_result = Some(tir_result);
    } else if let Some(registry) = options.tir_registry {
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

/// Parse an ISO 8601 / RFC 3339 timestamp to epoch seconds.
/// Fails closed: returns Err if the timestamp cannot be parsed.
pub(crate) fn parse_timestamp(ts: &str) -> Result<i64> {
    DateTime::parse_from_rfc3339(ts)
        .map(|dt| dt.timestamp())
        .map_err(|e| {
            PdtfError::VerificationError(format!("Invalid timestamp '{}': {}", ts, e))
        })
}

/// Stage 1: Check VC structure.
fn check_structure(vc: &VerifiableCredential) -> Result<()> {
    // Must have exact W3C VC v2 context URI
    if vc.context.is_empty() {
        return Err(PdtfError::VerificationError("Missing @context".into()));
    }

    if !vc.context.iter().any(|c| c == W3C_VC_V2_CONTEXT) {
        return Err(PdtfError::VerificationError(format!(
            "Missing required W3C VC v2 context: {}",
            W3C_VC_V2_CONTEXT
        )));
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
    let proof = vc.proof.as_ref().ok_or_else(|| {
        PdtfError::VerificationError("Missing proof".into())
    })?;

    // Validate proof type — must be DataIntegrityProof
    if proof.proof_type != "DataIntegrityProof" {
        return Err(PdtfError::VerificationError(format!(
            "Unexpected proof type: '{}' (expected 'DataIntegrityProof')",
            proof.proof_type
        )));
    }

    // Validate proof cryptosuite — must be eddsa-jcs-2022
    if proof.cryptosuite != "eddsa-jcs-2022" {
        return Err(PdtfError::VerificationError(format!(
            "Unexpected cryptosuite: '{}' (expected 'eddsa-jcs-2022')",
            proof.cryptosuite
        )));
    }

    // credentialSubject.id must not be empty
    if vc.credential_subject.id.is_empty() {
        return Err(PdtfError::VerificationError(
            "credentialSubject.id must not be empty".into(),
        ));
    }

    // Check validFrom — fail-closed on parse error
    let valid_from_epoch = parse_timestamp(&vc.valid_from)?;
    let now = chrono::Utc::now().timestamp();

    if valid_from_epoch > now + CLOCK_SKEW_TOLERANCE_SECS {
        return Err(PdtfError::VerificationError(format!(
            "validFrom '{}' is in the future",
            vc.valid_from
        )));
    }

    // Check validUntil is not in the past (credential expired) — fail-closed on parse error
    if let Some(ref valid_until) = vc.valid_until {
        let valid_until_epoch = parse_timestamp(valid_until)?;
        if valid_until_epoch + CLOCK_SKEW_TOLERANCE_SECS < now {
            return Err(PdtfError::VerificationError(format!(
                "Credential expired: validUntil '{}'",
                valid_until
            )));
        }
    }

    Ok(())
}

/// Stage 2: Verify the signature by resolving the issuer DID.
///
/// Includes:
/// - Issuer ↔ proof DID binding check
/// - assertionMethod membership check
/// - Cryptographic signature verification
async fn verify_signature(vc: &VerifiableCredential, resolver: &DidResolver) -> Result<bool> {
    let proof = vc
        .proof
        .as_ref()
        .ok_or_else(|| PdtfError::VerificationError("No proof to verify".into()))?;

    // Extract DID from verification method (part before '#')
    let proof_did = proof
        .verification_method
        .split('#')
        .next()
        .unwrap_or(&proof.verification_method);

    // FIX 1: Issuer binding — vc.issuer must match the DID from proof.verificationMethod
    let issuer_did = vc.issuer.id();
    if issuer_did != proof_did {
        return Err(PdtfError::VerificationError(format!(
            "Issuer DID '{}' does not match proof verification method DID '{}'",
            issuer_did, proof_did
        )));
    }

    // Resolve DID document
    let doc = resolver.resolve(proof_did).await?;

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

    // FIX 4: Check that the verification method is in assertionMethod
    let assertion_methods = doc.assertion_method.as_ref().ok_or_else(|| {
        PdtfError::VerificationError(
            "DID document has no assertionMethod — cannot verify proof purpose".into(),
        )
    })?;

    let vm_in_assertion = assertion_methods.iter().any(|am| {
        am.id() == proof.verification_method
    });

    if !vm_in_assertion {
        return Err(PdtfError::VerificationError(format!(
            "Verification method '{}' is not listed in assertionMethod",
            proof.verification_method
        )));
    }

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
            trust_resolver: None,
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
            trust_resolver: None,
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
            trust_resolver: None,
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
            trust_resolver: None,
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
            trust_resolver: None,
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
            trust_resolver: None,
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
            trust_resolver: None,
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

    // ── New tests for review fixes ──────────────────────────────────────

    #[tokio::test]
    async fn test_issuer_proof_did_mismatch_fails() {
        let (mut vc, _provider) = make_signed_vc().await;
        // Tamper the issuer to a different DID — proof was signed by original key
        vc.issuer = Issuer::Did("did:web:attacker.example".to_string());

        let resolver = DidResolver::default();

        let result = verify_vc(VerifyVcOptions {
            vc: &vc,
            resolver: &resolver,
            tir_registry: None,
            trust_resolver: None,
            claimed_paths: vec![],
            status_list_bitstring: None,
        })
        .await;

        assert!(!result.valid, "Issuer/proof DID mismatch must fail");
        assert!(result.errors.iter().any(|e| e.contains("does not match")));
    }

    #[tokio::test]
    async fn test_fractional_second_timestamp_parsed() {
        // Fractional seconds must be parsed correctly, not skip the check
        let provider = MemoryKeyProvider::new();
        provider
            .generate_key("frac-key", KeyCategory::Adapter)
            .await
            .unwrap();

        let signer = VcSigner::from_key_id(&provider, "frac-key").await.unwrap();

        let vc = signer
            .sign(BuildVcOptions {
                vc_type: vec!["PropertyDataCredential".to_string()],
                credential_subject: CredentialSubject {
                    id: "urn:pdtf:uprn:123456789".to_string(),
                    claims: HashMap::new(),
                },
                id: Some("urn:uuid:frac-ts".to_string()),
                valid_from: Some("2024-06-01T12:00:00.123Z".to_string()),
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
            trust_resolver: None,
            claimed_paths: vec![],
            status_list_bitstring: None,
        })
        .await;

        assert!(result.valid, "Fractional-second timestamps must be accepted");
        assert!(result.structure_ok);
    }

    #[tokio::test]
    async fn test_offset_timestamp_parsed() {
        let provider = MemoryKeyProvider::new();
        provider
            .generate_key("offset-key", KeyCategory::Adapter)
            .await
            .unwrap();

        let signer = VcSigner::from_key_id(&provider, "offset-key").await.unwrap();

        let vc = signer
            .sign(BuildVcOptions {
                vc_type: vec!["PropertyDataCredential".to_string()],
                credential_subject: CredentialSubject {
                    id: "urn:pdtf:uprn:123456789".to_string(),
                    claims: HashMap::new(),
                },
                id: Some("urn:uuid:offset-ts".to_string()),
                valid_from: Some("2024-06-01T12:00:00+00:00".to_string()),
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
            trust_resolver: None,
            claimed_paths: vec![],
            status_list_bitstring: None,
        })
        .await;

        assert!(result.valid, "Offset timestamps (+00:00) must be accepted");
        assert!(result.structure_ok);
    }

    #[tokio::test]
    async fn test_wrong_proof_type_fails() {
        let (mut vc, _provider) = make_signed_vc().await;
        if let Some(ref mut proof) = vc.proof {
            proof.proof_type = "Ed25519Signature2020".to_string();
        }

        let resolver = DidResolver::default();

        let result = verify_vc(VerifyVcOptions {
            vc: &vc,
            resolver: &resolver,
            tir_registry: None,
            trust_resolver: None,
            claimed_paths: vec![],
            status_list_bitstring: None,
        })
        .await;

        assert!(!result.valid, "Wrong proof type must fail structure check");
        assert!(!result.structure_ok);
        assert!(result.errors.iter().any(|e| e.contains("proof type")));
    }

    #[tokio::test]
    async fn test_wrong_cryptosuite_fails() {
        let (mut vc, _provider) = make_signed_vc().await;
        if let Some(ref mut proof) = vc.proof {
            proof.cryptosuite = "ecdsa-jcs-2019".to_string();
        }

        let resolver = DidResolver::default();

        let result = verify_vc(VerifyVcOptions {
            vc: &vc,
            resolver: &resolver,
            tir_registry: None,
            trust_resolver: None,
            claimed_paths: vec![],
            status_list_bitstring: None,
        })
        .await;

        assert!(!result.valid, "Wrong cryptosuite must fail structure check");
        assert!(!result.structure_ok);
        assert!(result.errors.iter().any(|e| e.contains("cryptosuite")));
    }

    #[test]
    fn test_parse_timestamp_rfc3339() {
        assert!(parse_timestamp("2024-06-01T12:00:00Z").is_ok());
        assert!(parse_timestamp("2024-06-01T12:00:00.123Z").is_ok());
        assert!(parse_timestamp("2024-06-01T12:00:00+00:00").is_ok());
        assert!(parse_timestamp("2024-06-01T12:00:00.999999+05:30").is_ok());
        // Invalid timestamps must error
        assert!(parse_timestamp("not-a-date").is_err());
        assert!(parse_timestamp("2024-06-01").is_err());
        assert!(parse_timestamp("").is_err());
    }
}
