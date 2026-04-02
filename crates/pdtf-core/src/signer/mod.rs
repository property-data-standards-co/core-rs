//! VC signing — DataIntegrityProof creation and verification, VC builder.

pub mod proof;

use crate::error::Result;
use crate::keys::ed25519::derive_did_key;
use crate::keys::provider::KeyProvider;
use crate::types::*;
use proof::{create_proof, CreateProofOptions};

const W3C_VC_CONTEXT: &str = "https://www.w3.org/ns/credentials/v2";
const PDTF_CONTEXT: &str = "https://propdata.org.uk/credentials/v2";

/// Options for building a VC.
pub struct BuildVcOptions {
    /// Credential type(s) beyond 'VerifiableCredential'.
    pub vc_type: Vec<String>,
    /// Credential subject.
    pub credential_subject: CredentialSubject,
    /// Credential ID (optional).
    pub id: Option<String>,
    /// Valid from (ISO timestamp). Defaults to provided or fallback.
    pub valid_from: Option<String>,
    /// Valid until (ISO timestamp, optional).
    pub valid_until: Option<String>,
    /// Credential status for revocation.
    pub credential_status: Option<CredentialStatus>,
    /// Evidence array.
    pub evidence: Option<Vec<Evidence>>,
    /// Terms of use.
    pub terms_of_use: Option<Vec<TermsOfUse>>,
}

/// High-level VC signing interface.
///
/// Builds complete Verifiable Credentials with DataIntegrityProof.
pub struct VcSigner<'a> {
    key_provider: &'a dyn KeyProvider,
    key_id: String,
    issuer_did: String,
}

impl<'a> VcSigner<'a> {
    /// Create a VcSigner for a specific issuer key.
    pub fn new(key_provider: &'a dyn KeyProvider, key_id: &str, issuer_did: &str) -> Self {
        Self {
            key_provider,
            key_id: key_id.to_string(),
            issuer_did: issuer_did.to_string(),
        }
    }

    /// Create a VcSigner from a key ID, resolving the DID automatically.
    /// Only works for did:key issuers.
    pub async fn from_key_id(key_provider: &'a dyn KeyProvider, key_id: &str) -> Result<Self> {
        let pk = key_provider.get_public_key(key_id).await?;
        let did = derive_did_key(&pk)?;
        Ok(Self::new(key_provider, key_id, &did))
    }

    /// Get the issuer DID.
    pub fn did(&self) -> &str {
        &self.issuer_did
    }

    /// Build and sign a Verifiable Credential.
    pub async fn sign(&self, options: BuildVcOptions) -> Result<VerifiableCredential> {
        let valid_from = options
            .valid_from
            .unwrap_or_else(|| "2024-01-01T00:00:00Z".to_string());

        // Build unsigned VC
        let vc = VerifiableCredential {
            context: vec![W3C_VC_CONTEXT.to_string(), PDTF_CONTEXT.to_string()],
            vc_type: {
                let mut types = vec!["VerifiableCredential".to_string()];
                types.extend(options.vc_type);
                types
            },
            id: options.id,
            issuer: Issuer::Did(self.issuer_did.clone()),
            valid_from: valid_from.clone(),
            valid_until: options.valid_until,
            credential_subject: options.credential_subject,
            credential_status: options.credential_status,
            proof: None,
            evidence: options.evidence,
            terms_of_use: options.terms_of_use,
        };

        let verification_method = self.build_verification_method();

        let proof = create_proof(CreateProofOptions {
            document: &vc,
            key_id: &self.key_id,
            verification_method: &verification_method,
            key_provider: self.key_provider,
            created: Some(&valid_from),
        })
        .await?;

        Ok(VerifiableCredential {
            proof: Some(proof),
            ..vc
        })
    }

    /// Build the verification method URI.
    fn build_verification_method(&self) -> String {
        if self.issuer_did.starts_with("did:key:") {
            let multibase = &self.issuer_did["did:key:".len()..];
            format!("{}#{}", self.issuer_did, multibase)
        } else {
            // did:web — use conventional key-1 fragment
            format!("{}#key-1", self.issuer_did)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::keys::provider::memory::MemoryKeyProvider;
    use crate::signer::proof::verify_proof;
    use std::collections::HashMap;

    #[tokio::test]
    async fn test_vc_signer_sign() {
        let provider = MemoryKeyProvider::new();
        provider
            .generate_key("signer-1", KeyCategory::Adapter)
            .await
            .unwrap();

        let signer = VcSigner::from_key_id(&provider, "signer-1").await.unwrap();
        assert!(signer.did().starts_with("did:key:z6Mk"));

        let vc = signer
            .sign(BuildVcOptions {
                vc_type: vec!["PropertyDataCredential".to_string()],
                credential_subject: CredentialSubject {
                    id: "urn:pdtf:uprn:123456789".to_string(),
                    claims: HashMap::new(),
                },
                id: Some("urn:uuid:test".to_string()),
                valid_from: Some("2024-06-01T12:00:00Z".to_string()),
                valid_until: None,
                credential_status: None,
                evidence: None,
                terms_of_use: None,
            })
            .await
            .unwrap();

        assert!(vc.proof.is_some());
        assert_eq!(vc.vc_type.len(), 2);
        assert_eq!(vc.context.len(), 2);

        // Verify the signed VC
        let pk = provider.get_public_key("signer-1").await.unwrap();
        let pk_arr: [u8; 32] = pk.try_into().unwrap();
        assert!(verify_proof(&vc, &pk_arr));
    }

    #[tokio::test]
    async fn test_vc_signer_did_web_verification_method() {
        let provider = MemoryKeyProvider::new();
        provider
            .generate_key("web-key", KeyCategory::Platform)
            .await
            .unwrap();

        let signer = VcSigner::new(&provider, "web-key", "did:web:example.com");
        assert_eq!(signer.build_verification_method(), "did:web:example.com#key-1");
    }
}
