//! PDTF 2.0 Core Types
//!
//! Canonical type definitions used across all modules.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;

// ─── Verifiable Credentials ─────────────────────────────────────────────────

/// W3C VC 2.0 compliant Verifiable Credential.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VerifiableCredential {
    #[serde(rename = "@context")]
    pub context: Vec<String>,
    #[serde(rename = "type")]
    pub vc_type: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub id: Option<String>,
    pub issuer: Issuer,
    #[serde(rename = "validFrom")]
    pub valid_from: String,
    #[serde(rename = "validUntil", skip_serializing_if = "Option::is_none")]
    pub valid_until: Option<String>,
    #[serde(rename = "credentialSubject")]
    pub credential_subject: CredentialSubject,
    #[serde(rename = "credentialStatus", skip_serializing_if = "Option::is_none")]
    pub credential_status: Option<CredentialStatus>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub proof: Option<DataIntegrityProof>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub evidence: Option<Vec<Evidence>>,
    #[serde(rename = "termsOfUse", skip_serializing_if = "Option::is_none")]
    pub terms_of_use: Option<Vec<TermsOfUse>>,
}

/// Issuer — can be a simple DID string or an object with id.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(untagged)]
pub enum Issuer {
    Did(String),
    Object {
        id: String,
        #[serde(flatten)]
        extra: HashMap<String, serde_json::Value>,
    },
}

impl Issuer {
    /// Get the DID string regardless of variant.
    pub fn id(&self) -> &str {
        match self {
            Issuer::Did(did) => did,
            Issuer::Object { id, .. } => id,
        }
    }
}

/// Credential subject with id and arbitrary claims.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CredentialSubject {
    pub id: String,
    #[serde(flatten)]
    pub claims: HashMap<String, serde_json::Value>,
}

/// W3C Bitstring Status List entry.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CredentialStatus {
    pub id: String,
    #[serde(rename = "type")]
    pub status_type: String, // "BitstringStatusListEntry"
    #[serde(rename = "statusPurpose")]
    pub status_purpose: StatusPurpose,
    #[serde(rename = "statusListIndex")]
    pub status_list_index: String,
    #[serde(rename = "statusListCredential")]
    pub status_list_credential: String,
}

/// Status purpose.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub enum StatusPurpose {
    Revocation,
    Suspension,
}

/// DataIntegrityProof with eddsa-jcs-2022.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DataIntegrityProof {
    #[serde(rename = "type")]
    pub proof_type: String, // "DataIntegrityProof"
    pub cryptosuite: String, // "eddsa-jcs-2022"
    #[serde(rename = "verificationMethod")]
    pub verification_method: String,
    #[serde(rename = "proofPurpose")]
    pub proof_purpose: String, // "assertionMethod"
    pub created: String,
    #[serde(rename = "proofValue")]
    pub proof_value: String,
}

// ─── Evidence ───────────────────────────────────────────────────────────────

/// Evidence attached to a VC.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Evidence {
    #[serde(rename = "type")]
    pub evidence_type: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub source: Option<String>,
    #[serde(rename = "retrievedAt", skip_serializing_if = "Option::is_none")]
    pub retrieved_at: Option<String>,
    #[serde(rename = "documentReference", skip_serializing_if = "Option::is_none")]
    pub document_reference: Option<String>,
    #[serde(flatten)]
    pub extra: HashMap<String, serde_json::Value>,
}

/// Terms of use for access control.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TermsOfUse {
    #[serde(rename = "type")]
    pub terms_type: String, // "PdtfAccessPolicy"
    pub confidentiality: Confidentiality,
    #[serde(rename = "authorisedRoles", skip_serializing_if = "Option::is_none")]
    pub authorised_roles: Option<Vec<String>>,
}

/// Confidentiality level.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub enum Confidentiality {
    Public,
    TransactionParticipants,
    RoleRestricted,
    PartyOnly,
}

// ─── DIDs ───────────────────────────────────────────────────────────────────

/// DID Document.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DidDocument {
    #[serde(rename = "@context")]
    pub context: Vec<String>,
    pub id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub controller: Option<StringOrArray>,
    #[serde(rename = "alsoKnownAs", skip_serializing_if = "Option::is_none")]
    pub also_known_as: Option<Vec<String>>,
    #[serde(rename = "verificationMethod", skip_serializing_if = "Option::is_none")]
    pub verification_method: Option<Vec<VerificationMethod>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub authentication: Option<Vec<VerificationMethodOrRef>>,
    #[serde(rename = "assertionMethod", skip_serializing_if = "Option::is_none")]
    pub assertion_method: Option<Vec<VerificationMethodOrRef>>,
    #[serde(rename = "keyAgreement", skip_serializing_if = "Option::is_none")]
    pub key_agreement: Option<Vec<VerificationMethodOrRef>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub service: Option<Vec<ServiceEndpoint>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub deactivated: Option<bool>,
}

/// String or array of strings.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(untagged)]
pub enum StringOrArray {
    Single(String),
    Multiple(Vec<String>),
}

/// Verification method within a DID document.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct VerificationMethod {
    pub id: String,
    #[serde(rename = "type")]
    pub method_type: String,
    pub controller: String,
    #[serde(rename = "publicKeyMultibase", skip_serializing_if = "Option::is_none")]
    pub public_key_multibase: Option<String>,
}

/// A verification method that can be either a string reference or an embedded object.
/// Matches the DID spec where authentication/assertionMethod/keyAgreement can contain
/// either a string reference to a verification method or an embedded verification method.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(untagged)]
pub enum VerificationMethodOrRef {
    Reference(String),
    Embedded(VerificationMethod),
}

impl VerificationMethodOrRef {
    /// Get the ID of the verification method (either the reference string or the embedded id).
    pub fn id(&self) -> &str {
        match self {
            VerificationMethodOrRef::Reference(s) => s,
            VerificationMethodOrRef::Embedded(vm) => &vm.id,
        }
    }
}

/// Service endpoint in a DID document.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServiceEndpoint {
    pub id: String,
    #[serde(rename = "type")]
    pub service_type: String,
    #[serde(rename = "serviceEndpoint")]
    pub service_endpoint: serde_json::Value,
}

// ─── Key Management ─────────────────────────────────────────────────────────

/// Key category.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub enum KeyCategory {
    Adapter,
    User,
    Platform,
    Organisation,
}

/// Stored key record.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KeyRecord {
    pub key_id: String,
    pub did: String,
    pub public_key: Vec<u8>,
    pub category: KeyCategory,
    pub created_at: String,
    pub rotated_at: Option<String>,
}

// ─── TIR ────────────────────────────────────────────────────────────────────

/// Trust level for an issuer.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub enum TrustLevel {
    RootIssuer,
    TrustedProxy,
    AccountProvider,
}

/// Issuer status.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub enum IssuerStatus {
    Active,
    Deprecated,
    Revoked,
    Planned,
}

/// TIR issuer entry.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TirIssuerEntry {
    pub slug: String,
    pub did: String,
    pub name: String,
    #[serde(rename = "trustLevel")]
    pub trust_level: TrustLevel,
    pub status: IssuerStatus,
    #[serde(rename = "authorisedPaths")]
    pub authorised_paths: Vec<String>,
    #[serde(rename = "proxyFor", skip_serializing_if = "Option::is_none")]
    pub proxy_for: Option<String>,
    #[serde(rename = "validFrom", skip_serializing_if = "Option::is_none")]
    pub valid_from: Option<String>,
    #[serde(rename = "validUntil", skip_serializing_if = "Option::is_none")]
    pub valid_until: Option<String>,
    #[serde(
        rename = "regulatoryRegistration",
        skip_serializing_if = "Option::is_none"
    )]
    pub regulatory_registration: Option<String>,
    #[serde(flatten)]
    pub extra: HashMap<String, serde_json::Value>,
}

/// TIR account provider entry.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TirAccountProvider {
    pub slug: String,
    pub did: String,
    pub name: String,
    pub status: IssuerStatus,
    #[serde(
        rename = "managedOrganisations",
        skip_serializing_if = "Option::is_none"
    )]
    pub managed_organisations: Option<String>,
    #[serde(rename = "validFrom", skip_serializing_if = "Option::is_none")]
    pub valid_from: Option<String>,
    #[serde(flatten)]
    pub extra: HashMap<String, serde_json::Value>,
}

/// Complete TIR registry.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TirRegistry {
    pub version: String,
    #[serde(rename = "lastUpdated")]
    pub last_updated: String,
    pub issuers: HashMap<String, TirIssuerEntry>,
    #[serde(rename = "userAccountProviders")]
    pub user_account_providers: HashMap<String, TirAccountProvider>,
}

/// Result of TIR verification (legacy path-coverage check).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TirVerificationResult {
    pub trusted: bool,
    pub issuer_slug: Option<String>,
    pub trust_level: Option<TrustLevel>,
    pub status: Option<IssuerStatus>,
    pub paths_covered: Vec<String>,
    pub uncovered_paths: Vec<String>,
    pub warnings: Vec<String>,
}

// ─── Federation / Trust Resolution ──────────────────────────────────────────

/// A trust mark representing an issuer's authorisation scope.
///
/// In the bootstrap model this maps 1:1 to a TIR issuer entry.
/// In OpenID Federation this will be derived from verified trust mark JWTs.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TrustMark {
    /// The trust level granted by this mark.
    #[serde(rename = "trustLevel")]
    pub trust_level: TrustLevel,
    /// Entity:path patterns this mark authorises.
    #[serde(rename = "authorisedPaths")]
    pub authorised_paths: Vec<String>,
}

/// Result of trust resolution from any `TrustResolver` implementation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TrustResolutionResult {
    /// Whether the issuer is trusted (active, valid, resolvable).
    pub trusted: bool,
    /// Issuer slug/identifier, if known.
    pub issuer_slug: Option<String>,
    /// Trust marks collected during resolution.
    pub trust_marks: Vec<TrustMark>,
    /// Warnings encountered during resolution.
    pub warnings: Vec<String>,
}

// ─── Status List ────────────────────────────────────────────────────────────

/// Status list metadata.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StatusList {
    pub issuer_did: String,
    pub list_id: String,
    pub purpose: StatusPurpose,
    pub bitstring: Vec<u8>,
    pub size: usize,
    pub next_index: usize,
}
