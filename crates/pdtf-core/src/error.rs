//! PDTF error types.

use thiserror::Error;

/// Unified error type for all PDTF operations.
#[derive(Error, Debug)]
pub enum PdtfError {
    #[error("Invalid key: {0}")]
    InvalidKey(String),

    #[error("Signing error: {0}")]
    SigningError(String),

    #[error("Verification error: {0}")]
    VerificationError(String),

    #[error("DID error: {0}")]
    DidError(String),

    #[error("DID resolution failed: {0}")]
    DidResolutionFailed(String),

    #[error("Invalid URN: {0}")]
    InvalidUrn(String),

    #[error("Status list error: {0}")]
    StatusListError(String),

    #[error("TIR error: {0}")]
    TirError(String),

    #[error("Serialisation error: {0}")]
    SerialisationError(String),

    #[error("HTTP error: {0}")]
    HttpError(String),

    #[error("Encoding error: {0}")]
    EncodingError(String),
}

impl From<serde_json::Error> for PdtfError {
    fn from(e: serde_json::Error) -> Self {
        PdtfError::SerialisationError(e.to_string())
    }
}

impl From<ed25519_dalek::SignatureError> for PdtfError {
    fn from(e: ed25519_dalek::SignatureError) -> Self {
        PdtfError::SigningError(e.to_string())
    }
}

#[cfg(feature = "network")]
impl From<reqwest::Error> for PdtfError {
    fn from(e: reqwest::Error) -> Self {
        PdtfError::HttpError(e.to_string())
    }
}

/// Convenience type alias.
pub type Result<T> = std::result::Result<T, PdtfError>;
