//! # PDTF Core
//!
//! PDTF 2.0 cryptographic core library — Ed25519 signing/verification,
//! DID resolution, Verifiable Credentials, Bitstring Status List, and
//! Trusted Issuer Registry.
//!
//! ## Features
//!
//! - **`network`** (default) — enables HTTP-based did:web resolution,
//!   status list checking, and TIR registry fetching via `reqwest`.
//!
//! ## Quick Start
//!
//! ```rust,no_run
//! use pdtf_core::keys::provider::memory::MemoryKeyProvider;
//! use pdtf_core::keys::provider::KeyProvider;
//! use pdtf_core::signer::{VcSigner, BuildVcOptions};
//! use pdtf_core::types::*;
//! use std::collections::HashMap;
//!
//! # async fn example() -> pdtf_core::error::Result<()> {
//! // Generate a key
//! let provider = MemoryKeyProvider::new();
//! let record = provider.generate_key("my-key", KeyCategory::Adapter).await?;
//!
//! // Create a signer
//! let signer = VcSigner::from_key_id(&provider, "my-key").await?;
//!
//! // Sign a VC
//! let vc = signer.sign(BuildVcOptions {
//!     vc_type: vec!["PropertyDataCredential".to_string()],
//!     credential_subject: CredentialSubject {
//!         id: "urn:pdtf:uprn:123456789".to_string(),
//!         claims: HashMap::new(),
//!     },
//!     id: None,
//!     valid_from: None,
//!     valid_until: None,
//!     credential_status: None,
//!     evidence: None,
//!     terms_of_use: None,
//! }).await?;
//!
//! println!("Signed VC: {}", serde_json::to_string_pretty(&vc).unwrap());
//! # Ok(())
//! # }
//! ```

pub mod did;
pub mod error;
pub mod keys;
pub mod signer;
pub mod status;
pub mod federation;
#[deprecated(since = "0.2.0", note = "Use the `federation` module instead")]
pub mod tir;
pub mod types;
pub mod validator;

// Re-export key types at crate level for convenience
pub use error::{PdtfError, Result};
