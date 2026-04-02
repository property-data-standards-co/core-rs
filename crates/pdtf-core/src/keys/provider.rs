//! KeyProvider trait — abstracts over key storage and signing backends.

use crate::error::Result;
use crate::types::{KeyCategory, KeyRecord};
use async_trait::async_trait;

/// Key provider interface — abstracts over storage backends.
///
/// All signing operations go through this interface. Implementations
/// might store keys in memory, on disk, in a KMS, etc.
#[cfg_attr(not(target_arch = "wasm32"), async_trait)]
#[cfg_attr(target_arch = "wasm32", async_trait(?Send))]
pub trait KeyProvider: Send + Sync {
    /// Generate a new Ed25519 key pair, store it, return the key record.
    async fn generate_key(&self, key_id: &str, category: KeyCategory) -> Result<KeyRecord>;

    /// Sign arbitrary bytes with the named key.
    async fn sign(&self, key_id: &str, data: &[u8]) -> Result<Vec<u8>>;

    /// Get the public key bytes for a key.
    async fn get_public_key(&self, key_id: &str) -> Result<Vec<u8>>;

    /// Derive the did:key identifier for a key.
    async fn resolve_did_key(&self, key_id: &str) -> Result<String>;
}

/// In-memory key provider for testing and simple use cases.
pub mod memory {
    use super::*;
    use crate::keys::ed25519::{derive_did_key, generate_keypair};
    use ed25519_dalek::{Signer, SigningKey};
    use std::collections::HashMap;
    use std::sync::Mutex;

    struct StoredKey {
        signing_key: SigningKey,
        record: KeyRecord,
    }

    /// Simple in-memory key provider.
    pub struct MemoryKeyProvider {
        keys: Mutex<HashMap<String, StoredKey>>,
    }

    impl MemoryKeyProvider {
        pub fn new() -> Self {
            Self {
                keys: Mutex::new(HashMap::new()),
            }
        }
    }

    impl Default for MemoryKeyProvider {
        fn default() -> Self {
            Self::new()
        }
    }

    #[cfg_attr(not(target_arch = "wasm32"), async_trait)]
    #[cfg_attr(target_arch = "wasm32", async_trait(?Send))]
    impl KeyProvider for MemoryKeyProvider {
        async fn generate_key(&self, key_id: &str, category: KeyCategory) -> Result<KeyRecord> {
            let kp = generate_keypair();
            let did = derive_did_key(kp.verifying_key.as_bytes())?;
            let now = chrono_now();

            let record = KeyRecord {
                key_id: key_id.to_string(),
                did,
                public_key: kp.verifying_key.as_bytes().to_vec(),
                category,
                created_at: now,
                rotated_at: None,
            };

            let stored = StoredKey {
                signing_key: kp.signing_key,
                record: record.clone(),
            };

            self.keys
                .lock()
                .map_err(|_| crate::error::PdtfError::InvalidKey("Key store lock poisoned".into()))?
                .insert(key_id.to_string(), stored);

            Ok(record)
        }

        async fn sign(&self, key_id: &str, data: &[u8]) -> Result<Vec<u8>> {
            let keys = self.keys.lock().map_err(|_| {
                crate::error::PdtfError::InvalidKey("Key store lock poisoned".into())
            })?;
            let stored = keys.get(key_id).ok_or_else(|| {
                crate::error::PdtfError::InvalidKey(format!("Key not found: {key_id}"))
            })?;
            let sig = stored.signing_key.sign(data);
            Ok(sig.to_bytes().to_vec())
        }

        async fn get_public_key(&self, key_id: &str) -> Result<Vec<u8>> {
            let keys = self.keys.lock().map_err(|_| {
                crate::error::PdtfError::InvalidKey("Key store lock poisoned".into())
            })?;
            let stored = keys.get(key_id).ok_or_else(|| {
                crate::error::PdtfError::InvalidKey(format!("Key not found: {key_id}"))
            })?;
            Ok(stored.record.public_key.clone())
        }

        async fn resolve_did_key(&self, key_id: &str) -> Result<String> {
            let keys = self.keys.lock().map_err(|_| {
                crate::error::PdtfError::InvalidKey("Key store lock poisoned".into())
            })?;
            let stored = keys.get(key_id).ok_or_else(|| {
                crate::error::PdtfError::InvalidKey(format!("Key not found: {key_id}"))
            })?;
            Ok(stored.record.did.clone())
        }
    }

    fn chrono_now() -> String {
        use std::time::{SystemTime, UNIX_EPOCH};
        let secs = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        crate::signer::proof::format_epoch_timestamp(secs)
    }
}

#[cfg(test)]
mod tests {
    use super::memory::MemoryKeyProvider;
    use super::*;
    use crate::types::KeyCategory;

    #[tokio::test]
    async fn test_memory_provider_generate_and_sign() {
        let provider = MemoryKeyProvider::new();
        let record = provider
            .generate_key("test-key-1", KeyCategory::Adapter)
            .await
            .unwrap();
        assert!(record.did.starts_with("did:key:z6Mk"));

        let data = b"hello world";
        let sig = provider.sign("test-key-1", data).await.unwrap();
        assert_eq!(sig.len(), 64); // Ed25519 signature is 64 bytes

        let pk = provider.get_public_key("test-key-1").await.unwrap();
        assert_eq!(pk, record.public_key);
    }

    #[tokio::test]
    async fn test_memory_provider_key_not_found() {
        let provider = MemoryKeyProvider::new();
        let result = provider.sign("nonexistent", b"data").await;
        assert!(result.is_err());
    }
}
