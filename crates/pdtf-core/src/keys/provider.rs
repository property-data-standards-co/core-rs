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
                .unwrap()
                .insert(key_id.to_string(), stored);

            Ok(record)
        }

        async fn sign(&self, key_id: &str, data: &[u8]) -> Result<Vec<u8>> {
            let keys = self.keys.lock().unwrap();
            let stored = keys.get(key_id).ok_or_else(|| {
                crate::error::PdtfError::InvalidKey(format!("Key not found: {key_id}"))
            })?;
            let sig = stored.signing_key.sign(data);
            Ok(sig.to_bytes().to_vec())
        }

        async fn get_public_key(&self, key_id: &str) -> Result<Vec<u8>> {
            let keys = self.keys.lock().unwrap();
            let stored = keys.get(key_id).ok_or_else(|| {
                crate::error::PdtfError::InvalidKey(format!("Key not found: {key_id}"))
            })?;
            Ok(stored.record.public_key.clone())
        }

        async fn resolve_did_key(&self, key_id: &str) -> Result<String> {
            let keys = self.keys.lock().unwrap();
            let stored = keys.get(key_id).ok_or_else(|| {
                crate::error::PdtfError::InvalidKey(format!("Key not found: {key_id}"))
            })?;
            Ok(stored.record.did.clone())
        }
    }

    fn chrono_now() -> String {
        // Simple ISO 8601 timestamp without chrono dependency
        use std::time::{SystemTime, UNIX_EPOCH};
        let dur = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default();
        let secs = dur.as_secs();
        // Rough ISO format — good enough for testing
        format!("1970-01-01T00:00:00Z")
            .replace("1970-01-01T00:00:00Z", &format_timestamp(secs))
    }

    fn format_timestamp(epoch_secs: u64) -> String {
        // Calculate date/time from epoch seconds
        let days = epoch_secs / 86400;
        let time_secs = epoch_secs % 86400;
        let hours = time_secs / 3600;
        let minutes = (time_secs % 3600) / 60;
        let seconds = time_secs % 60;

        // Simple date calculation (not accounting for leap seconds, but close enough)
        let (year, month, day) = days_to_ymd(days);

        format!(
            "{:04}-{:02}-{:02}T{:02}:{:02}:{:02}Z",
            year, month, day, hours, minutes, seconds
        )
    }

    fn days_to_ymd(mut days: u64) -> (u64, u64, u64) {
        // Approximate — good enough for ISO timestamps
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
        (y % 4 == 0 && y % 100 != 0) || y % 400 == 0
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
