//! Universal DID resolver with LRU cache.
//!
//! Supports did:key (local) and did:web (network).
//! Cache TTLs:
//! - did:key: infinite (deterministic)
//! - did:web: configurable (default 1 hour)

use crate::error::{PdtfError, Result};
use crate::types::DidDocument;
use lru::LruCache;
use std::num::NonZeroUsize;
use std::sync::Mutex;
use std::time::Instant;

/// Options for the DID resolver.
pub struct DidResolverOptions {
    /// Cache TTL for did:web in milliseconds. Default: 3,600,000 (1 hour).
    pub default_ttl_ms: u64,
    /// Maximum cache entries. Default: 1000.
    pub max_cache_size: usize,
}

impl Default for DidResolverOptions {
    fn default() -> Self {
        Self {
            default_ttl_ms: 3_600_000,
            max_cache_size: 1000,
        }
    }
}

struct CacheEntry {
    doc: DidDocument,
    expires_at: Option<Instant>, // None = never expires (did:key)
}

/// Universal DID resolver with LRU caching.
pub struct DidResolver {
    cache: Mutex<LruCache<String, CacheEntry>>,
    default_ttl_ms: u64,
}

impl DidResolver {
    /// Create a new DID resolver.
    pub fn new(options: DidResolverOptions) -> Self {
        let cache_size =
            NonZeroUsize::new(options.max_cache_size).unwrap_or(NonZeroUsize::new(1000).unwrap());
        Self {
            cache: Mutex::new(LruCache::new(cache_size)),
            default_ttl_ms: options.default_ttl_ms,
        }
    }

    /// Resolve a DID to its DID document.
    ///
    /// did:key is resolved locally (deterministic, cached forever).
    /// did:web is fetched over HTTPS with TTL-based caching.
    pub async fn resolve(&self, did: &str) -> Result<DidDocument> {
        // Check cache
        {
            let mut cache = self
                .cache
                .lock()
                .map_err(|_| PdtfError::DidResolutionFailed("Cache lock poisoned".into()))?;
            if let Some(entry) = cache.get(did) {
                match entry.expires_at {
                    None => return Ok(entry.doc.clone()), // never expires
                    Some(expires_at) if Instant::now() < expires_at => {
                        return Ok(entry.doc.clone());
                    }
                    _ => {} // expired, fall through
                }
            }
        }

        let (doc, ttl) = if did.starts_with("did:key:") {
            let doc = crate::did::did_key::resolve_did_key(did)?;
            (doc, None) // infinite TTL
        } else if did.starts_with("did:web:") {
            #[cfg(feature = "network")]
            {
                let doc = crate::did::did_web::resolve_did_web(did).await?;
                let ttl = Some(std::time::Duration::from_millis(self.default_ttl_ms));
                (doc, ttl)
            }
            #[cfg(not(feature = "network"))]
            {
                return Err(PdtfError::DidResolutionFailed(
                    "did:web resolution requires the 'network' feature".into(),
                ));
            }
        } else {
            return Err(PdtfError::DidError(format!(
                "Unsupported DID method: {did}"
            )));
        };

        // Store in cache
        {
            let mut cache = self
                .cache
                .lock()
                .map_err(|_| PdtfError::DidResolutionFailed("Cache lock poisoned".into()))?;
            cache.put(
                did.to_string(),
                CacheEntry {
                    doc: doc.clone(),
                    expires_at: ttl.map(|d| Instant::now() + d),
                },
            );
        }

        Ok(doc)
    }

    /// Invalidate a cached DID document.
    pub fn invalidate(&self, did: &str) {
        if let Ok(mut cache) = self.cache.lock() {
            cache.pop(did);
        }
    }

    /// Clear the entire cache.
    pub fn clear_cache(&self) {
        if let Ok(mut cache) = self.cache.lock() {
            cache.clear();
        }
    }

    /// Current cache size.
    pub fn cache_size(&self) -> usize {
        self.cache.lock().map(|c| c.len()).unwrap_or(0)
    }
}

impl Default for DidResolver {
    fn default() -> Self {
        Self::new(DidResolverOptions::default())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::keys::ed25519::{derive_did_key, generate_keypair};

    #[tokio::test]
    async fn test_resolve_did_key_cached() {
        let resolver = DidResolver::default();
        let kp = generate_keypair();
        let did = derive_did_key(kp.verifying_key.as_bytes()).unwrap();

        let doc = resolver.resolve(&did).await.unwrap();
        assert_eq!(doc.id, did);
        assert_eq!(resolver.cache_size(), 1);

        // Second resolution should hit cache
        let doc2 = resolver.resolve(&did).await.unwrap();
        assert_eq!(doc2.id, did);
    }

    #[tokio::test]
    async fn test_resolve_unsupported_method() {
        let resolver = DidResolver::default();
        let result = resolver.resolve("did:example:123").await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_invalidate() {
        let resolver = DidResolver::default();
        let kp = generate_keypair();
        let did = derive_did_key(kp.verifying_key.as_bytes()).unwrap();

        resolver.resolve(&did).await.unwrap();
        assert_eq!(resolver.cache_size(), 1);

        resolver.invalidate(&did);
        assert_eq!(resolver.cache_size(), 0);
    }

    #[tokio::test]
    async fn test_clear_cache() {
        let resolver = DidResolver::default();
        let kp = generate_keypair();
        let did = derive_did_key(kp.verifying_key.as_bytes()).unwrap();

        resolver.resolve(&did).await.unwrap();
        resolver.clear_cache();
        assert_eq!(resolver.cache_size(), 0);
    }
}
