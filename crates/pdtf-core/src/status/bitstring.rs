//! W3C Bitstring Status List v1.0 implementation.
//!
//! Encoding: bitstring → gzip → base64 (no multibase prefix)
//! Minimum size: 16KB (131,072 bits) for herd privacy
//! Indices never reused.
//!
//! Bit reading: `byte_index = index / 8`, `bit_index = index % 8`
//!              `bit = (byte >> (7 - bit_index)) & 1`

use crate::error::{PdtfError, Result};
use base64::engine::general_purpose::STANDARD as BASE64;
use base64::Engine;
use flate2::read::GzDecoder;
use flate2::write::GzEncoder;
use flate2::Compression;
use std::io::{Read, Write};

/// Minimum bitstring size in bits (16KB = 131,072 bits).
pub const MIN_BITSTRING_SIZE: usize = 131_072;

/// Create a new empty status list bitstring.
///
/// # Arguments
/// * `size` - Number of entries (bits). Minimum 131,072 (16KB).
///
/// # Returns
/// Zero-filled byte vector of `size / 8` bytes.
pub fn create_status_list(size: usize) -> Result<Vec<u8>> {
    if size < MIN_BITSTRING_SIZE {
        return Err(PdtfError::StatusListError(format!(
            "Status list must be at least {MIN_BITSTRING_SIZE} bits (16KB). Got {size}."
        )));
    }
    if !size.is_multiple_of(8) {
        return Err(PdtfError::StatusListError(
            "Status list size must be a multiple of 8".into(),
        ));
    }
    Ok(vec![0u8; size / 8])
}

/// Encode a bitstring for inclusion in a status list VC.
/// Compresses with gzip and encodes as base64.
pub fn encode_status_list(bitstring: &[u8]) -> Result<String> {
    let mut encoder = GzEncoder::new(Vec::new(), Compression::default());
    encoder
        .write_all(bitstring)
        .map_err(|e| PdtfError::StatusListError(format!("Gzip compression failed: {e}")))?;
    let compressed = encoder
        .finish()
        .map_err(|e| PdtfError::StatusListError(format!("Gzip finish failed: {e}")))?;
    Ok(BASE64.encode(&compressed))
}

/// Decode an encoded status list back to a raw bitstring.
pub fn decode_status_list(encoded: &str) -> Result<Vec<u8>> {
    let compressed = BASE64
        .decode(encoded)
        .map_err(|e| PdtfError::StatusListError(format!("Base64 decode failed: {e}")))?;
    let mut decoder = GzDecoder::new(compressed.as_slice());
    let mut bitstring = Vec::new();
    decoder
        .read_to_end(&mut bitstring)
        .map_err(|e| PdtfError::StatusListError(format!("Gzip decompression failed: {e}")))?;
    Ok(bitstring)
}

/// Set a bit in the status list (revoke or suspend).
///
/// Mutates the bitstring in place.
pub fn set_bit(bitstring: &mut [u8], index: usize) -> Result<()> {
    let byte_index = index / 8;
    let bit_index = index % 8;

    if byte_index >= bitstring.len() {
        return Err(PdtfError::StatusListError(format!(
            "Index {index} out of range for status list of size {}",
            bitstring.len() * 8
        )));
    }

    bitstring[byte_index] |= 1 << (7 - bit_index);
    Ok(())
}

/// Get the value of a bit in the status list.
///
/// Returns `true` if the bit is set (credential is revoked/suspended).
pub fn get_bit(bitstring: &[u8], index: usize) -> Result<bool> {
    let byte_index = index / 8;
    let bit_index = index % 8;

    if byte_index >= bitstring.len() {
        return Err(PdtfError::StatusListError(format!(
            "Index {index} out of range for status list of size {}",
            bitstring.len() * 8
        )));
    }

    Ok((bitstring[byte_index] >> (7 - bit_index)) & 1 == 1)
}

/// Revoke a credential by setting its bit in the status list.
/// Revocation is permanent — the bit is never unset.
pub fn revoke_credential(bitstring: &mut [u8], index: usize) -> Result<()> {
    set_bit(bitstring, index)
}

/// Check the revocation/suspension status of a credential by fetching
/// and checking its status list.
///
/// # Arguments
/// * `status_list_credential_url` - URL of the status list VC
/// * `status_list_index` - The credential's index in the list
#[cfg(feature = "network")]
pub async fn check_status(
    status_list_credential_url: &str,
    status_list_index: usize,
) -> Result<bool> {
    let client = reqwest::Client::new();
    let response = client
        .get(status_list_credential_url)
        .header("Accept", "application/json")
        .timeout(std::time::Duration::from_secs(10))
        .send()
        .await
        .map_err(|e| PdtfError::HttpError(format!("Failed to fetch status list: {e}")))?;

    if !response.status().is_success() {
        return Err(PdtfError::HttpError(format!(
            "Failed to fetch status list from {}: HTTP {}",
            status_list_credential_url,
            response.status()
        )));
    }

    let body: serde_json::Value = response
        .json()
        .await
        .map_err(|e| PdtfError::HttpError(format!("Invalid status list response: {e}")))?;

    let encoded = body
        .get("credentialSubject")
        .and_then(|cs| cs.get("encodedList"))
        .and_then(|e| e.as_str())
        .ok_or_else(|| {
            PdtfError::StatusListError(
                "Status list VC missing credentialSubject.encodedList".into(),
            )
        })?;

    let bitstring = decode_status_list(encoded)?;
    get_bit(&bitstring, status_list_index)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_create_status_list() {
        let list = create_status_list(MIN_BITSTRING_SIZE).unwrap();
        assert_eq!(list.len(), MIN_BITSTRING_SIZE / 8);
        assert!(list.iter().all(|&b| b == 0));
    }

    #[test]
    fn test_create_status_list_too_small() {
        assert!(create_status_list(1024).is_err());
    }

    #[test]
    fn test_create_status_list_not_multiple_of_8() {
        assert!(create_status_list(MIN_BITSTRING_SIZE + 3).is_err());
    }

    #[test]
    fn test_set_and_get_bit() {
        let mut list = create_status_list(MIN_BITSTRING_SIZE).unwrap();

        assert!(!get_bit(&list, 0).unwrap());
        assert!(!get_bit(&list, 42).unwrap());

        set_bit(&mut list, 0).unwrap();
        set_bit(&mut list, 42).unwrap();

        assert!(get_bit(&list, 0).unwrap());
        assert!(get_bit(&list, 42).unwrap());
        assert!(!get_bit(&list, 1).unwrap());
        assert!(!get_bit(&list, 41).unwrap());
    }

    #[test]
    fn test_bit_operations_within_byte() {
        let mut list = create_status_list(MIN_BITSTRING_SIZE).unwrap();

        // Set bits 0-7 (all bits in first byte)
        for i in 0..8 {
            set_bit(&mut list, i).unwrap();
        }
        assert_eq!(list[0], 0xFF);

        // Check individual bits
        for i in 0..8 {
            assert!(get_bit(&list, i).unwrap());
        }
        assert!(!get_bit(&list, 8).unwrap());
    }

    #[test]
    fn test_encode_decode_roundtrip() {
        let mut list = create_status_list(MIN_BITSTRING_SIZE).unwrap();
        set_bit(&mut list, 100).unwrap();
        set_bit(&mut list, 50000).unwrap();

        let encoded = encode_status_list(&list).unwrap();
        let decoded = decode_status_list(&encoded).unwrap();

        assert_eq!(list, decoded);
        assert!(get_bit(&decoded, 100).unwrap());
        assert!(get_bit(&decoded, 50000).unwrap());
        assert!(!get_bit(&decoded, 101).unwrap());
    }

    #[test]
    fn test_revoke_credential() {
        let mut list = create_status_list(MIN_BITSTRING_SIZE).unwrap();
        revoke_credential(&mut list, 42).unwrap();
        assert!(get_bit(&list, 42).unwrap());
    }

    #[test]
    fn test_out_of_range() {
        let list = create_status_list(MIN_BITSTRING_SIZE).unwrap();
        assert!(get_bit(&list, MIN_BITSTRING_SIZE + 1).is_err());
    }
}
