//! C FFI bindings for PDTF 2.0 core library.
//!
//! Exposes C-compatible functions for use via .NET P/Invoke (or any C FFI consumer).
//! All returned strings are heap-allocated and must be freed with `pdtf_free_string()`.
#![allow(clippy::not_unsafe_ptr_arg_deref)] // raw pointer deref is inside catch_unwind + unsafe blocks

use std::cell::RefCell;
use std::ffi::{c_char, CStr, CString};
use std::panic::catch_unwind;

// ---------------------------------------------------------------------------
// Thread-local error storage
// ---------------------------------------------------------------------------

thread_local! {
    static LAST_ERROR: RefCell<Option<String>> = RefCell::new(None);
}

fn set_last_error(msg: String) {
    LAST_ERROR.with(|e| *e.borrow_mut() = Some(msg));
}

fn clear_last_error() {
    LAST_ERROR.with(|e| *e.borrow_mut() = None);
}

/// Allocate a C string on the heap. Returns null on interior NUL bytes.
fn to_c_string(s: &str) -> *mut c_char {
    match CString::new(s) {
        Ok(cs) => cs.into_raw(),
        Err(e) => {
            set_last_error(format!("String contains interior NUL byte: {e}"));
            std::ptr::null_mut()
        }
    }
}

/// Read a `*const c_char` into a `&str`. Returns Err with a message on failure.
unsafe fn read_c_str<'a>(ptr: *const c_char, name: &str) -> Result<&'a str, String> {
    if ptr.is_null() {
        return Err(format!("{name} is null"));
    }
    unsafe { CStr::from_ptr(ptr) }
        .to_str()
        .map_err(|e| format!("{name} is not valid UTF-8: {e}"))
}

// ---------------------------------------------------------------------------
// Public C API
// ---------------------------------------------------------------------------

/// Generate an Ed25519 keypair.
/// Returns JSON: `{"did":"did:key:z6Mk...","publicKeyHex":"...","secretKeyHex":"..."}`
/// The returned string must be freed with `pdtf_free_string()`.
#[no_mangle]
pub extern "C" fn pdtf_generate_keypair() -> *mut c_char {
    clear_last_error();
    match catch_unwind(|| {
        let kp = pdtf_core::keys::ed25519::generate_keypair();
        let did = pdtf_core::keys::ed25519::derive_did_key(kp.verifying_key.as_bytes())
            .map_err(|e| e.to_string())?;
        let json = serde_json::json!({
            "did": did,
            "publicKeyHex": hex::encode(kp.verifying_key.as_bytes()),
            "secretKeyHex": hex::encode(kp.signing_key.as_bytes()),
        });
        Ok::<String, String>(json.to_string())
    }) {
        Ok(Ok(json)) => to_c_string(&json),
        Ok(Err(e)) => {
            set_last_error(e);
            std::ptr::null_mut()
        }
        Err(_) => {
            set_last_error("panic in pdtf_generate_keypair".into());
            std::ptr::null_mut()
        }
    }
}

/// Sign a Verifiable Credential JSON string with a secret key (hex-encoded).
/// Returns the signed VC JSON string. Must be freed with `pdtf_free_string()`.
#[no_mangle]
pub extern "C" fn pdtf_sign_vc(
    vc_json: *const c_char,
    secret_key_hex: *const c_char,
) -> *mut c_char {
    clear_last_error();
    match catch_unwind(std::panic::AssertUnwindSafe(|| {
        let vc_str = unsafe { read_c_str(vc_json, "vc_json") }?;
        let sk_hex = unsafe { read_c_str(secret_key_hex, "secret_key_hex") }?;
        sign_vc_inner(vc_str, sk_hex)
    })) {
        Ok(Ok(json)) => to_c_string(&json),
        Ok(Err(e)) => {
            set_last_error(e);
            std::ptr::null_mut()
        }
        Err(_) => {
            set_last_error("panic in pdtf_sign_vc".into());
            std::ptr::null_mut()
        }
    }
}

fn sign_vc_inner(vc_str: &str, sk_hex: &str) -> Result<String, String> {
    use ed25519_dalek::Signer;
    use sha2::{Digest, Sha256};

    let secret_bytes = hex::decode(sk_hex).map_err(|e| format!("Invalid secret key hex: {e}"))?;
    if secret_bytes.len() != 32 {
        return Err("Secret key must be 32 bytes".into());
    }

    let signing_key =
        ed25519_dalek::SigningKey::from_bytes(secret_bytes.as_slice().try_into().unwrap());
    let verifying_key = signing_key.verifying_key();
    let did = pdtf_core::keys::ed25519::derive_did_key(verifying_key.as_bytes())
        .map_err(|e| e.to_string())?;

    let mut vc: pdtf_core::types::VerifiableCredential =
        serde_json::from_str(vc_str).map_err(|e| format!("Invalid VC JSON: {e}"))?;

    // Validate issuer matches signing key
    if vc.issuer.id() != did {
        return Err(format!(
            "Issuer DID '{}' does not match signing key DID '{}'",
            vc.issuer.id(),
            did
        ));
    }

    let multibase = &did["did:key:".len()..];
    let verification_method = format!("{did}#{multibase}");
    let timestamp = vc.valid_from.clone();

    // JCS-canonicalize proof options using json_canon
    let proof_opts = serde_json::json!({
        "type": "DataIntegrityProof",
        "cryptosuite": "eddsa-jcs-2022",
        "verificationMethod": verification_method,
        "proofPurpose": "assertionMethod",
        "created": timestamp,
    });

    let canonical_proof_opts =
        json_canon::to_string(&proof_opts).map_err(|e| format!("JCS error: {e}"))?;
    let proof_options_hash = Sha256::digest(canonical_proof_opts.as_bytes());

    let mut doc_value = serde_json::to_value(&vc).map_err(|e| e.to_string())?;
    if let Some(obj) = doc_value.as_object_mut() {
        obj.remove("proof");
    }
    let canonical_doc = json_canon::to_string(&doc_value).map_err(|e| format!("JCS error: {e}"))?;
    let document_hash = Sha256::digest(canonical_doc.as_bytes());

    let mut combined = Vec::with_capacity(64);
    combined.extend_from_slice(&proof_options_hash);
    combined.extend_from_slice(&document_hash);

    let signature = signing_key.sign(&combined);
    let proof_value = format!("z{}", bs58::encode(signature.to_bytes()).into_string());

    vc.proof = Some(pdtf_core::types::DataIntegrityProof {
        proof_type: "DataIntegrityProof".into(),
        cryptosuite: "eddsa-jcs-2022".into(),
        verification_method,
        proof_purpose: "assertionMethod".into(),
        created: timestamp,
        proof_value,
    });

    serde_json::to_string_pretty(&vc).map_err(|e| e.to_string())
}

/// Verify a DataIntegrityProof on a VC.
/// Returns 1 for valid, 0 for invalid, -1 for error.
#[no_mangle]
pub extern "C" fn pdtf_verify_proof(vc_json: *const c_char, public_key_hex: *const c_char) -> i32 {
    clear_last_error();
    match catch_unwind(std::panic::AssertUnwindSafe(|| {
        let vc_str = unsafe { read_c_str(vc_json, "vc_json") }?;
        let pk_hex = unsafe { read_c_str(public_key_hex, "public_key_hex") }?;

        let pk_bytes = hex::decode(pk_hex).map_err(|e| format!("Invalid public key hex: {e}"))?;
        if pk_bytes.len() != 32 {
            return Err("Public key must be 32 bytes".into());
        }

        let vc: pdtf_core::types::VerifiableCredential =
            serde_json::from_str(vc_str).map_err(|e| format!("Invalid VC JSON: {e}"))?;

        let mut pk_arr = [0u8; 32];
        pk_arr.copy_from_slice(&pk_bytes);
        let valid = pdtf_core::signer::proof::verify_proof(&vc, &pk_arr);
        Ok::<i32, String>(if valid { 1 } else { 0 })
    })) {
        Ok(Ok(v)) => v,
        Ok(Err(e)) => {
            set_last_error(e);
            -1
        }
        Err(_) => {
            set_last_error("panic in pdtf_verify_proof".into());
            -1
        }
    }
}

/// Resolve a did:key to its DID document JSON.
/// The returned string must be freed with `pdtf_free_string()`.
#[no_mangle]
pub extern "C" fn pdtf_resolve_did_key(did: *const c_char) -> *mut c_char {
    clear_last_error();
    match catch_unwind(std::panic::AssertUnwindSafe(|| {
        let did_str = unsafe { read_c_str(did, "did") }?;
        let doc = pdtf_core::did::did_key::resolve_did_key(did_str).map_err(|e| e.to_string())?;
        serde_json::to_string_pretty(&doc).map_err(|e| e.to_string())
    })) {
        Ok(Ok(json)) => to_c_string(&json),
        Ok(Err(e)) => {
            set_last_error(e);
            std::ptr::null_mut()
        }
        Err(_) => {
            set_last_error("panic in pdtf_resolve_did_key".into());
            std::ptr::null_mut()
        }
    }
}

/// Check federation registry trust authorisation.
/// `registry_json` — serialized FederationRegistry JSON.
/// `issuer_did` — the DID of the issuer to check.
/// `paths_json` — JSON array of path strings.
/// Returns TrustVerificationResult JSON. Must be freed with `pdtf_free_string()`.
#[no_mangle]
pub extern "C" fn pdtf_check_trust(
    registry_json: *const c_char,
    issuer_did: *const c_char,
    paths_json: *const c_char,
) -> *mut c_char {
    clear_last_error();
    match catch_unwind(std::panic::AssertUnwindSafe(|| {
        let reg_str = unsafe { read_c_str(registry_json, "registry_json") }?;
        let issuer_str = unsafe { read_c_str(issuer_did, "issuer_did") }?;
        let paths_str = unsafe { read_c_str(paths_json, "paths_json") }?;

        let registry: pdtf_core::types::FederationRegistry =
            serde_json::from_str(reg_str).map_err(|e| format!("Invalid registry JSON: {e}"))?;
        let paths: Vec<String> =
            serde_json::from_str(paths_str).map_err(|e| format!("Invalid paths JSON: {e}"))?;

        let resolver = pdtf_core::federation::FederationRegistryResolver::with_registry(registry);
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .map_err(|e| format!("Runtime error: {e}"))?;
        let resolution = rt.block_on(pdtf_core::federation::TrustResolver::resolve_trust(
            &resolver, issuer_str, None,
        ));
        let result =
            pdtf_core::federation::verify::verify_trust_coverage(&resolution, &paths);
        serde_json::to_string_pretty(&result).map_err(|e| e.to_string())
    })) {
        Ok(Ok(json)) => to_c_string(&json),
        Ok(Err(e)) => {
            set_last_error(e);
            std::ptr::null_mut()
        }
        Err(_) => {
            set_last_error("panic in pdtf_check_trust".into());
            std::ptr::null_mut()
        }
    }
}

/// Create an empty status list bitstring of `size` bits, encoded as base64 gzip.
/// The returned string must be freed with `pdtf_free_string()`.
#[no_mangle]
pub extern "C" fn pdtf_create_status_list(size: u32) -> *mut c_char {
    clear_last_error();
    match catch_unwind(|| {
        let list = pdtf_core::status::bitstring::create_status_list(size as usize)
            .map_err(|e| e.to_string())?;
        pdtf_core::status::bitstring::encode_status_list(&list).map_err(|e| e.to_string())
    }) {
        Ok(Ok(s)) => to_c_string(&s),
        Ok(Err(e)) => {
            set_last_error(e);
            std::ptr::null_mut()
        }
        Err(_) => {
            set_last_error("panic in pdtf_create_status_list".into());
            std::ptr::null_mut()
        }
    }
}

/// Check if a bit is set in a status list bitstring.
/// Returns 1 for revoked/set, 0 for not set, -1 for error.
#[no_mangle]
pub extern "C" fn pdtf_check_status(bitstring_b64: *const c_char, index: u32) -> i32 {
    clear_last_error();
    match catch_unwind(std::panic::AssertUnwindSafe(|| {
        let bs_str = unsafe { read_c_str(bitstring_b64, "bitstring_b64") }?;
        let decoded =
            pdtf_core::status::bitstring::decode_status_list(bs_str).map_err(|e| e.to_string())?;
        let set = pdtf_core::status::bitstring::get_bit(&decoded, index as usize)
            .map_err(|e| e.to_string())?;
        Ok::<i32, String>(if set { 1 } else { 0 })
    })) {
        Ok(Ok(v)) => v,
        Ok(Err(e)) => {
            set_last_error(e);
            -1
        }
        Err(_) => {
            set_last_error("panic in pdtf_check_status".into());
            -1
        }
    }
}

/// Free a string allocated by any pdtf_* function.
/// Passing null is a no-op.
#[no_mangle]
pub extern "C" fn pdtf_free_string(ptr: *mut c_char) {
    if !ptr.is_null() {
        unsafe {
            drop(CString::from_raw(ptr));
        }
    }
}

/// Returns the last error message (thread-local), or null if no error.
/// The returned string must be freed with `pdtf_free_string()`.
#[no_mangle]
pub extern "C" fn pdtf_last_error() -> *mut c_char {
    LAST_ERROR.with(|e| match e.borrow().as_ref() {
        Some(msg) => to_c_string(msg),
        None => std::ptr::null_mut(),
    })
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_generate_keypair() {
        let ptr = pdtf_generate_keypair();
        assert!(!ptr.is_null());
        let json = unsafe { CStr::from_ptr(ptr) }.to_str().unwrap();
        let v: serde_json::Value = serde_json::from_str(json).unwrap();
        assert!(v["did"].as_str().unwrap().starts_with("did:key:z6Mk"));
        assert!(!v["publicKeyHex"].as_str().unwrap().is_empty());
        assert!(!v["secretKeyHex"].as_str().unwrap().is_empty());
        pdtf_free_string(ptr);
    }

    #[test]
    fn test_sign_and_verify_roundtrip() {
        let kp_ptr = pdtf_generate_keypair();
        let kp_json = unsafe { CStr::from_ptr(kp_ptr) }.to_str().unwrap();
        let kp: serde_json::Value = serde_json::from_str(kp_json).unwrap();
        let sk = kp["secretKeyHex"].as_str().unwrap();
        let pk = kp["publicKeyHex"].as_str().unwrap();
        let did = kp["did"].as_str().unwrap();
        pdtf_free_string(kp_ptr);

        let vc_json = format!(
            r#"{{
            "@context": ["https://www.w3.org/ns/credentials/v2"],
            "type": ["VerifiableCredential"],
            "issuer": "{did}",
            "validFrom": "2026-01-01T00:00:00Z",
            "credentialSubject": {{"id": "did:example:subject", "name": "Test"}}
        }}"#
        );

        let vc_cstr = CString::new(vc_json).unwrap();
        let sk_cstr = CString::new(sk).unwrap();
        let signed_ptr = pdtf_sign_vc(vc_cstr.as_ptr(), sk_cstr.as_ptr());
        assert!(!signed_ptr.is_null(), "sign_vc returned null");

        let signed_json = unsafe { CStr::from_ptr(signed_ptr) }.to_str().unwrap();
        let pk_cstr = CString::new(pk).unwrap();
        let signed_cstr = CString::new(signed_json).unwrap();
        let result = pdtf_verify_proof(signed_cstr.as_ptr(), pk_cstr.as_ptr());
        assert_eq!(result, 1, "verification should succeed");
        pdtf_free_string(signed_ptr);
    }

    #[test]
    fn test_verify_wrong_key() {
        let kp_ptr = pdtf_generate_keypair();
        let kp_json = unsafe { CStr::from_ptr(kp_ptr) }.to_str().unwrap();
        let kp: serde_json::Value = serde_json::from_str(kp_json).unwrap();
        let sk = kp["secretKeyHex"].as_str().unwrap();
        let did = kp["did"].as_str().unwrap();
        pdtf_free_string(kp_ptr);

        let vc_json = format!(
            r#"{{
            "@context": ["https://www.w3.org/ns/credentials/v2"],
            "type": ["VerifiableCredential"],
            "issuer": "{did}",
            "validFrom": "2026-01-01T00:00:00Z",
            "credentialSubject": {{"id": "did:example:subject"}}
        }}"#
        );

        let vc_cstr = CString::new(vc_json).unwrap();
        let sk_cstr = CString::new(sk).unwrap();
        let signed_ptr = pdtf_sign_vc(vc_cstr.as_ptr(), sk_cstr.as_ptr());
        assert!(!signed_ptr.is_null());

        // Generate a different keypair
        let kp2_ptr = pdtf_generate_keypair();
        let kp2_json = unsafe { CStr::from_ptr(kp2_ptr) }.to_str().unwrap();
        let kp2: serde_json::Value = serde_json::from_str(kp2_json).unwrap();
        let wrong_pk = kp2["publicKeyHex"].as_str().unwrap();
        pdtf_free_string(kp2_ptr);

        let signed_json = unsafe { CStr::from_ptr(signed_ptr) }.to_str().unwrap();
        let signed_cstr = CString::new(signed_json).unwrap();
        let wrong_pk_cstr = CString::new(wrong_pk).unwrap();
        let result = pdtf_verify_proof(signed_cstr.as_ptr(), wrong_pk_cstr.as_ptr());
        assert_eq!(result, 0, "verification with wrong key should fail");
        pdtf_free_string(signed_ptr);
    }

    #[test]
    fn test_sign_issuer_mismatch() {
        let kp_ptr = pdtf_generate_keypair();
        let kp_json = unsafe { CStr::from_ptr(kp_ptr) }.to_str().unwrap();
        let kp: serde_json::Value = serde_json::from_str(kp_json).unwrap();
        let sk = kp["secretKeyHex"].as_str().unwrap();
        pdtf_free_string(kp_ptr);

        // Use a different DID as issuer
        let vc_json = r#"{
            "@context": ["https://www.w3.org/ns/credentials/v2"],
            "type": ["VerifiableCredential"],
            "issuer": "did:key:z6MkWrongIssuer",
            "validFrom": "2026-01-01T00:00:00Z",
            "credentialSubject": {"id": "did:example:subject"}
        }"#;

        let vc_cstr = CString::new(vc_json).unwrap();
        let sk_cstr = CString::new(sk).unwrap();
        let signed_ptr = pdtf_sign_vc(vc_cstr.as_ptr(), sk_cstr.as_ptr());
        assert!(
            signed_ptr.is_null(),
            "sign_vc should fail on issuer mismatch"
        );

        let err_ptr = pdtf_last_error();
        assert!(!err_ptr.is_null());
        let err = unsafe { CStr::from_ptr(err_ptr) }.to_str().unwrap();
        assert!(err.contains("does not match"), "Error: {err}");
        pdtf_free_string(err_ptr);
    }

    #[test]
    fn test_resolve_did_key() {
        let kp_ptr = pdtf_generate_keypair();
        let kp_json = unsafe { CStr::from_ptr(kp_ptr) }.to_str().unwrap();
        let kp: serde_json::Value = serde_json::from_str(kp_json).unwrap();
        let did = kp["did"].as_str().unwrap();
        pdtf_free_string(kp_ptr);

        let did_cstr = CString::new(did).unwrap();
        let doc_ptr = pdtf_resolve_did_key(did_cstr.as_ptr());
        assert!(!doc_ptr.is_null());
        let doc_json = unsafe { CStr::from_ptr(doc_ptr) }.to_str().unwrap();
        let doc: serde_json::Value = serde_json::from_str(doc_json).unwrap();
        assert_eq!(doc["id"].as_str().unwrap(), did);
        pdtf_free_string(doc_ptr);
    }

    #[test]
    fn test_trust_check() {
        let registry_json = r#"{
            "version": "1.0",
            "lastUpdated": "2026-01-01T00:00:00Z",
            "issuers": {
                "test-issuer": {
                    "slug": "test-issuer",
                    "did": "did:key:z6MkTest",
                    "name": "Test Issuer",
                    "trustLevel": "rootIssuer",
                    "status": "active",
                    "authorisedPaths": ["Property:*", "Title:*"]
                }
            },
            "userAccountProviders": {}
        }"#;

        let reg_cstr = CString::new(registry_json).unwrap();
        let issuer_cstr = CString::new("did:key:z6MkTest").unwrap();
        let paths_cstr = CString::new(r#"["Property:/address"]"#).unwrap();

        let result_ptr =
            pdtf_check_trust(reg_cstr.as_ptr(), issuer_cstr.as_ptr(), paths_cstr.as_ptr());
        assert!(!result_ptr.is_null());
        let result_json = unsafe { CStr::from_ptr(result_ptr) }.to_str().unwrap();
        let result: serde_json::Value = serde_json::from_str(result_json).unwrap();
        assert_eq!(result["trusted"], true);
        pdtf_free_string(result_ptr);

        // Unknown issuer
        let unknown_cstr = CString::new("did:key:z6MkUnknown").unwrap();
        let result2_ptr = pdtf_check_trust(
            reg_cstr.as_ptr(),
            unknown_cstr.as_ptr(),
            paths_cstr.as_ptr(),
        );
        assert!(!result2_ptr.is_null());
        let result2_json = unsafe { CStr::from_ptr(result2_ptr) }.to_str().unwrap();
        let result2: serde_json::Value = serde_json::from_str(result2_json).unwrap();
        assert_eq!(result2["trusted"], false);
        pdtf_free_string(result2_ptr);
    }

    #[test]
    fn test_status_list() {
        let list_ptr = pdtf_create_status_list(131072);
        assert!(!list_ptr.is_null());
        let list_str = unsafe { CStr::from_ptr(list_ptr) }.to_str().unwrap();

        let list_cstr = CString::new(list_str).unwrap();
        let status = pdtf_check_status(list_cstr.as_ptr(), 0);
        assert_eq!(status, 0, "newly created list should have all bits unset");
        pdtf_free_string(list_ptr);
    }

    #[test]
    fn test_null_input_handling() {
        let result = pdtf_verify_proof(std::ptr::null(), std::ptr::null());
        assert_eq!(result, -1);
        let err_ptr = pdtf_last_error();
        assert!(!err_ptr.is_null());
        pdtf_free_string(err_ptr);
    }
}
