//! Python bindings for PDTF 2.0 core library.

use pyo3::prelude::*;
use pyo3::types::PyDict;

/// Generate an Ed25519 keypair.
/// Returns dict with {did, public_key_hex, secret_key_hex}.
#[pyfunction]
fn generate_keypair() -> PyResult<PyObject> {
    let kp = ::pdtf_core::keys::ed25519::generate_keypair();
    let did = ::pdtf_core::keys::ed25519::derive_did_key(kp.verifying_key.as_bytes())
        .map_err(|e| pyo3::exceptions::PyValueError::new_err(e.to_string()))?;

    Python::with_gil(|py| {
        let dict = PyDict::new_bound(py);
        dict.set_item("did", &did)?;
        dict.set_item("public_key_hex", hex::encode(kp.verifying_key.as_bytes()))?;
        dict.set_item("secret_key_hex", hex::encode(kp.signing_key.as_bytes()))?;
        Ok(dict.into())
    })
}

/// Sign a VC JSON string with a secret key (hex-encoded).
#[pyfunction]
fn sign_vc(vc_json: &str, secret_key_hex: &str) -> PyResult<String> {
    use ed25519_dalek::Signer;
    use sha2::{Digest, Sha256};

    let secret_bytes = hex::decode(secret_key_hex)
        .map_err(|e| pyo3::exceptions::PyValueError::new_err(format!("Invalid hex: {e}")))?;

    if secret_bytes.len() != 32 {
        return Err(pyo3::exceptions::PyValueError::new_err(
            "Secret key must be 32 bytes",
        ));
    }

    let signing_key =
        ed25519_dalek::SigningKey::from_bytes(secret_bytes.as_slice().try_into().unwrap());
    let verifying_key = signing_key.verifying_key();
    let did = ::pdtf_core::keys::ed25519::derive_did_key(verifying_key.as_bytes())
        .map_err(|e| pyo3::exceptions::PyValueError::new_err(e.to_string()))?;

    let mut vc: ::pdtf_core::types::VerifiableCredential = serde_json::from_str(vc_json)
        .map_err(|e| pyo3::exceptions::PyValueError::new_err(format!("Invalid VC JSON: {e}")))?;

    // FIX 6: Validate issuer matches signing key
    if vc.issuer.id() != did {
        return Err(pyo3::exceptions::PyValueError::new_err(format!(
            "Issuer DID '{}' does not match signing key DID '{}'",
            vc.issuer.id(),
            did
        )));
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

    let canonical_proof_opts = json_canon::to_string(&proof_opts)
        .map_err(|e| pyo3::exceptions::PyRuntimeError::new_err(format!("JCS error: {e}")))?;
    let proof_options_hash = Sha256::digest(canonical_proof_opts.as_bytes());

    let mut doc_value = serde_json::to_value(&vc)
        .map_err(|e| pyo3::exceptions::PyRuntimeError::new_err(e.to_string()))?;
    if let Some(obj) = doc_value.as_object_mut() {
        obj.remove("proof");
    }
    let canonical_doc = json_canon::to_string(&doc_value)
        .map_err(|e| pyo3::exceptions::PyRuntimeError::new_err(format!("JCS error: {e}")))?;
    let document_hash = Sha256::digest(canonical_doc.as_bytes());

    let mut combined = Vec::with_capacity(64);
    combined.extend_from_slice(&proof_options_hash);
    combined.extend_from_slice(&document_hash);

    let signature = signing_key.sign(&combined);
    let proof_value = format!("z{}", bs58::encode(signature.to_bytes()).into_string());

    vc.proof = Some(::pdtf_core::types::DataIntegrityProof {
        proof_type: "DataIntegrityProof".into(),
        cryptosuite: "eddsa-jcs-2022".into(),
        verification_method,
        proof_purpose: "assertionMethod".into(),
        created: timestamp,
        proof_value,
    });

    serde_json::to_string_pretty(&vc)
        .map_err(|e| pyo3::exceptions::PyRuntimeError::new_err(e.to_string()))
}

/// Verify a DataIntegrityProof on a VC.
#[pyfunction]
fn verify_proof(vc_json: &str, public_key_hex: &str) -> PyResult<bool> {
    let pk_bytes = hex::decode(public_key_hex)
        .map_err(|e| pyo3::exceptions::PyValueError::new_err(format!("Invalid hex: {e}")))?;
    if pk_bytes.len() != 32 {
        return Err(pyo3::exceptions::PyValueError::new_err(
            "Public key must be 32 bytes",
        ));
    }
    let vc: ::pdtf_core::types::VerifiableCredential = serde_json::from_str(vc_json)
        .map_err(|e| pyo3::exceptions::PyValueError::new_err(format!("Invalid VC JSON: {e}")))?;
    let mut pk_arr = [0u8; 32];
    pk_arr.copy_from_slice(&pk_bytes);
    Ok(::pdtf_core::signer::proof::verify_proof(&vc, &pk_arr))
}

/// Resolve a did:key to its DID document JSON.
#[pyfunction]
fn resolve_did_key(did: &str) -> PyResult<String> {
    let doc = ::pdtf_core::did::did_key::resolve_did_key(did)
        .map_err(|e| pyo3::exceptions::PyValueError::new_err(e.to_string()))?;
    serde_json::to_string_pretty(&doc)
        .map_err(|e| pyo3::exceptions::PyRuntimeError::new_err(e.to_string()))
}

/// Check TIR authorisation. Returns result JSON.
#[pyfunction]
fn check_tir(registry_json: &str, issuer_did: &str, paths: Vec<String>) -> PyResult<String> {
    let registry: ::pdtf_core::types::TirRegistry =
        serde_json::from_str(registry_json).map_err(|e| {
            pyo3::exceptions::PyValueError::new_err(format!("Invalid registry JSON: {e}"))
        })?;
    let result = ::pdtf_core::federation::verify::verify_tir(&registry, issuer_did, &paths);
    serde_json::to_string_pretty(&result)
        .map_err(|e| pyo3::exceptions::PyRuntimeError::new_err(e.to_string()))
}

/// Create an empty status list bitstring, encoded as base64 gzip.
#[pyfunction]
fn create_status_list(size: usize) -> PyResult<String> {
    let list = ::pdtf_core::status::bitstring::create_status_list(size)
        .map_err(|e| pyo3::exceptions::PyValueError::new_err(e.to_string()))?;
    ::pdtf_core::status::bitstring::encode_status_list(&list)
        .map_err(|e| pyo3::exceptions::PyRuntimeError::new_err(e.to_string()))
}

/// Check if a bit is set in a status list bitstring.
#[pyfunction]
fn check_status(bitstring_b64: &str, index: usize) -> PyResult<bool> {
    let decoded = ::pdtf_core::status::bitstring::decode_status_list(bitstring_b64)
        .map_err(|e| pyo3::exceptions::PyValueError::new_err(e.to_string()))?;
    ::pdtf_core::status::bitstring::get_bit(&decoded, index)
        .map_err(|e| pyo3::exceptions::PyValueError::new_err(e.to_string()))
}

/// PDTF 2.0 core library Python bindings.
#[pymodule]
fn pdtf_core(m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_function(wrap_pyfunction!(generate_keypair, m)?)?;
    m.add_function(wrap_pyfunction!(sign_vc, m)?)?;
    m.add_function(wrap_pyfunction!(verify_proof, m)?)?;
    m.add_function(wrap_pyfunction!(resolve_did_key, m)?)?;
    m.add_function(wrap_pyfunction!(check_tir, m)?)?;
    m.add_function(wrap_pyfunction!(create_status_list, m)?)?;
    m.add_function(wrap_pyfunction!(check_status, m)?)?;
    Ok(())
}
