# pdtf-core (Python)

Python bindings for the PDTF 2.0 core library — Ed25519 signing, DID resolution, credential verification, and trust registry.

Built on the Rust `pdtf-core` crate via [PyO3](https://pyo3.rs/) and [maturin](https://github.com/PyO3/maturin).

## Installation

### From source

```bash
cd bindings/python
pip install maturin
maturin develop
```

This compiles the Rust library and installs `pdtf_core` into your active Python environment.

### Requirements

- Python 3.8+
- Rust toolchain (rustup)
- maturin (`pip install maturin`)

## API Reference

### `generate_keypair() → dict`

Generate a new Ed25519 keypair with a derived `did:key` identifier.

```python
import pdtf_core

kp = pdtf_core.generate_keypair()
# {
#   "did": "did:key:z6Mkh...",
#   "publicKeyHex": "ab12cd...",
#   "secretKeyHex": "ef34ab..."
# }
```

**Returns:** A dict with keys `did`, `publicKeyHex`, and `secretKeyHex`.

---

### `sign_vc(vc_json: str, secret_key_hex: str) → str`

Sign a Verifiable Credential with an Ed25519 secret key. Adds a `DataIntegrityProof` using the `eddsa-jcs-2022` cryptosuite.

```python
import json
import pdtf_core

vc = {
    "@context": [
        "https://www.w3.org/ns/credentials/v2",
        "https://www.w3.org/ns/credentials/examples/v2"
    ],
    "type": ["VerifiableCredential", "PropertyDataCredential"],
    "issuer": kp["did"],
    "validFrom": "2025-01-15T09:00:00Z",
    "credentialSubject": {
        "id": "urn:pdtf:uprn:100023336956",
        "energyRating": "B"
    }
}

signed_json = pdtf_core.sign_vc(json.dumps(vc), kp["secretKeyHex"])
signed_vc = json.loads(signed_json)
print(signed_vc["proof"]["cryptosuite"])  # "eddsa-jcs-2022"
```

**Parameters:**
- `vc_json` — JSON string of the unsigned VC
- `secret_key_hex` — hex-encoded Ed25519 secret key (from `generate_keypair()`)

**Returns:** JSON string of the signed VC (with `proof` attached).

---

### `verify_proof(vc_json: str, public_key_hex: str) → bool`

Verify the `DataIntegrityProof` on a signed Verifiable Credential.

```python
import pdtf_core

is_valid = pdtf_core.verify_proof(signed_json, kp["publicKeyHex"])
print(is_valid)  # True
```

**Parameters:**
- `vc_json` — JSON string of the signed VC (must contain a `proof` field)
- `public_key_hex` — hex-encoded Ed25519 public key

**Returns:** `True` if the proof is valid, `False` otherwise.

---

### `resolve_did_key(did: str) → str`

Resolve a `did:key` identifier to its DID Document.

```python
import json
import pdtf_core

doc_json = pdtf_core.resolve_did_key("did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK")
doc = json.loads(doc_json)
print(doc["verificationMethod"][0]["type"])  # "Ed25519VerificationKey2020"
```

**Parameters:**
- `did` — a `did:key` identifier string

**Returns:** JSON string of the resolved DID Document.

---

### `check_trust(registry_json: str, issuer_did: str, paths: list[str]) → str`

Check whether an issuer is authorised for the given credential paths in a Federation Trust Registry.

```python
import json
import pdtf_core

registry = {
    "version": "1.0",
    "lastUpdated": "2025-06-01T00:00:00Z",
    "issuers": {
        "epc-adapter": {
            "did": "did:key:z6Mkh...",
            "name": "EPC Adapter",
            "slug": "epc-adapter",
            "trustLevel": "trustedProxy",
            "status": "active",
            "authorisedPaths": ["Property:/energyEfficiency/*"]
        }
    },
    "userAccountProviders": {}
}

result_json = pdtf_core.check_trust(
    json.dumps(registry),
    "did:key:z6Mkh...",
    ["Property:/energyEfficiency/rating"]
)
result = json.loads(result_json)
print(result["trusted"])        # True
print(result["paths_covered"])  # ["Property:/energyEfficiency/rating"]
```

**Parameters:**
- `registry_json` — JSON string of the federation registry
- `issuer_did` — the issuer's DID to check
- `paths` — list of credential paths to verify authorisation for

**Returns:** JSON string with fields: `trusted`, `issuer_slug`, `trust_level`, `status`, `paths_covered`, `uncovered_paths`, `warnings`.

---

### `create_status_list(size: int) → str`

Create an empty Bitstring Status List. Used for credential revocation/suspension per W3C Bitstring Status List v1.0.

```python
import pdtf_core

bitstring = pdtf_core.create_status_list(131072)
print(type(bitstring))  # <class 'str'> — base64-encoded gzip-compressed bitstring
```

**Parameters:**
- `size` — size in bits (minimum 131072, must be a multiple of 8)

**Returns:** Base64-encoded gzip-compressed bitstring.

---

### `check_status(bitstring_b64: str, index: int) → bool`

Check whether a specific credential index is revoked in a Bitstring Status List.

```python
import pdtf_core

bitstring = pdtf_core.create_status_list(131072)
is_revoked = pdtf_core.check_status(bitstring, 42)
print(is_revoked)  # False (fresh list — all zeros)
```

**Parameters:**
- `bitstring_b64` — base64-encoded bitstring (from `create_status_list()` or fetched from a status endpoint)
- `index` — the credential's status list index

**Returns:** `True` if the bit is set (revoked), `False` otherwise.

---

## End-to-End Example

Generate a keypair, build a VC, sign it, and verify the signature:

```python
import json
import pdtf_core

# 1. Generate a keypair
kp = pdtf_core.generate_keypair()
print(f"Issuer DID: {kp['did']}")

# 2. Build an unsigned Verifiable Credential
vc = {
    "@context": [
        "https://www.w3.org/ns/credentials/v2",
        "https://www.w3.org/ns/credentials/examples/v2"
    ],
    "type": ["VerifiableCredential", "PropertyDataCredential"],
    "issuer": kp["did"],
    "validFrom": "2025-01-15T09:00:00Z",
    "credentialSubject": {
        "id": "urn:pdtf:uprn:100023336956",
        "titleNumber": "WYK123456",
        "tenure": "freehold"
    }
}

# 3. Sign it
signed_json = pdtf_core.sign_vc(json.dumps(vc), kp["secretKeyHex"])
signed_vc = json.loads(signed_json)

print(f"Proof type: {signed_vc['proof']['type']}")
print(f"Cryptosuite: {signed_vc['proof']['cryptosuite']}")
print(f"Proof value: {signed_vc['proof']['proofValue'][:40]}...")

# 4. Verify the signature
is_valid = pdtf_core.verify_proof(signed_json, kp["publicKeyHex"])
print(f"Signature valid: {is_valid}")  # True

# 5. Resolve the issuer's DID document
doc = json.loads(pdtf_core.resolve_did_key(kp["did"]))
print(f"Verification method: {doc['verificationMethod'][0]['type']}")

# 6. Tamper detection — modify the VC and re-verify
tampered = json.loads(signed_json)
tampered["credentialSubject"]["tenure"] = "leasehold"
is_valid_after_tamper = pdtf_core.verify_proof(json.dumps(tampered), kp["publicKeyHex"])
print(f"Valid after tampering: {is_valid_after_tamper}")  # False
```

## Cryptographic Details

- **Algorithm:** Ed25519 (EdDSA over Curve25519)
- **Canonicalization:** [JCS (RFC 8785)](https://www.rfc-editor.org/rfc/rfc8785) — uses `json_canon` internally for deterministic JSON serialisation before signing
- **Cryptosuite:** `eddsa-jcs-2022` per [W3C Data Integrity EdDSA Cryptosuites](https://www.w3.org/TR/vc-di-eddsa/)
- **DID method:** `did:key` with Ed25519 multicodec prefix (`0xed01`)

All operations are W3C-compliant. VCs signed with this library verify correctly in any other PDTF implementation (TypeScript, Rust, C#/.NET).

## Links

- **Core Rust library:** [property-data-standards-co/core-rs](https://github.com/property-data-standards-co/core-rs)
- **PDTF 2.0 specs:** [property-data-standards-co.github.io/webv2](https://property-data-standards-co.github.io/webv2/)
- **W3C VC Data Model 2.0:** [w3.org/TR/vc-data-model-2.0](https://www.w3.org/TR/vc-data-model-2.0/)

## License

MIT — Ed Molyneux / [Moverly](https://moverly.com)
