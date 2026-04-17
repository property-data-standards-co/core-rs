# core-rs

PDTF 2.0 core library — Rust implementation with Python and C#/.NET bindings.

Cryptographic core for the [Property Data Trust Framework](https://propdata.org.uk) v2.0.

## Features

- **Ed25519 key generation** and `did:key` derivation
- **DataIntegrityProof** creation and verification (`eddsa-jcs-2022` cryptosuite)
- **DID resolution** — `did:key` (local, deterministic) and `did:web` (HTTPS)
- **Bitstring Status List** — W3C credential revocation/suspension
- **Federation Trust Registry** — path-based issuer authorisation with pluggable trust resolution
- **VC builder & validator** — 4-stage verification pipeline
- **Python bindings** via PyO3/maturin
- **C#/.NET bindings** via P/Invoke FFI (targets .NET 8.0)

## Rust Usage

```toml
[dependencies]
pdtf-core = { git = "https://github.com/property-data-standards-co/core-rs" }
```

### Sign a Verifiable Credential

```rust
use pdtf_core::keys::provider::memory::MemoryKeyProvider;
use pdtf_core::keys::provider::KeyProvider;
use pdtf_core::signer::{VcSigner, BuildVcOptions};
use pdtf_core::types::*;
use std::collections::HashMap;

#[tokio::main]
async fn main() {
    let provider = MemoryKeyProvider::new();
    provider.generate_key("my-key", KeyCategory::Adapter).await.unwrap();

    let signer = VcSigner::from_key_id(&provider, "my-key").await.unwrap();

    let vc = signer.sign(BuildVcOptions {
        vc_type: vec!["PropertyDataCredential".to_string()],
        credential_subject: CredentialSubject {
            id: "urn:pdtf:uprn:123456789".to_string(),
            claims: HashMap::new(),
        },
        id: Some("urn:uuid:example".to_string()),
        valid_from: Some("2024-06-01T12:00:00Z".to_string()),
        valid_until: None,
        credential_status: None,
        evidence: None,
        terms_of_use: None,
    }).await.unwrap();

    println!("{}", serde_json::to_string_pretty(&vc).unwrap());
}
```

### Verify a VC

```rust
use pdtf_core::validator::verify::{verify_vc, VerifyVcOptions};
use pdtf_core::did::resolver::DidResolver;

let resolver = DidResolver::default();
let result = verify_vc(VerifyVcOptions {
    vc: &signed_vc,
    resolver: &resolver,
    trust_resolver: None,
    claimed_paths: vec![],
    status_list_bitstring: None,
}).await;

assert!(result.valid);
```

### Status List

```rust
use pdtf_core::status::bitstring::*;

let mut list = create_status_list(MIN_BITSTRING_SIZE).unwrap();
set_bit(&mut list, 42).unwrap();

let encoded = encode_status_list(&list).unwrap();
let decoded = decode_status_list(&encoded).unwrap();
assert!(get_bit(&decoded, 42).unwrap());
```

## Python Usage

### Install

```bash
cd bindings/python
pip install maturin
maturin develop
```

### Example

```python
import pdtf_core

# Generate a keypair
kp = pdtf_core.generate_keypair()
print(f"DID: {kp['did']}")

# Resolve a did:key
doc = pdtf_core.resolve_did_key(kp['did'])
print(doc)

# Create a status list
bitstring = pdtf_core.create_status_list(131072)
is_revoked = pdtf_core.check_status(bitstring, 42)
print(f"Revoked: {is_revoked}")  # False
```

## C#/.NET Usage

C# bindings via P/Invoke to the native FFI library. Targets .NET 8.0.

See [`bindings/dotnet/README.md`](bindings/dotnet/README.md) for full documentation, model classes, and platform setup.

### Quick Example

```csharp
using Pdtf.Core;

// Generate a keypair
var kp = PdtfCore.GenerateKeyPair();
Console.WriteLine($"DID: {kp.Did}");

// Sign a credential
string signedJson = PdtfCore.SignCredential(vcJson, kp.SecretKeyHex);

// Verify the signature
bool valid = PdtfCore.VerifyProof(signedJson, kp.PublicKeyHex);
Console.WriteLine($"Valid: {valid}"); // True
```

### Building

```bash
# Build native library
cargo build --release -p pdtf-core-ffi

# Build .NET project
cd bindings/dotnet && dotnet build
```

## Architecture

```
crates/pdtf-core/
├── src/
│   ├── keys/          # Ed25519 key generation, did:key encoding, KeyProvider trait
│   ├── signer/        # DataIntegrityProof creation/verification, VC builder
│   ├── did/           # DID resolution (did:key, did:web), URN validation
│   ├── status/        # Bitstring Status List (W3C)
│   ├── federation/    # Federation trust resolution (bootstrap registry + OpenID Federation)
│   ├── validator/     # 4-stage VC verification pipeline
│   ├── types.rs       # Core type definitions
│   └── error.rs       # Error types
bindings/python/       # PyO3 Python bindings
```

## Spec Compliance

- [W3C Verifiable Credentials Data Model v2.0](https://www.w3.org/TR/vc-data-model-2.0/)
- [W3C Data Integrity EdDSA Cryptosuites v1.0](https://www.w3.org/TR/vc-di-eddsa/)
- [W3C Bitstring Status List v1.0](https://www.w3.org/TR/vc-bitstring-status-list/)
- [W3C did:key Method](https://w3c-ccg.github.io/did-method-key/)
- [W3C did:web Method](https://w3c-ccg.github.io/did-method-web/)
- [OpenID Federation 1.0](https://openid.net/specs/openid-federation-1_0.html)

## License

MIT — see [LICENSE](LICENSE).

**Author:** Ed Molyneux
