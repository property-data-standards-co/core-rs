# Pdtf.Core (.NET)

C#/.NET bindings for the PDTF 2.0 core library — Ed25519 signing, DID resolution, credential verification, and trust registry.

Wraps the native Rust `pdtf_core_ffi` library via P/Invoke. Targets .NET 8.0.

## Prerequisites

- .NET 8.0 SDK
- Rust toolchain (for building the native library from source)
- Native `libpdtf_core_ffi` library (see [Building from Source](#building-from-source))

## Building from Source

### 1. Build the native FFI library

```bash
# From the core-rs repo root
cargo build --release -p pdtf-core-ffi

# The native library will be at:
#   Linux:   target/release/libpdtf_core_ffi.so
#   macOS:   target/release/libpdtf_core_ffi.dylib
#   Windows: target/release/pdtf_core_ffi.dll
```

### 2. Build the .NET project

```bash
cd bindings/dotnet
dotnet build
```

### 3. Make the native library available

Copy the native library to your output directory, or set `LD_LIBRARY_PATH` (Linux), `DYLD_LIBRARY_PATH` (macOS), or `PATH` (Windows):

```bash
# Linux
export LD_LIBRARY_PATH=/path/to/core-rs/target/release:$LD_LIBRARY_PATH

# macOS
export DYLD_LIBRARY_PATH=/path/to/core-rs/target/release:$DYLD_LIBRARY_PATH
```

## API Reference

All methods are on the static class `PdtfCore` in namespace `Pdtf.Core`.

### `PdtfCore.GenerateKeyPair() → KeyPair`

Generate a new Ed25519 keypair with a derived `did:key` identifier.

```csharp
using Pdtf.Core;

var kp = PdtfCore.GenerateKeyPair();
Console.WriteLine($"DID: {kp.Did}");
Console.WriteLine($"Public key: {kp.PublicKeyHex}");
```

**Returns:** `KeyPair` with properties `Did`, `PublicKeyHex`, `SecretKeyHex`.

---

### `PdtfCore.SignCredential(string vcJson, string secretKeyHex) → string`

Sign a Verifiable Credential with an Ed25519 secret key. Adds a `DataIntegrityProof` using the `eddsa-jcs-2022` cryptosuite.

```csharp
using Pdtf.Core;

var vc = """
{
    "@context": [
        "https://www.w3.org/ns/credentials/v2",
        "https://www.w3.org/ns/credentials/examples/v2"
    ],
    "type": ["VerifiableCredential", "PropertyDataCredential"],
    "issuer": "did:key:z6Mkh...",
    "validFrom": "2025-01-15T09:00:00Z",
    "credentialSubject": {
        "id": "urn:pdtf:uprn:100023336956",
        "energyRating": "B"
    }
}
""";

string signedJson = PdtfCore.SignCredential(vc, kp.SecretKeyHex);
```

**Parameters:**
- `vcJson` — JSON string of the unsigned VC
- `secretKeyHex` — hex-encoded Ed25519 secret key

**Returns:** JSON string of the signed VC with `proof` attached.

**Throws:** `PdtfException` on signing failure, `ArgumentNullException` if parameters are null.

---

### `PdtfCore.VerifyProof(string vcJson, string publicKeyHex) → bool`

Verify the `DataIntegrityProof` on a signed Verifiable Credential.

```csharp
using Pdtf.Core;

bool isValid = PdtfCore.VerifyProof(signedJson, kp.PublicKeyHex);
Console.WriteLine($"Valid: {isValid}"); // True
```

**Parameters:**
- `vcJson` — JSON string of the signed VC (must contain a `proof` field)
- `publicKeyHex` — hex-encoded Ed25519 public key

**Returns:** `true` if the proof is valid, `false` otherwise.

**Throws:** `PdtfException` on verification error.

---

### `PdtfCore.ResolveDidKey(string did) → string`

Resolve a `did:key` identifier to its DID Document.

```csharp
using Pdtf.Core;

string docJson = PdtfCore.ResolveDidKey("did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK");
Console.WriteLine(docJson);
```

**Returns:** JSON string of the DID Document.

---

### `PdtfCore.CheckTrust(string registryJson, string issuerDid, string[] paths) → TrustVerificationResult`

Check whether an issuer is authorised for the given credential paths in a Federation Trust Registry.

```csharp
using Pdtf.Core;

var result = PdtfCore.CheckTrust(registryJson, "did:key:z6Mkh...", 
    new[] { "Property:/energyEfficiency/rating" });

Console.WriteLine($"Trusted: {result.Trusted}");
Console.WriteLine($"Trust level: {result.TrustLevel}");
Console.WriteLine($"Paths covered: {string.Join(", ", result.PathsCovered)}");
```

**Returns:** `TrustVerificationResult` with properties:
- `Trusted` (bool) — whether the issuer is authorised
- `IssuerSlug` (string?) — matched issuer slug
- `TrustLevel` (string?) — `"rootIssuer"`, `"trustedProxy"`, or `"accountProvider"`
- `Status` (string?) — `"active"`, `"deprecated"`, `"revoked"`, or `"planned"`
- `PathsCovered` (List\<string\>) — paths the issuer is authorised for
- `UncoveredPaths` (List\<string\>) — paths not covered
- `Warnings` (List\<string\>) — any warnings

---

### `PdtfCore.CreateStatusList(int size) → string`

Create an empty Bitstring Status List for credential revocation.

```csharp
using Pdtf.Core;

string bitstring = PdtfCore.CreateStatusList(131072);
```

**Parameters:**
- `size` — size in bits (minimum 131072, must be a multiple of 8)

**Returns:** Base64-encoded gzip-compressed bitstring.

---

### `PdtfCore.CheckStatus(string bitstringBase64, int index) → bool`

Check whether a credential index is revoked in a Bitstring Status List.

```csharp
using Pdtf.Core;

string bitstring = PdtfCore.CreateStatusList(131072);
bool revoked = PdtfCore.CheckStatus(bitstring, 42);
Console.WriteLine($"Revoked: {revoked}"); // False
```

**Returns:** `true` if the bit is set (revoked), `false` otherwise.

---

## Model Classes

### `KeyPair`

```csharp
public sealed class KeyPair
{
    public string Did { get; set; }
    public string PublicKeyHex { get; set; }
    public string SecretKeyHex { get; set; }
}
```

### `TrustVerificationResult`

```csharp
public sealed class TrustVerificationResult
{
    public bool Trusted { get; set; }
    public string? IssuerSlug { get; set; }
    public string? TrustLevel { get; set; }
    public string? Status { get; set; }
    public List<string> PathsCovered { get; set; }
    public List<string> UncoveredPaths { get; set; }
    public List<string> Warnings { get; set; }
}
```

### `VerifiableCredential`

```csharp
public sealed class VerifiableCredential
{
    public List<string> Context { get; set; }
    public List<string> Type { get; set; }
    public string Issuer { get; set; }
    public string ValidFrom { get; set; }
    public Dictionary<string, object>? CredentialSubject { get; set; }
    public DataIntegrityProof? Proof { get; set; }
}
```

### `DidDocument`

```csharp
public sealed class DidDocument
{
    public List<string> Context { get; set; }
    public string Id { get; set; }
    public List<VerificationMethod>? VerificationMethods { get; set; }
    public List<string>? Authentication { get; set; }
    public List<string>? AssertionMethod { get; set; }
}
```

## End-to-End Example

```csharp
using System.Text.Json;
using Pdtf.Core;

// 1. Generate a keypair
var kp = PdtfCore.GenerateKeyPair();
Console.WriteLine($"Issuer DID: {kp.Did}");

// 2. Build an unsigned VC
var vc = JsonSerializer.Serialize(new
{
    @context = new[]
    {
        "https://www.w3.org/ns/credentials/v2",
        "https://www.w3.org/ns/credentials/examples/v2"
    },
    type = new[] { "VerifiableCredential", "PropertyDataCredential" },
    issuer = kp.Did,
    validFrom = "2025-01-15T09:00:00Z",
    credentialSubject = new
    {
        id = "urn:pdtf:uprn:100023336956",
        titleNumber = "WYK123456",
        tenure = "freehold"
    }
});

// 3. Sign it
string signedJson = PdtfCore.SignCredential(vc, kp.SecretKeyHex);
Console.WriteLine("Signed VC:");
Console.WriteLine(signedJson);

// 4. Verify the signature
bool isValid = PdtfCore.VerifyProof(signedJson, kp.PublicKeyHex);
Console.WriteLine($"Signature valid: {isValid}"); // True

// 5. Resolve the issuer's DID
string didDoc = PdtfCore.ResolveDidKey(kp.Did);
Console.WriteLine($"DID Document: {didDoc}");

// 6. Tamper detection
var tampered = JsonSerializer.Deserialize<JsonElement>(signedJson);
// ... modify credentialSubject ...
bool validAfterTamper = PdtfCore.VerifyProof(tamperedJson, kp.PublicKeyHex);
Console.WriteLine($"Valid after tampering: {validAfterTamper}"); // False
```

## Error Handling

All methods throw `PdtfException` when the native library returns an error. The exception message contains the error detail from the Rust FFI layer.

```csharp
try
{
    PdtfCore.VerifyProof(invalidJson, publicKey);
}
catch (PdtfException ex)
{
    Console.WriteLine($"Verification failed: {ex.Message}");
}
```

Methods also throw `ArgumentNullException` for null parameters and `ArgumentOutOfRangeException` for invalid sizes/indices.

## Platform Support

The native library must be compiled for your target platform:

| Platform | Library file | Env variable |
|----------|-------------|--------------|
| Linux x64 | `libpdtf_core_ffi.so` | `LD_LIBRARY_PATH` |
| macOS x64/arm64 | `libpdtf_core_ffi.dylib` | `DYLD_LIBRARY_PATH` |
| Windows x64 | `pdtf_core_ffi.dll` | `PATH` |

Cross-compilation via `cargo build --target` is supported for all platforms.

## NuGet Package

> **Coming soon.** The `Pdtf.Core` NuGet package will include pre-built native binaries for Linux, macOS, and Windows, with automatic runtime selection via NuGet's `runtimes/` convention.

## Links

- **Core Rust library:** [property-data-standards-co/core-rs](https://github.com/property-data-standards-co/core-rs)
- **Python bindings:** [bindings/python/README.md](../python/README.md)
- **PDTF 2.0 specs:** [property-data-standards-co.github.io/webv2](https://property-data-standards-co.github.io/webv2/)

## License

MIT — Ed Molyneux
