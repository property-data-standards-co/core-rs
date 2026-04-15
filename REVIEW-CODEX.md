# REVIEW-CODEX

## Scope reviewed

I reviewed the actual source in:

- `crates/pdtf-core/src/` (keys, signer/proof, validator, DID resolution, status lists, TIR)
- `bindings/python/`
- `bindings/dotnet-ffi/` and `bindings/dotnet/`
- `test-vectors/vectors.json`
- cross-language tests in Rust / Python / C#
- TypeScript reference implementation in `~/repos/pdtf-core/`

I also ran the TypeScript test suite successfully:

- `~/repos/pdtf-core`: `vitest` passed (`7` files, `68` tests)

I could not run:

- Rust tests: `cargo` not installed in this environment
- Python tests: `pytest` not installed
- C# tests: `dotnet` not installed

So the review below is source-based for Rust/Python/C# runtime behaviour, with TS tests executed.

---

## Critical issues

### 1. Validator does not bind `issuer` to the signing DID / verification method

**Files:**
- Rust: `crates/pdtf-core/src/validator/verify.rs`
- TS: `~/repos/pdtf-core/src/validator/vc-validator.ts`

**Problem**

Stage 2 verifies the signature against the DID extracted from `proof.verificationMethod`. Stage 3 then checks TIR authorisation against `vc.issuer`. There is no check that:

- `vc.issuer` equals the DID part of `proof.verificationMethod`
- the verification method is controlled by that issuer
- the verification method is authorised for `assertionMethod`

That creates an identity-binding flaw:

1. attacker signs with their own key/DID `did:key:attacker...`
2. attacker sets `vc.issuer = did:web:trusted.example`
3. Stage 2 passes, because the proof is internally valid for the attacker's DID
4. Stage 3 checks TIR against the claimed issuer field (`did:web:trusted.example`), not the proof DID

So a credential can claim to be issued by a trusted DID while actually being signed by another DID.

**Why this matters**

This is a correctness and trust-model failure, not just a cosmetic validation gap. It undermines the entire issuer authorisation step.

**Notes**

- The Python and .NET signing helpers added an issuer/key consistency check when signing.
- But the core Rust `create_proof` function does not enforce this.
- More importantly, verification must defend against malicious input regardless of how the VC was produced.

**What to fix first**

At verification time, require all of the following:

- DID part of `proof.verificationMethod` == `vc.issuer.id()`
- resolved verification method controller == issuer DID
- verification method is referenced from `assertionMethod`

This should be enforced in both Rust and TypeScript validators.

---

### 2. Rust timestamp parsing is fail-open and accepts invalid / unsupported ISO timestamps by skipping checks

**Files:**
- `crates/pdtf-core/src/validator/verify.rs`
- `crates/pdtf-core/src/tir/verify.rs`

**Problem**

Rust uses a hand-rolled `parse_iso_epoch()` that only supports an exact `YYYY-MM-DDTHH:MM:SSZ` shape. If parsing fails, the code silently skips the check.

That means these checks can be bypassed simply by using a legitimate ISO 8601 form that the parser does not understand, such as:

- fractional seconds: `2026-01-01T00:00:00.123Z`
- offset form: `2026-01-01T00:00:00+00:00`
- other valid RFC3339 forms

Affected checks:

- VC `validFrom`
- VC `validUntil`
- TIR issuer `validFrom`
- TIR issuer `validUntil`

If parsing fails, expired or not-yet-valid credentials / issuers can be treated as valid.

**Cross-language divergence**

TypeScript uses `new Date(...)`, so Rust and TS do not currently agree on timestamp acceptance semantics.

**What to fix first**

Use a real RFC3339 / ISO 8601 parser (`time` or `chrono`) and fail closed on unparseable timestamps during validation.

---

## Important issues

### 3. Rust structure validation is materially looser than TypeScript

**Files:**
- Rust: `crates/pdtf-core/src/validator/verify.rs`
- TS: `~/repos/pdtf-core/src/validator/vc-validator.ts`

Rust `check_structure()` is noticeably weaker than the TS validator:

- it only checks `@context` contains the substring `"credentials"`
- it does not require the exact W3C VC v2 context URI
- it does not validate proof `type`
- it does not validate proof `cryptosuite`
- it does not require `credentialStatus`

TS is stricter on these points, though still not fully strict about exact context matching.

**Impact**

The same VC can pass Rust structure checks but fail TS structure checks. That is a cross-language consistency problem in the validator, even if the primitive proof verification still agrees.

**Recommendation**

Define one normative validator contract and make Rust/TS match exactly.

---

### 4. Cross-language tests cover primitives, not the full verification pipeline

**Files:**
- `crates/pdtf-core/tests/cross_language.rs`
- `bindings/python/tests/test_cross_language.py`
- `bindings/dotnet/Pdtf.Core.Tests/CrossLanguageTests.cs`
- `~/repos/pdtf-core/scripts/generate-vectors.ts`
- `test-vectors/vectors.json`

The shared vectors are good for:

- did:key derivation
- proof signing/verifying
- bitstring status list bit operations
- TIR path matching

But they do **not** cover the highest-risk validator cases, including:

- issuer/proof DID mismatch
- verification method not present in DID document
- verification method not authorised in `assertionMethod`
- wrong `proofPurpose`
- wrong proof `type` / `cryptosuite`
- malformed or unsupported timestamp formats
- TIR not-yet-valid / expired issuer windows
- malformed gzip/base64 status lists
- did:web verification method handling
- empty claimed paths behaviour in end-to-end validator calls

Given the identity-binding flaw above, this gap is significant.

**Recommendation**

Add validator-level vectors and run them through Rust + TS + Python + C# wrappers where applicable.

---

### 5. Python and .NET bindings expose a smaller, did:key-only signing surface than Rust core

**Files:**
- `bindings/python/src/lib.rs`
- `bindings/dotnet-ffi/src/lib.rs`
- `bindings/dotnet/Pdtf.Core/PdtfCore.cs`
- Rust signer: `crates/pdtf-core/src/signer/mod.rs`

The bindings' signing helpers derive a `did:key` directly from the supplied secret key and always emit a `did:key` verification method. That is fine for deterministic cross-language testing, but it is narrower than the Rust core API, which can also sign as `did:web` via `VcSigner::new(..., issuer_did)`.

So the binding APIs are not feature-equivalent to the Rust core.

**Impact**

- cross-language capability mismatch
- no path in Python / C# to exercise `did:web` signing flows
- test coverage remains biased toward `did:key`

**Recommendation**

Either:

- explicitly document Python/.NET as primitive `did:key` wrappers only, or
- expose a higher-level API that accepts issuer DID + verification method and mirrors Rust `VcSigner`

---

### 6. Validator does not verify `assertionMethod` membership

**Files:**
- Rust: `crates/pdtf-core/src/validator/verify.rs`
- TS: `~/repos/pdtf-core/src/validator/vc-validator.ts`

Both validators find the verification method in the DID document and extract the key, but they do not verify that the method is actually authorised for `assertionMethod`.

For VC issuance, this matters. A DID document can contain multiple verification methods for different purposes.

**Recommendation**

After resolving the DID document, require `proof.verificationMethod` to be present in `assertionMethod` (accounting for URI/reference forms as needed).

---

## Minor issues

### 7. Python API naming is inconsistent

**File:** `bindings/python/src/lib.rs`

The module exports `verify_proof_py`, whereas the rest of the surface uses neutral names like `sign_vc`, `resolve_did_key`, `check_tir`, `check_status`.

This is harmless but awkward. `verify_proof` would be the natural public name.

---

### 8. `vectors.json` includes a generation timestamp, so the file is not reproducible byte-for-byte

**Files:**
- `~/repos/pdtf-core/scripts/generate-vectors.ts`
- `test-vectors/vectors.json`

`generated` changes on every regeneration. That is fine for metadata, but it means the shared vectors file is always noisy in diffs even when the substantive vectors are unchanged.

A stable mode or separate metadata file would make review easier.

---

### 9. Rust duplicates hand-written date logic in multiple places

**Files:**
- `crates/pdtf-core/src/validator/verify.rs`
- `crates/pdtf-core/src/tir/verify.rs`
- `crates/pdtf-core/src/signer/proof.rs`

There is repeated custom calendar logic for parsing/formatting timestamps. Even where it is correct for the narrow happy path, it is fragile and hard to audit.

Replacing it with a standard time library would reduce risk and simplify maintenance.

---

### 10. Some tamper tests are brittle string replacements

**File:** `bindings/dotnet/Pdtf.Core.Tests/CrossLanguageTests.cs`

The C# tamper test mutates JSON with string replacement (`"score":85` → `"score":99`). It works for the current formatting but is brittle. A structured JSON mutation would be safer.

---

## Cross-language consistency

### Things that look good

- **Proof construction / verification**: Rust and TS are aligned on the intended `eddsa-jcs-2022` flow:
  - JCS canonicalize proof options
  - SHA-256
  - JCS canonicalize document without proof
  - SHA-256
  - concatenate hashes
  - Ed25519 sign/verify raw 64-byte concatenation
- **did:key**: Rust and TS both use the Ed25519 multicodec prefix `0xed01`, base58btc, and `z` multibase prefix correctly.
- **Bitstring status lists**: Rust and TS both implement gzip + base64 around the raw bitstring and the shared vectors exercise logical compatibility.
- **TIR wildcard matching**: Rust and TS match on the cases I checked; wildcard semantics are consistent for exact entity matches, `Entity:*`, and `Entity:/path/*` descendants.
- **FFI hygiene**: the Rust C FFI is generally careful about `catch_unwind`, null checks, and ownership of returned strings. The C# wrapper correctly frees returned pointers.

### Divergences / mismatches

1. **Validator semantics differ between Rust and TS**
   - Rust structure validation is looser.
   - TS handles timestamp parsing more broadly.
   - Neither binds issuer ↔ proof DID correctly.

2. **Bindings are not capability-equivalent to Rust core**
   - Python/C# signing helpers are effectively `did:key`-only.
   - Rust core can model `did:web` signing/verification paths.

3. **Shared vectors are primitive-focused**
   - They prove crypto/interoperability basics.
   - They do not prove the full security properties of the validator pipeline.

4. **Binding signing helpers have stricter issuer/key checks than core Rust proof creation**
   - Python/.NET `sign_vc` reject issuer/key mismatch.
   - core Rust `create_proof()` does not enforce that relationship.
   - Verification still needs to enforce it, so this partial inconsistency is not enough.

---

## Verdict

**Not production-ready yet.**

The cryptographic primitives themselves look broadly sound, and the TS reference tests pass. did:key encoding, JCS+SHA-256+Ed25519 proof construction, status-list bit operations, and TIR path wildcard matching all look directionally correct.

But there are two blockers before I would trust this in production:

1. **Fix issuer binding in verification**
   - `vc.issuer` must be cryptographically tied to `proof.verificationMethod`
   - enforce controller + `assertionMethod`
   - do this in both Rust and TS validators

2. **Replace fail-open timestamp parsing in Rust**
   - use proper RFC3339 parsing
   - invalid/unparseable timestamps must fail validation, not skip checks

After that, the next priority is:

3. **Expand cross-language vectors/tests to cover validator security cases**, not just primitive interoperability.

If those three things are fixed, the remaining issues are mostly API/documentation consistency rather than fundamental correctness.
