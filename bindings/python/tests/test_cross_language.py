"""
Cross-language test vector validation for Python bindings.

Proves that Python (via PyO3 → Rust) produces identical results to the
TypeScript reference implementation for all PDTF core operations.
"""
import json
import os
import pytest
import pdtf_core

VECTORS_PATH = os.path.join(
    os.path.dirname(__file__), '..', '..', '..', 'test-vectors', 'vectors.json'
)

@pytest.fixture(scope='module')
def vectors():
    with open(VECTORS_PATH) as f:
        return json.load(f)


class TestKeyDerivation:
    """Verify did:key derivation matches TypeScript."""

    def test_generate_keypair_format(self):
        """Generated keypair has correct structure and DID format."""
        kp = pdtf_core.generate_keypair()
        assert kp['did'].startswith('did:key:z6Mk')
        assert len(kp['public_key_hex']) == 64  # 32 bytes hex
        assert len(kp['secret_key_hex']) == 64  # 32 bytes hex

    def test_resolve_did_key_matches_typescript(self, vectors):
        """Resolve the vector's did:key and verify DID document structure."""
        did = vectors['keys']['did']
        doc = json.loads(pdtf_core.resolve_did_key(did))

        expected = vectors['didDocument']['expected']
        assert doc['id'] == expected['id']
        assert doc['verificationMethod'][0]['publicKeyMultibase'] == \
               expected['verificationMethod'][0]['publicKeyMultibase']
        assert doc['verificationMethod'][0]['controller'] == did


class TestSigningAndVerification:
    """End-to-end: sign with Python, verify with Python, cross-verify with TS vectors."""

    def test_sign_and_verify_roundtrip(self):
        """Generate key, sign a VC, verify — full Python roundtrip."""
        kp = pdtf_core.generate_keypair()

        vc = {
            "@context": [
                "https://www.w3.org/ns/credentials/v2",
                "https://propdata.org.uk/credentials/v2"
            ],
            "type": ["VerifiableCredential", "PropertyDataCredential"],
            "id": "urn:uuid:python-test-001",
            "issuer": kp['did'],
            "validFrom": "2026-01-01T00:00:00Z",
            "credentialSubject": {
                "id": "urn:pdtf:uprn:100023336956",
                "energyEfficiency": {"rating": "B", "score": 85}
            }
        }

        signed_json = pdtf_core.sign_vc(json.dumps(vc), kp['secret_key_hex'])
        signed = json.loads(signed_json)

        # Must have a proof
        assert 'proof' in signed
        assert signed['proof']['type'] == 'DataIntegrityProof'
        assert signed['proof']['cryptosuite'] == 'eddsa-jcs-2022'
        assert signed['proof']['proofValue'].startswith('z')

        # Verify with the correct key
        assert pdtf_core.verify_proof(signed_json, kp['public_key_hex']) is True

    def test_verify_typescript_signed_vc(self, vectors):
        """Verify VCs that were signed by TypeScript."""
        for vv in vectors['verification']:
            vc_json = json.dumps(vv['vc'])
            result = pdtf_core.verify_proof(vc_json, vv['publicKeyHex'])
            assert result == vv['expectedValid'], \
                f"Verification mismatch for '{vv['name']}': expected {vv['expectedValid']}, got {result}"

    def test_tampered_vc_fails(self, vectors):
        """Tampered VC should fail verification."""
        tampered = [v for v in vectors['verification'] if v['name'] == 'tampered-subject']
        assert len(tampered) == 1
        assert pdtf_core.verify_proof(
            json.dumps(tampered[0]['vc']), tampered[0]['publicKeyHex']
        ) is False

    def test_wrong_key_fails(self, vectors):
        """Valid VC verified with wrong public key should fail."""
        wrong_key = [v for v in vectors['verification'] if v['name'] == 'wrong-key']
        assert len(wrong_key) == 1
        assert pdtf_core.verify_proof(
            json.dumps(wrong_key[0]['vc']), wrong_key[0]['publicKeyHex']
        ) is False


class TestStatusList:
    """Verify status list encode/decode matches TypeScript."""

    def test_empty_status_list(self, vectors):
        """Create empty list, all bits should be false."""
        size = vectors['statusList']['size']
        bitstring = pdtf_core.create_status_list(size)
        assert isinstance(bitstring, str)

        for idx in [0, 1, 42, 100, size - 1]:
            assert pdtf_core.check_status(bitstring, idx) is False, \
                f"Empty list bit {idx} should be false"

    def test_decode_typescript_bitstrings(self, vectors):
        """Decode TS-produced bitstrings and verify bit values."""
        for op in vectors['statusList']['operations']:
            if op['action'] == 'check':
                result = pdtf_core.check_status(op['bitstring'], op['index'])
                assert result == op['expected'], \
                    f"Status check at index {op['index']}: expected {op['expected']}, got {result}"


class TestTirPathMatching:
    """Verify TIR path matching matches TypeScript via check_tir."""

    def test_path_matching_vectors(self, vectors):
        """All TIR path matching results must match TypeScript."""
        for tv in vectors['tirPathMatching']:
            registry = {
                "version": "1.0.0",
                "lastUpdated": "2026-01-01T00:00:00Z",
                "issuers": {
                    "test-issuer": {
                        "slug": "test-issuer",
                        "name": "Test Issuer",
                        "did": vectors['keys']['did'],
                        "trustLevel": "rootIssuer",
                        "status": "active",
                        "authorisedPaths": [tv['pattern']],
                        "validFrom": "2024-01-01T00:00:00Z"
                    }
                },
                "userAccountProviders": {}
            }
            result = json.loads(pdtf_core.check_tir(
                json.dumps(registry),
                vectors['keys']['did'],
                [tv['path']]
            ))
            assert result['trusted'] == tv['expected'], \
                f"TIR: pattern='{tv['pattern']}', path='{tv['path']}', " \
                f"expected={tv['expected']}, got={result['trusted']}"


class TestEndToEnd:
    """Full credential lifecycle in Python."""

    def test_full_lifecycle(self):
        """generate → sign → verify → tamper → reject → status list."""
        # 1. Generate key
        kp = pdtf_core.generate_keypair()
        assert kp['did'].startswith('did:key:z6Mk')

        # 2. Resolve DID document
        doc = json.loads(pdtf_core.resolve_did_key(kp['did']))
        assert doc['id'] == kp['did']
        assert len(doc['verificationMethod']) == 1

        # 3. Sign a VC
        vc = {
            "@context": [
                "https://www.w3.org/ns/credentials/v2",
                "https://propdata.org.uk/credentials/v2"
            ],
            "type": ["VerifiableCredential", "PropertyDataCredential"],
            "id": "urn:uuid:e2e-python-test",
            "issuer": kp['did'],
            "validFrom": "2026-06-01T00:00:00Z",
            "credentialSubject": {
                "id": "urn:pdtf:uprn:999999999999",
                "floodRisk": {"zone": "1", "risk": "low"}
            }
        }
        signed_json = pdtf_core.sign_vc(json.dumps(vc), kp['secret_key_hex'])
        signed = json.loads(signed_json)

        # 4. Verify — should pass
        assert pdtf_core.verify_proof(signed_json, kp['public_key_hex']) is True

        # 5. Tamper — should fail
        signed['credentialSubject']['floodRisk']['risk'] = 'high'
        tampered_json = json.dumps(signed)
        assert pdtf_core.verify_proof(tampered_json, kp['public_key_hex']) is False

        # 6. Wrong key — should fail
        kp2 = pdtf_core.generate_keypair()
        assert pdtf_core.verify_proof(signed_json, kp2['public_key_hex']) is False

        # 7. Status list
        bitstring = pdtf_core.create_status_list(131072)
        assert pdtf_core.check_status(bitstring, 42) is False
