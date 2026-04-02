using System.Text.Json;
using Xunit;

namespace Pdtf.Core.Tests;

public class SignerTests
{
    private static string MakeUnsignedVc(string issuerDid) => $$"""
        {
            "@context": ["https://www.w3.org/ns/credentials/v2"],
            "type": ["VerifiableCredential"],
            "issuer": "{{issuerDid}}",
            "validFrom": "2026-01-01T00:00:00Z",
            "credentialSubject": {"id": "did:example:subject", "name": "Test"}
        }
        """;

    [Fact]
    public void SignAndVerify_Roundtrip()
    {
        var kp = PdtfCore.GenerateKeyPair();
        var vcJson = MakeUnsignedVc(kp.Did);

        var signed = PdtfCore.SignCredential(vcJson, kp.SecretKeyHex);

        Assert.NotNull(signed);
        Assert.Contains("proof", signed);
        Assert.Contains("proofValue", signed);

        var valid = PdtfCore.VerifyProof(signed, kp.PublicKeyHex);
        Assert.True(valid);
    }

    [Fact]
    public void Verify_WithWrongKey_ReturnsFalse()
    {
        var kp1 = PdtfCore.GenerateKeyPair();
        var kp2 = PdtfCore.GenerateKeyPair();

        var vcJson = MakeUnsignedVc(kp1.Did);
        var signed = PdtfCore.SignCredential(vcJson, kp1.SecretKeyHex);

        var valid = PdtfCore.VerifyProof(signed, kp2.PublicKeyHex);
        Assert.False(valid);
    }
}
