using Xunit;

namespace Pdtf.Core.Tests;

public class KeyTests
{
    [Fact]
    public void GenerateKeyPair_ReturnsValidDidKey()
    {
        var kp = PdtfCore.GenerateKeyPair();

        Assert.NotNull(kp);
        Assert.StartsWith("did:key:z6Mk", kp.Did);
        Assert.Equal(64, kp.PublicKeyHex.Length);  // 32 bytes hex-encoded
        Assert.Equal(64, kp.SecretKeyHex.Length);  // 32 bytes hex-encoded
    }

    [Fact]
    public void GenerateKeyPair_ProducesDifferentKeysEachTime()
    {
        var kp1 = PdtfCore.GenerateKeyPair();
        var kp2 = PdtfCore.GenerateKeyPair();

        Assert.NotEqual(kp1.Did, kp2.Did);
        Assert.NotEqual(kp1.SecretKeyHex, kp2.SecretKeyHex);
    }
}
