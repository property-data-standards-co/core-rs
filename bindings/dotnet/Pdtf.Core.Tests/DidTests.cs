using System.Text.Json;
using Xunit;

namespace Pdtf.Core.Tests;

public class DidTests
{
    [Fact]
    public void ResolveDidKey_ReturnsValidDocument()
    {
        var kp = PdtfCore.GenerateKeyPair();

        var docJson = PdtfCore.ResolveDidKey(kp.Did);

        Assert.NotNull(docJson);
        var doc = JsonDocument.Parse(docJson);
        Assert.Equal(kp.Did, doc.RootElement.GetProperty("id").GetString());
    }

    [Fact]
    public void ResolveDidKey_InvalidDid_Throws()
    {
        Assert.Throws<PdtfException>(() => PdtfCore.ResolveDidKey("not-a-did"));
    }
}
