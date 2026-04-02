using Xunit;

namespace Pdtf.Core.Tests;

public class StatusListTests
{
    [Fact]
    public void CreateStatusList_ReturnsNonEmptyBitstring()
    {
        var bitstring = PdtfCore.CreateStatusList(131072);

        Assert.NotNull(bitstring);
        Assert.NotEmpty(bitstring);
    }

    [Fact]
    public void CheckStatus_NewList_AllBitsUnset()
    {
        var bitstring = PdtfCore.CreateStatusList(131072);

        Assert.False(PdtfCore.CheckStatus(bitstring, 0));
        Assert.False(PdtfCore.CheckStatus(bitstring, 100));
        Assert.False(PdtfCore.CheckStatus(bitstring, 131071));
    }

    [Fact]
    public void CreateStatusList_TooSmall_Throws()
    {
        Assert.Throws<PdtfException>(() => PdtfCore.CreateStatusList(1000));
    }
}
