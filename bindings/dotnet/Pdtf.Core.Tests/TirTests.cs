using Xunit;

namespace Pdtf.Core.Tests;

public class TirTests
{
    private const string RegistryJson = """
        {
            "version": "1.0",
            "lastUpdated": "2026-01-01T00:00:00Z",
            "issuers": {
                "test-issuer": {
                    "slug": "test-issuer",
                    "did": "did:key:z6MkTest",
                    "name": "Test Issuer",
                    "trustLevel": "rootIssuer",
                    "status": "active",
                    "authorisedPaths": ["Property:*", "Title:*"]
                }
            },
            "userAccountProviders": {}
        }
        """;

    [Fact]
    public void CheckTir_KnownIssuer_ReturnsTrusted()
    {
        var result = PdtfCore.CheckTir(
            RegistryJson,
            "did:key:z6MkTest",
            new[] { "Property:/address" });

        Assert.True(result.Trusted);
        Assert.Equal("test-issuer", result.IssuerSlug);
        Assert.Contains("Property:/address", result.PathsCovered);
        Assert.Empty(result.UncoveredPaths);
    }

    [Fact]
    public void CheckTir_UnknownIssuer_ReturnsUntrusted()
    {
        var result = PdtfCore.CheckTir(
            RegistryJson,
            "did:key:z6MkUnknown",
            new[] { "Property:/address" });

        Assert.False(result.Trusted);
        Assert.Null(result.IssuerSlug);
        Assert.Contains("Property:/address", result.UncoveredPaths);
    }
}
