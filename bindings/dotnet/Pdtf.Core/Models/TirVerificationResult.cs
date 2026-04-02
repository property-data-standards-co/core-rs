using System.Text.Json.Serialization;

namespace Pdtf.Core.Models;

/// <summary>
/// Result of a Trusted Issuer Registry verification check.
/// </summary>
public sealed class TirVerificationResult
{
    [JsonPropertyName("trusted")]
    public bool Trusted { get; set; }

    [JsonPropertyName("issuer_slug")]
    public string? IssuerSlug { get; set; }

    [JsonPropertyName("trust_level")]
    public string? TrustLevel { get; set; }

    [JsonPropertyName("status")]
    public string? Status { get; set; }

    [JsonPropertyName("paths_covered")]
    public List<string> PathsCovered { get; set; } = new();

    [JsonPropertyName("uncovered_paths")]
    public List<string> UncoveredPaths { get; set; } = new();

    [JsonPropertyName("warnings")]
    public List<string> Warnings { get; set; } = new();
}
