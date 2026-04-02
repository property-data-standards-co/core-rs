using System.Text.Json.Serialization;

namespace Pdtf.Core.Models;

/// <summary>
/// A DID Document resolved from a did:key identifier.
/// </summary>
public sealed class DidDocument
{
    [JsonPropertyName("@context")]
    public List<string> Context { get; set; } = new();

    [JsonPropertyName("id")]
    public string Id { get; set; } = string.Empty;

    [JsonPropertyName("verificationMethod")]
    public List<VerificationMethod>? VerificationMethods { get; set; }

    [JsonPropertyName("authentication")]
    public List<string>? Authentication { get; set; }

    [JsonPropertyName("assertionMethod")]
    public List<string>? AssertionMethod { get; set; }
}

/// <summary>
/// A verification method within a DID Document.
/// </summary>
public sealed class VerificationMethod
{
    [JsonPropertyName("id")]
    public string Id { get; set; } = string.Empty;

    [JsonPropertyName("type")]
    public string Type { get; set; } = string.Empty;

    [JsonPropertyName("controller")]
    public string Controller { get; set; } = string.Empty;

    [JsonPropertyName("publicKeyMultibase")]
    public string? PublicKeyMultibase { get; set; }
}
