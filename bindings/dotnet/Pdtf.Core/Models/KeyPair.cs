using System.Text.Json.Serialization;

namespace Pdtf.Core.Models;

/// <summary>
/// An Ed25519 keypair with its derived did:key identifier.
/// </summary>
public sealed class KeyPair
{
    [JsonPropertyName("did")]
    public string Did { get; set; } = string.Empty;

    [JsonPropertyName("publicKeyHex")]
    public string PublicKeyHex { get; set; } = string.Empty;

    [JsonPropertyName("secretKeyHex")]
    public string SecretKeyHex { get; set; } = string.Empty;
}
