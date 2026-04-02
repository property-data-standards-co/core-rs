using System.Text.Json.Serialization;

namespace Pdtf.Core.Models;

/// <summary>
/// A W3C Verifiable Credential with optional DataIntegrityProof.
/// This is a minimal representation for serialization — the full VC is
/// handled as raw JSON by the native library.
/// </summary>
public sealed class VerifiableCredential
{
    [JsonPropertyName("@context")]
    public List<string> Context { get; set; } = new();

    [JsonPropertyName("type")]
    public List<string> Type { get; set; } = new();

    [JsonPropertyName("issuer")]
    public string Issuer { get; set; } = string.Empty;

    [JsonPropertyName("validFrom")]
    public string ValidFrom { get; set; } = string.Empty;

    [JsonPropertyName("credentialSubject")]
    public Dictionary<string, object>? CredentialSubject { get; set; }

    [JsonPropertyName("proof")]
    public DataIntegrityProof? Proof { get; set; }
}

/// <summary>
/// A Data Integrity Proof using the eddsa-jcs-2022 cryptosuite.
/// </summary>
public sealed class DataIntegrityProof
{
    [JsonPropertyName("type")]
    public string Type { get; set; } = "DataIntegrityProof";

    [JsonPropertyName("cryptosuite")]
    public string Cryptosuite { get; set; } = "eddsa-jcs-2022";

    [JsonPropertyName("verificationMethod")]
    public string VerificationMethod { get; set; } = string.Empty;

    [JsonPropertyName("proofPurpose")]
    public string ProofPurpose { get; set; } = "assertionMethod";

    [JsonPropertyName("created")]
    public string Created { get; set; } = string.Empty;

    [JsonPropertyName("proofValue")]
    public string ProofValue { get; set; } = string.Empty;
}
