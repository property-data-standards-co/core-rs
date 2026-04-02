namespace Pdtf.Core.Models;

/// <summary>
/// A Bitstring Status List for credential revocation.
/// The bitstring is stored as a base64-encoded gzip-compressed byte array.
/// </summary>
public sealed class StatusList
{
    /// <summary>
    /// The base64-encoded, gzip-compressed bitstring.
    /// </summary>
    public string BitstringBase64 { get; set; } = string.Empty;

    /// <summary>
    /// The size of the status list in bits.
    /// </summary>
    public int Size { get; set; }
}
