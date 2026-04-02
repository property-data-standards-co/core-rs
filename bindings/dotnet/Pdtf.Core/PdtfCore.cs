using System.Runtime.InteropServices;
using System.Text.Json;
using Pdtf.Core.Models;

namespace Pdtf.Core;

/// <summary>
/// High-level C# API for the PDTF 2.0 core library.
/// Wraps the native Rust FFI library via P/Invoke.
/// </summary>
public static class PdtfCore
{
    /// <summary>
    /// Generate an Ed25519 keypair with a derived did:key identifier.
    /// </summary>
    public static KeyPair GenerateKeyPair()
    {
        var ptr = NativeMethods.pdtf_generate_keypair();
        var json = ConsumeNativeString(ptr)
            ?? throw new PdtfException(GetLastErrorOrDefault("Failed to generate keypair"));
        return JsonSerializer.Deserialize<KeyPair>(json)
            ?? throw new PdtfException("Failed to deserialize keypair JSON");
    }

    /// <summary>
    /// Sign a Verifiable Credential JSON string with a secret key (hex-encoded).
    /// Returns the signed VC as a JSON string.
    /// </summary>
    public static string SignCredential(string vcJson, string secretKeyHex)
    {
        ArgumentNullException.ThrowIfNull(vcJson);
        ArgumentNullException.ThrowIfNull(secretKeyHex);

        var ptr = NativeMethods.pdtf_sign_vc(vcJson, secretKeyHex);
        return ConsumeNativeString(ptr)
            ?? throw new PdtfException(GetLastErrorOrDefault("Failed to sign credential"));
    }

    /// <summary>
    /// Verify a DataIntegrityProof on a VC using the given public key (hex-encoded).
    /// </summary>
    public static bool VerifyProof(string vcJson, string publicKeyHex)
    {
        ArgumentNullException.ThrowIfNull(vcJson);
        ArgumentNullException.ThrowIfNull(publicKeyHex);

        var result = NativeMethods.pdtf_verify_proof(vcJson, publicKeyHex);
        return result switch
        {
            1 => true,
            0 => false,
            _ => throw new PdtfException(GetLastErrorOrDefault("Failed to verify proof"))
        };
    }

    /// <summary>
    /// Resolve a did:key identifier to its DID Document JSON.
    /// </summary>
    public static string ResolveDidKey(string did)
    {
        ArgumentNullException.ThrowIfNull(did);

        var ptr = NativeMethods.pdtf_resolve_did_key(did);
        return ConsumeNativeString(ptr)
            ?? throw new PdtfException(GetLastErrorOrDefault("Failed to resolve DID"));
    }

    /// <summary>
    /// Check a set of credential paths against a Trusted Issuer Registry.
    /// </summary>
    public static TirVerificationResult CheckTir(string registryJson, string issuerDid, string[] paths)
    {
        ArgumentNullException.ThrowIfNull(registryJson);
        ArgumentNullException.ThrowIfNull(issuerDid);
        ArgumentNullException.ThrowIfNull(paths);

        var pathsJson = JsonSerializer.Serialize(paths);
        var ptr = NativeMethods.pdtf_check_tir(registryJson, issuerDid, pathsJson);
        var json = ConsumeNativeString(ptr)
            ?? throw new PdtfException(GetLastErrorOrDefault("Failed to check TIR"));
        return JsonSerializer.Deserialize<TirVerificationResult>(json)
            ?? throw new PdtfException("Failed to deserialize TIR result");
    }

    /// <summary>
    /// Create an empty Bitstring Status List of the given size (in bits).
    /// Minimum size is 131072 (16KB). Must be a multiple of 8.
    /// Returns the base64-encoded gzip-compressed bitstring.
    /// </summary>
    public static string CreateStatusList(int size)
    {
        if (size < 0)
            throw new ArgumentOutOfRangeException(nameof(size), "Size must be non-negative");

        var ptr = NativeMethods.pdtf_create_status_list((uint)size);
        return ConsumeNativeString(ptr)
            ?? throw new PdtfException(GetLastErrorOrDefault("Failed to create status list"));
    }

    /// <summary>
    /// Check if a credential index is revoked in a Bitstring Status List.
    /// </summary>
    public static bool CheckStatus(string bitstringBase64, int index)
    {
        ArgumentNullException.ThrowIfNull(bitstringBase64);
        if (index < 0)
            throw new ArgumentOutOfRangeException(nameof(index), "Index must be non-negative");

        var result = NativeMethods.pdtf_check_status(bitstringBase64, (uint)index);
        return result switch
        {
            1 => true,
            0 => false,
            _ => throw new PdtfException(GetLastErrorOrDefault("Failed to check status"))
        };
    }

    // -----------------------------------------------------------------------
    // Helpers
    // -----------------------------------------------------------------------

    /// <summary>
    /// Read a native C string, free it, and return the managed string.
    /// Returns null if the pointer is IntPtr.Zero.
    /// </summary>
    private static string? ConsumeNativeString(IntPtr ptr)
    {
        if (ptr == IntPtr.Zero)
            return null;

        try
        {
            return Marshal.PtrToStringUTF8(ptr);
        }
        finally
        {
            NativeMethods.pdtf_free_string(ptr);
        }
    }

    /// <summary>
    /// Get the last error from the native library, or a default message.
    /// </summary>
    private static string GetLastErrorOrDefault(string defaultMessage)
    {
        var errPtr = NativeMethods.pdtf_last_error();
        var err = ConsumeNativeString(errPtr);
        return err ?? defaultMessage;
    }
}
