using System.Runtime.InteropServices;

namespace Pdtf.Core;

/// <summary>
/// P/Invoke declarations for the pdtf_core_ffi native library.
/// All returned IntPtr strings must be freed with PdtfFreeString().
/// </summary>
internal static class NativeMethods
{
    private const string LibName = "pdtf_core_ffi";

    [DllImport(LibName, CallingConvention = CallingConvention.Cdecl)]
    internal static extern IntPtr pdtf_generate_keypair();

    [DllImport(LibName, CallingConvention = CallingConvention.Cdecl)]
    internal static extern IntPtr pdtf_sign_vc(
        [MarshalAs(UnmanagedType.LPUTF8Str)] string vcJson,
        [MarshalAs(UnmanagedType.LPUTF8Str)] string secretKeyHex);

    [DllImport(LibName, CallingConvention = CallingConvention.Cdecl)]
    internal static extern int pdtf_verify_proof(
        [MarshalAs(UnmanagedType.LPUTF8Str)] string vcJson,
        [MarshalAs(UnmanagedType.LPUTF8Str)] string publicKeyHex);

    [DllImport(LibName, CallingConvention = CallingConvention.Cdecl)]
    internal static extern IntPtr pdtf_resolve_did_key(
        [MarshalAs(UnmanagedType.LPUTF8Str)] string did);

    [DllImport(LibName, CallingConvention = CallingConvention.Cdecl)]
    internal static extern IntPtr pdtf_check_tir(
        [MarshalAs(UnmanagedType.LPUTF8Str)] string registryJson,
        [MarshalAs(UnmanagedType.LPUTF8Str)] string issuerDid,
        [MarshalAs(UnmanagedType.LPUTF8Str)] string pathsJson);

    [DllImport(LibName, CallingConvention = CallingConvention.Cdecl)]
    internal static extern IntPtr pdtf_create_status_list(uint size);

    [DllImport(LibName, CallingConvention = CallingConvention.Cdecl)]
    internal static extern int pdtf_check_status(
        [MarshalAs(UnmanagedType.LPUTF8Str)] string bitstringB64,
        uint index);

    [DllImport(LibName, CallingConvention = CallingConvention.Cdecl)]
    internal static extern void pdtf_free_string(IntPtr ptr);

    [DllImport(LibName, CallingConvention = CallingConvention.Cdecl)]
    internal static extern IntPtr pdtf_last_error();
}
