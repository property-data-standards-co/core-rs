namespace Pdtf.Core;

/// <summary>
/// Exception thrown when a PDTF native function fails.
/// </summary>
public class PdtfException : Exception
{
    public PdtfException(string message) : base(message) { }
    public PdtfException(string message, Exception inner) : base(message, inner) { }
}
