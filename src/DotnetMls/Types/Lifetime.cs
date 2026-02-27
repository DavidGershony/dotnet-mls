using DotnetMls.Codec;

namespace DotnetMls.Types;

/// <summary>
/// Lifetime for a KeyPackage leaf node (RFC 9420 Section 7.2).
/// Represents the validity window as Unix timestamps.
/// </summary>
public sealed class Lifetime
{
    /// <summary>
    /// The earliest time at which the KeyPackage is valid (Unix timestamp).
    /// </summary>
    public ulong NotBefore { get; set; }

    /// <summary>
    /// The latest time at which the KeyPackage is valid (Unix timestamp).
    /// </summary>
    public ulong NotAfter { get; set; }

    public Lifetime()
    {
    }

    public Lifetime(ulong notBefore, ulong notAfter)
    {
        NotBefore = notBefore;
        NotAfter = notAfter;
    }

    public void WriteTo(TlsWriter writer)
    {
        writer.WriteUint64(NotBefore);
        writer.WriteUint64(NotAfter);
    }

    public static Lifetime ReadFrom(TlsReader reader)
    {
        ulong notBefore = reader.ReadUint64();
        ulong notAfter = reader.ReadUint64();
        return new Lifetime(notBefore, notAfter);
    }
}
