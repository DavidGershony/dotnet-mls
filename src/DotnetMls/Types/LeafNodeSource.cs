using DotnetMls.Codec;

namespace DotnetMls.Types;

/// <summary>
/// Indicates how a leaf node was created (RFC 9420 Section 7.2).
/// </summary>
public enum LeafNodeSource : byte
{
    KeyPackage = 1,
    Update = 2,
    Commit = 3,
}

/// <summary>
/// TLS serialization helpers for <see cref="LeafNodeSource"/>.
/// </summary>
public static class LeafNodeSourceExtensions
{
    public static void WriteTo(this LeafNodeSource value, TlsWriter writer)
    {
        writer.WriteUint8((byte)value);
    }

    public static LeafNodeSource ReadLeafNodeSource(TlsReader reader)
    {
        byte raw = reader.ReadUint8();
        return raw switch
        {
            1 => LeafNodeSource.KeyPackage,
            2 => LeafNodeSource.Update,
            3 => LeafNodeSource.Commit,
            _ => throw new TlsDecodingException($"Unknown LeafNodeSource: {raw}"),
        };
    }
}
