using DotnetMls.Codec;

namespace DotnetMls.Types;

/// <summary>
/// Wire format identifiers for MLS messages (RFC 9420 Section 6).
/// </summary>
public enum WireFormat : ushort
{
    Reserved = 0,
    MlsPublicMessage = 1,
    MlsPrivateMessage = 2,
    MlsWelcome = 3,
    MlsGroupInfo = 4,
    MlsKeyPackage = 5,
}

/// <summary>
/// TLS serialization helpers for <see cref="WireFormat"/>.
/// </summary>
public static class WireFormatExtensions
{
    public static void WriteTo(this WireFormat value, TlsWriter writer)
    {
        writer.WriteUint16((ushort)value);
    }

    public static WireFormat ReadWireFormat(TlsReader reader)
    {
        ushort raw = reader.ReadUint16();
        return raw switch
        {
            0 => WireFormat.Reserved,
            1 => WireFormat.MlsPublicMessage,
            2 => WireFormat.MlsPrivateMessage,
            3 => WireFormat.MlsWelcome,
            4 => WireFormat.MlsGroupInfo,
            5 => WireFormat.MlsKeyPackage,
            _ => throw new TlsDecodingException($"Unknown WireFormat: {raw}"),
        };
    }
}
