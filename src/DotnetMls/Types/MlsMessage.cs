using DotnetMls.Codec;

namespace DotnetMls.Types;

/// <summary>
/// The top-level MLS message envelope (RFC 9420 Section 6).
/// Wraps a specific message body with version and wire format tags.
/// </summary>
public sealed class MlsMessage
{
    /// <summary>
    /// The protocol version. Must be <see cref="ProtocolVersion.Mls10"/>.
    /// </summary>
    public ushort Version { get; set; } = ProtocolVersion.Mls10;

    /// <summary>
    /// The wire format identifying the type of the body.
    /// </summary>
    public WireFormat WireFormat { get; set; }

    /// <summary>
    /// The message body. Must be one of:
    /// <see cref="PublicMessage"/>, <see cref="PrivateMessage"/>,
    /// <see cref="Welcome"/>, <see cref="GroupInfo"/>, or <see cref="KeyPackage"/>.
    /// </summary>
    public object Body { get; set; } = null!;

    public MlsMessage()
    {
    }

    public MlsMessage(WireFormat wireFormat, object body)
    {
        WireFormat = wireFormat;
        Body = body;
    }

    public void WriteTo(TlsWriter writer)
    {
        writer.WriteUint16(Version);
        writer.WriteUint16((ushort)WireFormat);

        switch (WireFormat)
        {
            case WireFormat.MlsPublicMessage:
                ((PublicMessage)Body).WriteTo(writer);
                break;
            case WireFormat.MlsPrivateMessage:
                ((PrivateMessage)Body).WriteTo(writer);
                break;
            case WireFormat.MlsWelcome:
                ((Welcome)Body).WriteTo(writer);
                break;
            case WireFormat.MlsGroupInfo:
                ((GroupInfo)Body).WriteTo(writer);
                break;
            case WireFormat.MlsKeyPackage:
                ((KeyPackage)Body).WriteTo(writer);
                break;
            default:
                throw new InvalidOperationException($"Cannot serialize MlsMessage with WireFormat: {WireFormat}");
        }
    }

    public static MlsMessage ReadFrom(TlsReader reader)
    {
        ushort version = reader.ReadUint16();
        if (version != ProtocolVersion.Mls10)
        {
            throw new TlsDecodingException($"Unsupported MLS version: 0x{version:X4}");
        }

        var wireFormat = WireFormatExtensions.ReadWireFormat(reader);

        object body = wireFormat switch
        {
            WireFormat.MlsPublicMessage => PublicMessage.ReadFrom(reader),
            WireFormat.MlsPrivateMessage => PrivateMessage.ReadFrom(reader),
            WireFormat.MlsWelcome => Welcome.ReadFrom(reader),
            WireFormat.MlsGroupInfo => GroupInfo.ReadFrom(reader),
            WireFormat.MlsKeyPackage => KeyPackage.ReadFrom(reader),
            _ => throw new TlsDecodingException($"Cannot deserialize MlsMessage with WireFormat: {wireFormat}"),
        };

        return new MlsMessage { Version = version, WireFormat = wireFormat, Body = body };
    }
}
