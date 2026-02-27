using DotnetMls.Codec;

namespace DotnetMls.Types;

/// <summary>
/// Identifies the sender of a framed message (RFC 9420 Section 6).
/// </summary>
public sealed class Sender
{
    /// <summary>
    /// The type of sender.
    /// </summary>
    public SenderType SenderType { get; set; }

    /// <summary>
    /// The leaf index within the ratchet tree. Only meaningful when
    /// <see cref="SenderType"/> is <see cref="Types.SenderType.Member"/>.
    /// </summary>
    public uint LeafIndex { get; set; }

    public Sender()
    {
    }

    public Sender(SenderType senderType, uint leafIndex = 0)
    {
        SenderType = senderType;
        LeafIndex = leafIndex;
    }

    public void WriteTo(TlsWriter writer)
    {
        writer.WriteUint8((byte)SenderType);
        if (SenderType == SenderType.Member)
        {
            writer.WriteUint32(LeafIndex);
        }
    }

    public static Sender ReadFrom(TlsReader reader)
    {
        var senderType = SenderTypeExtensions.ReadSenderType(reader);
        uint leafIndex = 0;
        if (senderType == SenderType.Member)
        {
            leafIndex = reader.ReadUint32();
        }
        return new Sender(senderType, leafIndex);
    }
}
