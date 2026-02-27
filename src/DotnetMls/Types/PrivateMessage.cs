using DotnetMls.Codec;

namespace DotnetMls.Types;

/// <summary>
/// A private (encrypted) MLS message (RFC 9420 Section 6.3).
/// </summary>
public sealed class PrivateMessage
{
    /// <summary>
    /// The group identifier.
    /// </summary>
    public byte[] GroupId { get; set; } = Array.Empty<byte>();

    /// <summary>
    /// The epoch in which this message was sent.
    /// </summary>
    public ulong Epoch { get; set; }

    /// <summary>
    /// The content type of the encrypted payload.
    /// </summary>
    public ContentType ContentType { get; set; }

    /// <summary>
    /// Application-level authenticated data.
    /// </summary>
    public byte[] AuthenticatedData { get; set; } = Array.Empty<byte>();

    /// <summary>
    /// The encrypted sender data (contains generation and leaf index).
    /// </summary>
    public byte[] EncryptedSenderData { get; set; } = Array.Empty<byte>();

    /// <summary>
    /// The AEAD ciphertext containing the content and auth data.
    /// </summary>
    public byte[] Ciphertext { get; set; } = Array.Empty<byte>();

    public PrivateMessage()
    {
    }

    public void WriteTo(TlsWriter writer)
    {
        writer.WriteOpaqueV(GroupId);
        writer.WriteUint64(Epoch);
        writer.WriteUint8((byte)ContentType);
        writer.WriteOpaqueV(AuthenticatedData);
        writer.WriteOpaqueV(EncryptedSenderData);
        writer.WriteOpaqueV(Ciphertext);
    }

    public static PrivateMessage ReadFrom(TlsReader reader)
    {
        var msg = new PrivateMessage();
        msg.GroupId = reader.ReadOpaqueV();
        msg.Epoch = reader.ReadUint64();
        msg.ContentType = ContentTypeExtensions.ReadContentType(reader);
        msg.AuthenticatedData = reader.ReadOpaqueV();
        msg.EncryptedSenderData = reader.ReadOpaqueV();
        msg.Ciphertext = reader.ReadOpaqueV();
        return msg;
    }
}
