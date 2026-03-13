using DotnetMls.Codec;

namespace DotnetMls.Types;

/// <summary>
/// The content of a framed MLS message before authentication
/// (RFC 9420 Section 6).
/// </summary>
public sealed class FramedContent
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
    /// The sender of this message.
    /// </summary>
    public Sender Sender { get; set; } = new Sender();

    /// <summary>
    /// Application-level authenticated data.
    /// </summary>
    public byte[] AuthenticatedData { get; set; } = Array.Empty<byte>();

    /// <summary>
    /// The type of content carried in this frame.
    /// </summary>
    public ContentType ContentType { get; set; }

    /// <summary>
    /// The raw content bytes (application data, serialized proposal, or serialized commit).
    /// </summary>
    public byte[] Content { get; set; } = Array.Empty<byte>();

    public FramedContent()
    {
    }

    public void WriteTo(TlsWriter writer)
    {
        writer.WriteOpaqueV(GroupId);
        writer.WriteUint64(Epoch);
        Sender.WriteTo(writer);
        writer.WriteOpaqueV(AuthenticatedData);
        writer.WriteUint8((byte)ContentType);

        // RFC 9420 §6: application_data is opaque<V>, but Proposal and Commit
        // are raw TLS structs (no VarInt prefix).
        if (ContentType == ContentType.Application)
            writer.WriteOpaqueV(Content);
        else
            writer.WriteBytes(Content);
    }

    public static FramedContent ReadFrom(TlsReader reader)
    {
        var fc = new FramedContent();
        fc.GroupId = reader.ReadOpaqueV();
        fc.Epoch = reader.ReadUint64();
        fc.Sender = Sender.ReadFrom(reader);
        fc.AuthenticatedData = reader.ReadOpaqueV();
        fc.ContentType = ContentTypeExtensions.ReadContentType(reader);

        // RFC 9420 §6: application_data is opaque<V>, but Proposal and Commit
        // are raw TLS structs parsed by their ReadFrom methods.
        if (fc.ContentType == ContentType.Application)
        {
            fc.Content = reader.ReadOpaqueV();
        }
        else
        {
            int startPos = reader.Position;
            if (fc.ContentType == ContentType.Proposal)
                Proposal.ReadFrom(reader);
            else
                Commit.ReadFrom(reader);
            fc.Content = reader.GetRange(startPos);
        }
        return fc;
    }
}
