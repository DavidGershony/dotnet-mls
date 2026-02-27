using DotnetMls.Codec;

namespace DotnetMls.Types;

/// <summary>
/// A public (plaintext) MLS message (RFC 9420 Section 6.2).
/// </summary>
public sealed class PublicMessage
{
    /// <summary>
    /// The framed content of the message.
    /// </summary>
    public FramedContent Content { get; set; } = new FramedContent();

    /// <summary>
    /// The authentication data (signature and optional confirmation tag).
    /// </summary>
    public FramedContentAuthData Auth { get; set; } = new FramedContentAuthData();

    /// <summary>
    /// The membership tag. Present only for messages from a member sender
    /// with content type other than Proposal.
    /// </summary>
    public byte[]? MembershipTag { get; set; }

    public PublicMessage()
    {
    }

    public PublicMessage(FramedContent content, FramedContentAuthData auth, byte[]? membershipTag)
    {
        Content = content;
        Auth = auth;
        MembershipTag = membershipTag;
    }

    public void WriteTo(TlsWriter writer)
    {
        Content.WriteTo(writer);
        Auth.WriteTo(writer, Content.ContentType);

        // membership_tag is present for member senders on non-proposal content
        if (Content.Sender.SenderType == SenderType.Member &&
            Content.ContentType != ContentType.Proposal)
        {
            writer.WriteOpaqueV(MembershipTag ?? Array.Empty<byte>());
        }
    }

    public static PublicMessage ReadFrom(TlsReader reader)
    {
        var content = FramedContent.ReadFrom(reader);
        var auth = FramedContentAuthData.ReadFrom(reader, content.ContentType);

        byte[]? membershipTag = null;
        if (content.Sender.SenderType == SenderType.Member &&
            content.ContentType != ContentType.Proposal)
        {
            membershipTag = reader.ReadOpaqueV();
        }

        return new PublicMessage(content, auth, membershipTag);
    }
}
