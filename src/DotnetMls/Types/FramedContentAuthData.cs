using DotnetMls.Codec;

namespace DotnetMls.Types;

/// <summary>
/// Authentication data for a framed message: signature and optional confirmation tag
/// (RFC 9420 Section 6.1).
/// </summary>
public sealed class FramedContentAuthData
{
    /// <summary>
    /// The signature over the framed content.
    /// </summary>
    public byte[] Signature { get; set; } = Array.Empty<byte>();

    /// <summary>
    /// The confirmation tag. Only present when the content type is
    /// <see cref="ContentType.Commit"/>.
    /// </summary>
    public byte[]? ConfirmationTag { get; set; }

    public FramedContentAuthData()
    {
    }

    public FramedContentAuthData(byte[] signature, byte[]? confirmationTag)
    {
        Signature = signature;
        ConfirmationTag = confirmationTag;
    }

    /// <summary>
    /// Serializes the auth data. The <paramref name="contentType"/> determines
    /// whether the confirmation tag is written.
    /// </summary>
    public void WriteTo(TlsWriter writer, ContentType contentType)
    {
        writer.WriteOpaqueV(Signature);
        if (contentType == ContentType.Commit)
        {
            writer.WriteOpaqueV(ConfirmationTag ?? Array.Empty<byte>());
        }
    }

    /// <summary>
    /// Deserializes the auth data. The <paramref name="contentType"/> determines
    /// whether a confirmation tag is expected.
    /// </summary>
    public static FramedContentAuthData ReadFrom(TlsReader reader, ContentType contentType)
    {
        byte[] signature = reader.ReadOpaqueV();
        byte[]? confirmationTag = null;
        if (contentType == ContentType.Commit)
        {
            confirmationTag = reader.ReadOpaqueV();
        }
        return new FramedContentAuthData(signature, confirmationTag);
    }
}
