using DotnetMls.Codec;

namespace DotnetMls.Types;

/// <summary>
/// The type of content in a framed message (RFC 9420 Section 6).
/// </summary>
public enum ContentType : byte
{
    Application = 1,
    Proposal = 2,
    Commit = 3,
}

/// <summary>
/// TLS serialization helpers for <see cref="ContentType"/>.
/// </summary>
public static class ContentTypeExtensions
{
    public static void WriteTo(this ContentType value, TlsWriter writer)
    {
        writer.WriteUint8((byte)value);
    }

    public static ContentType ReadContentType(TlsReader reader)
    {
        byte raw = reader.ReadUint8();
        return raw switch
        {
            1 => ContentType.Application,
            2 => ContentType.Proposal,
            3 => ContentType.Commit,
            _ => throw new TlsDecodingException($"Unknown ContentType: {raw}"),
        };
    }
}
