using DotnetMls.Codec;

namespace DotnetMls.Types;

/// <summary>
/// The type of sender within an MLS group (RFC 9420 Section 6).
/// </summary>
public enum SenderType : byte
{
    Member = 1,
    External = 2,
    NewMemberProposal = 3,
    NewMemberCommit = 4,
}

/// <summary>
/// TLS serialization helpers for <see cref="SenderType"/>.
/// </summary>
public static class SenderTypeExtensions
{
    public static void WriteTo(this SenderType value, TlsWriter writer)
    {
        writer.WriteUint8((byte)value);
    }

    public static SenderType ReadSenderType(TlsReader reader)
    {
        byte raw = reader.ReadUint8();
        return raw switch
        {
            1 => SenderType.Member,
            2 => SenderType.External,
            3 => SenderType.NewMemberProposal,
            4 => SenderType.NewMemberCommit,
            _ => throw new TlsDecodingException($"Unknown SenderType: {raw}"),
        };
    }
}
