using DotnetMls.Codec;

namespace DotnetMls.Types;

/// <summary>
/// Proposal type identifiers (RFC 9420 Section 12.4).
/// </summary>
public enum ProposalType : ushort
{
    Add = 1,
    Update = 2,
    Remove = 3,
    PreSharedKey = 4,
    ReInit = 5,
    ExternalInit = 6,
    GroupContextExtensions = 7,
}

/// <summary>
/// TLS serialization helpers for <see cref="ProposalType"/>.
/// </summary>
public static class ProposalTypeExtensions
{
    public static void WriteTo(this ProposalType value, TlsWriter writer)
    {
        writer.WriteUint16((ushort)value);
    }

    public static ProposalType ReadProposalType(TlsReader reader)
    {
        ushort raw = reader.ReadUint16();
        return raw switch
        {
            1 => ProposalType.Add,
            2 => ProposalType.Update,
            3 => ProposalType.Remove,
            4 => ProposalType.PreSharedKey,
            5 => ProposalType.ReInit,
            6 => ProposalType.ExternalInit,
            7 => ProposalType.GroupContextExtensions,
            _ => throw new TlsDecodingException($"Unknown ProposalType: {raw}"),
        };
    }
}
