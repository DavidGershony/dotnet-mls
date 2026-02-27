using DotnetMls.Codec;

namespace DotnetMls.Types;

/// <summary>
/// Distinguishes between inline proposals and proposal references in a Commit
/// (RFC 9420 Section 12.4).
/// </summary>
public enum ProposalOrRefType : byte
{
    Proposal = 1,
    Reference = 2,
}

/// <summary>
/// Either an inline proposal or a reference to a previously sent proposal
/// (RFC 9420 Section 12.4).
/// </summary>
public abstract class ProposalOrRef
{
    /// <summary>
    /// Whether this is an inline proposal or a reference.
    /// </summary>
    public abstract ProposalOrRefType Type { get; }

    /// <summary>
    /// Serializes this value to the writer.
    /// </summary>
    public abstract void WriteTo(TlsWriter writer);

    /// <summary>
    /// Deserializes from the reader.
    /// </summary>
    public static ProposalOrRef ReadFrom(TlsReader reader)
    {
        byte rawType = reader.ReadUint8();
        return rawType switch
        {
            (byte)ProposalOrRefType.Proposal => InlineProposal.ReadBody(reader),
            (byte)ProposalOrRefType.Reference => ProposalReference.ReadBody(reader),
            _ => throw new TlsDecodingException($"Unknown ProposalOrRefType: {rawType}"),
        };
    }
}

/// <summary>
/// An inline proposal embedded directly in a Commit.
/// </summary>
public sealed class InlineProposal : ProposalOrRef
{
    public override ProposalOrRefType Type => ProposalOrRefType.Proposal;

    /// <summary>
    /// The inline proposal.
    /// </summary>
    public Proposal Proposal { get; set; } = null!;

    public InlineProposal()
    {
    }

    public InlineProposal(Proposal proposal)
    {
        Proposal = proposal;
    }

    public override void WriteTo(TlsWriter writer)
    {
        writer.WriteUint8((byte)Type);
        Proposal.WriteTo(writer);
    }

    internal static InlineProposal ReadBody(TlsReader reader)
    {
        var proposal = Proposal.ReadFrom(reader);
        return new InlineProposal(proposal);
    }
}

/// <summary>
/// A reference (hash) to a previously sent proposal.
/// </summary>
public sealed class ProposalReference : ProposalOrRef
{
    public override ProposalOrRefType Type => ProposalOrRefType.Reference;

    /// <summary>
    /// The proposal reference hash.
    /// </summary>
    public byte[] Reference { get; set; } = Array.Empty<byte>();

    public ProposalReference()
    {
    }

    public ProposalReference(byte[] reference)
    {
        Reference = reference;
    }

    public override void WriteTo(TlsWriter writer)
    {
        writer.WriteUint8((byte)Type);
        writer.WriteOpaqueV(Reference);
    }

    internal static ProposalReference ReadBody(TlsReader reader)
    {
        byte[] reference = reader.ReadOpaqueV();
        return new ProposalReference(reference);
    }
}
