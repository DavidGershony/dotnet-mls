using DotnetMls.Codec;

namespace DotnetMls.Types;

/// <summary>
/// Abstract base class for MLS proposals (RFC 9420 Section 12).
/// </summary>
public abstract class Proposal
{
    /// <summary>
    /// The proposal type.
    /// </summary>
    public abstract ProposalType ProposalType { get; }

    /// <summary>
    /// Serializes this proposal (including the type tag) to the writer.
    /// </summary>
    public abstract void WriteTo(TlsWriter writer);

    /// <summary>
    /// Serializes only the proposal body (without the type tag).
    /// </summary>
    protected abstract void WriteBody(TlsWriter writer);

    /// <summary>
    /// Deserializes a proposal from the reader.
    /// </summary>
    public static Proposal ReadFrom(TlsReader reader)
    {
        ushort rawType = reader.ReadUint16();
        return rawType switch
        {
            (ushort)ProposalType.Add => AddProposal.ReadBody(reader),
            (ushort)ProposalType.Update => UpdateProposal.ReadBody(reader),
            (ushort)ProposalType.Remove => RemoveProposal.ReadBody(reader),
            (ushort)ProposalType.PreSharedKey => PreSharedKeyProposal.ReadBody(reader),
            (ushort)ProposalType.ReInit => ReInitProposal.ReadBody(reader),
            (ushort)ProposalType.ExternalInit => ExternalInitProposal.ReadBody(reader),
            (ushort)ProposalType.GroupContextExtensions => GroupContextExtensionsProposal.ReadBody(reader),
            _ => throw new TlsDecodingException($"Unknown ProposalType: {rawType}"),
        };
    }
}

/// <summary>
/// An Add proposal that adds a new member via a KeyPackage (RFC 9420 Section 12.1.1).
/// </summary>
public sealed class AddProposal : Proposal
{
    public override ProposalType ProposalType => ProposalType.Add;

    /// <summary>
    /// The KeyPackage of the member to add.
    /// </summary>
    public KeyPackage KeyPackage { get; set; } = new KeyPackage();

    public AddProposal()
    {
    }

    public AddProposal(KeyPackage keyPackage)
    {
        KeyPackage = keyPackage;
    }

    public override void WriteTo(TlsWriter writer)
    {
        writer.WriteUint16((ushort)ProposalType);
        WriteBody(writer);
    }

    protected override void WriteBody(TlsWriter writer)
    {
        KeyPackage.WriteTo(writer);
    }

    internal static AddProposal ReadBody(TlsReader reader)
    {
        var kp = KeyPackage.ReadFrom(reader);
        return new AddProposal(kp);
    }
}

/// <summary>
/// An Update proposal that replaces the sender's leaf node (RFC 9420 Section 12.1.2).
/// </summary>
public sealed class UpdateProposal : Proposal
{
    public override ProposalType ProposalType => ProposalType.Update;

    /// <summary>
    /// The new leaf node for the sender.
    /// </summary>
    public LeafNode LeafNode { get; set; } = new LeafNode();

    public UpdateProposal()
    {
    }

    public UpdateProposal(LeafNode leafNode)
    {
        LeafNode = leafNode;
    }

    public override void WriteTo(TlsWriter writer)
    {
        writer.WriteUint16((ushort)ProposalType);
        WriteBody(writer);
    }

    protected override void WriteBody(TlsWriter writer)
    {
        LeafNode.WriteTo(writer);
    }

    internal static UpdateProposal ReadBody(TlsReader reader)
    {
        var ln = LeafNode.ReadFrom(reader);
        return new UpdateProposal(ln);
    }
}

/// <summary>
/// A Remove proposal that removes a member by leaf index (RFC 9420 Section 12.1.3).
/// </summary>
public sealed class RemoveProposal : Proposal
{
    public override ProposalType ProposalType => ProposalType.Remove;

    /// <summary>
    /// The leaf index of the member to remove.
    /// </summary>
    public uint LeafIndex { get; set; }

    public RemoveProposal()
    {
    }

    public RemoveProposal(uint leafIndex)
    {
        LeafIndex = leafIndex;
    }

    public override void WriteTo(TlsWriter writer)
    {
        writer.WriteUint16((ushort)ProposalType);
        WriteBody(writer);
    }

    protected override void WriteBody(TlsWriter writer)
    {
        writer.WriteUint32(LeafIndex);
    }

    internal static RemoveProposal ReadBody(TlsReader reader)
    {
        uint leafIndex = reader.ReadUint32();
        return new RemoveProposal(leafIndex);
    }
}

/// <summary>
/// A GroupContextExtensions proposal that replaces group-level extensions
/// (RFC 9420 Section 12.1.7).
/// </summary>
public sealed class GroupContextExtensionsProposal : Proposal
{
    public override ProposalType ProposalType => ProposalType.GroupContextExtensions;

    /// <summary>
    /// The new set of group extensions.
    /// </summary>
    public Extension[] Extensions { get; set; } = Array.Empty<Extension>();

    public GroupContextExtensionsProposal()
    {
    }

    public GroupContextExtensionsProposal(Extension[] extensions)
    {
        Extensions = extensions;
    }

    public override void WriteTo(TlsWriter writer)
    {
        writer.WriteUint16((ushort)ProposalType);
        WriteBody(writer);
    }

    protected override void WriteBody(TlsWriter writer)
    {
        writer.WriteVectorV(inner =>
        {
            foreach (var ext in Extensions)
            {
                ext.WriteTo(inner);
            }
        });
    }

    internal static GroupContextExtensionsProposal ReadBody(TlsReader reader)
    {
        byte[] extData = reader.ReadOpaqueV();
        if (extData.Length == 0)
        {
            return new GroupContextExtensionsProposal(Array.Empty<Extension>());
        }

        var extReader = new TlsReader(extData);
        var list = new List<Extension>();
        while (!extReader.IsEmpty)
        {
            list.Add(Extension.ReadFrom(extReader));
        }
        return new GroupContextExtensionsProposal(list.ToArray());
    }
}

/// <summary>
/// A PreSharedKey proposal (RFC 9420 Section 12.1.4).
/// </summary>
public sealed class PreSharedKeyProposal : Proposal
{
    public override ProposalType ProposalType => ProposalType.PreSharedKey;

    public PreSharedKeyId Psk { get; set; } = new PreSharedKeyId();

    public PreSharedKeyProposal()
    {
    }

    public PreSharedKeyProposal(PreSharedKeyId psk)
    {
        Psk = psk;
    }

    public override void WriteTo(TlsWriter writer)
    {
        writer.WriteUint16((ushort)ProposalType);
        WriteBody(writer);
    }

    protected override void WriteBody(TlsWriter writer)
    {
        Psk.WriteTo(writer);
    }

    internal static PreSharedKeyProposal ReadBody(TlsReader reader)
    {
        var psk = PreSharedKeyId.ReadFrom(reader);
        return new PreSharedKeyProposal(psk);
    }
}

/// <summary>
/// A ReInit proposal (RFC 9420 Section 12.1.5).
/// </summary>
public sealed class ReInitProposal : Proposal
{
    public override ProposalType ProposalType => ProposalType.ReInit;

    public byte[] GroupId { get; set; } = Array.Empty<byte>();
    public ushort Version { get; set; }
    public ushort CipherSuite { get; set; }
    public Extension[] Extensions { get; set; } = Array.Empty<Extension>();

    public ReInitProposal()
    {
    }

    public override void WriteTo(TlsWriter writer)
    {
        writer.WriteUint16((ushort)ProposalType);
        WriteBody(writer);
    }

    protected override void WriteBody(TlsWriter writer)
    {
        writer.WriteOpaqueV(GroupId);
        writer.WriteUint16(Version);
        writer.WriteUint16(CipherSuite);
        writer.WriteVectorV(inner =>
        {
            foreach (var ext in Extensions)
            {
                ext.WriteTo(inner);
            }
        });
    }

    internal static ReInitProposal ReadBody(TlsReader reader)
    {
        var p = new ReInitProposal();
        p.GroupId = reader.ReadOpaqueV();
        p.Version = reader.ReadUint16();
        p.CipherSuite = reader.ReadUint16();

        byte[] extData = reader.ReadOpaqueV();
        if (extData.Length > 0)
        {
            var extReader = new TlsReader(extData);
            var list = new List<Extension>();
            while (!extReader.IsEmpty)
            {
                list.Add(Extension.ReadFrom(extReader));
            }
            p.Extensions = list.ToArray();
        }
        return p;
    }
}

/// <summary>
/// An ExternalInit proposal (RFC 9420 Section 12.1.6).
/// </summary>
public sealed class ExternalInitProposal : Proposal
{
    public override ProposalType ProposalType => ProposalType.ExternalInit;

    public byte[] KemOutput { get; set; } = Array.Empty<byte>();

    public ExternalInitProposal()
    {
    }

    public ExternalInitProposal(byte[] kemOutput)
    {
        KemOutput = kemOutput;
    }

    public override void WriteTo(TlsWriter writer)
    {
        writer.WriteUint16((ushort)ProposalType);
        WriteBody(writer);
    }

    protected override void WriteBody(TlsWriter writer)
    {
        writer.WriteOpaqueV(KemOutput);
    }

    internal static ExternalInitProposal ReadBody(TlsReader reader)
    {
        var kemOutput = reader.ReadOpaqueV();
        return new ExternalInitProposal(kemOutput);
    }
}
