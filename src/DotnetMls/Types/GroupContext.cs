using DotnetMls.Codec;

namespace DotnetMls.Types;

/// <summary>
/// The group context that binds all group state together (RFC 9420 Section 8).
/// </summary>
public sealed class GroupContext
{
    /// <summary>
    /// The protocol version. Must be <see cref="ProtocolVersion.Mls10"/>.
    /// </summary>
    public ushort Version { get; set; } = ProtocolVersion.Mls10;

    /// <summary>
    /// The cipher suite used by the group.
    /// </summary>
    public ushort CipherSuite { get; set; }

    /// <summary>
    /// The unique group identifier.
    /// </summary>
    public byte[] GroupId { get; set; } = Array.Empty<byte>();

    /// <summary>
    /// The current epoch number.
    /// </summary>
    public ulong Epoch { get; set; }

    /// <summary>
    /// The hash of the ratchet tree.
    /// </summary>
    public byte[] TreeHash { get; set; } = Array.Empty<byte>();

    /// <summary>
    /// The confirmed transcript hash up to the current epoch.
    /// </summary>
    public byte[] ConfirmedTranscriptHash { get; set; } = Array.Empty<byte>();

    /// <summary>
    /// Group-level extensions.
    /// </summary>
    public Extension[] Extensions { get; set; } = Array.Empty<Extension>();

    public GroupContext()
    {
    }

    public void WriteTo(TlsWriter writer)
    {
        writer.WriteUint16(Version);
        writer.WriteUint16(CipherSuite);
        writer.WriteOpaqueV(GroupId);
        writer.WriteUint64(Epoch);
        writer.WriteOpaqueV(TreeHash);
        writer.WriteOpaqueV(ConfirmedTranscriptHash);

        writer.WriteVectorV(inner =>
        {
            foreach (var ext in Extensions)
            {
                ext.WriteTo(inner);
            }
        });
    }

    public static GroupContext ReadFrom(TlsReader reader)
    {
        var ctx = new GroupContext();
        ctx.Version = reader.ReadUint16();
        ctx.CipherSuite = reader.ReadUint16();
        ctx.GroupId = reader.ReadOpaqueV();
        ctx.Epoch = reader.ReadUint64();
        ctx.TreeHash = reader.ReadOpaqueV();
        ctx.ConfirmedTranscriptHash = reader.ReadOpaqueV();

        byte[] extData = reader.ReadOpaqueV();
        ctx.Extensions = ReadExtensionList(extData);

        return ctx;
    }

    private static Extension[] ReadExtensionList(byte[] data)
    {
        if (data.Length == 0)
        {
            return Array.Empty<Extension>();
        }

        var extReader = new TlsReader(data);
        var list = new List<Extension>();
        while (!extReader.IsEmpty)
        {
            list.Add(Extension.ReadFrom(extReader));
        }
        return list.ToArray();
    }
}
