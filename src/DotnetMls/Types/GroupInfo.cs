using DotnetMls.Codec;

namespace DotnetMls.Types;

/// <summary>
/// GroupInfo sent to new members joining via a Welcome message
/// (RFC 9420 Section 12.4.3.1).
/// </summary>
public sealed class GroupInfo
{
    /// <summary>
    /// The group context at the time of the Welcome.
    /// </summary>
    public GroupContext GroupContext { get; set; } = new GroupContext();

    /// <summary>
    /// Extensions for this GroupInfo.
    /// </summary>
    public Extension[] Extensions { get; set; } = Array.Empty<Extension>();

    /// <summary>
    /// The MAC confirming the group state.
    /// </summary>
    public byte[] ConfirmationTag { get; set; } = Array.Empty<byte>();

    /// <summary>
    /// The leaf index of the member who created this GroupInfo.
    /// </summary>
    public uint Signer { get; set; }

    /// <summary>
    /// The signature over the GroupInfo content.
    /// </summary>
    public byte[] Signature { get; set; } = Array.Empty<byte>();

    public GroupInfo()
    {
    }

    public void WriteTo(TlsWriter writer)
    {
        GroupContext.WriteTo(writer);

        writer.WriteVectorV(inner =>
        {
            foreach (var ext in Extensions)
            {
                ext.WriteTo(inner);
            }
        });

        writer.WriteOpaqueV(ConfirmationTag);
        writer.WriteUint32(Signer);
        writer.WriteOpaqueV(Signature);
    }

    public static GroupInfo ReadFrom(TlsReader reader)
    {
        var gi = new GroupInfo();
        gi.GroupContext = GroupContext.ReadFrom(reader);

        byte[] extData = reader.ReadOpaqueV();
        gi.Extensions = ReadExtensionList(extData);

        gi.ConfirmationTag = reader.ReadOpaqueV();
        gi.Signer = reader.ReadUint32();
        gi.Signature = reader.ReadOpaqueV();
        return gi;
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
