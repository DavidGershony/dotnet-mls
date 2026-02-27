using DotnetMls.Codec;

namespace DotnetMls.Types;

/// <summary>
/// A KeyPackage used to add a new member to a group (RFC 9420 Section 10).
/// </summary>
public sealed class KeyPackage
{
    /// <summary>
    /// The protocol version. Must be <see cref="ProtocolVersion.Mls10"/>.
    /// </summary>
    public ushort Version { get; set; } = ProtocolVersion.Mls10;

    /// <summary>
    /// The cipher suite identifier.
    /// </summary>
    public ushort CipherSuite { get; set; }

    /// <summary>
    /// The HPKE init key (public key for initial key exchange).
    /// </summary>
    public byte[] InitKey { get; set; } = Array.Empty<byte>();

    /// <summary>
    /// The leaf node describing this member.
    /// </summary>
    public LeafNode LeafNode { get; set; } = new LeafNode();

    /// <summary>
    /// Extensions for this KeyPackage.
    /// </summary>
    public Extension[] Extensions { get; set; } = Array.Empty<Extension>();

    /// <summary>
    /// Signature over the KeyPackage content.
    /// </summary>
    public byte[] Signature { get; set; } = Array.Empty<byte>();

    public KeyPackage()
    {
    }

    public void WriteTo(TlsWriter writer)
    {
        writer.WriteUint16(Version);
        writer.WriteUint16(CipherSuite);
        writer.WriteOpaqueV(InitKey);
        LeafNode.WriteTo(writer);

        writer.WriteVectorV(inner =>
        {
            foreach (var ext in Extensions)
            {
                ext.WriteTo(inner);
            }
        });

        writer.WriteOpaqueV(Signature);
    }

    public static KeyPackage ReadFrom(TlsReader reader)
    {
        var kp = new KeyPackage();
        kp.Version = reader.ReadUint16();
        kp.CipherSuite = reader.ReadUint16();
        kp.InitKey = reader.ReadOpaqueV();
        kp.LeafNode = LeafNode.ReadFrom(reader);

        byte[] extData = reader.ReadOpaqueV();
        kp.Extensions = ReadExtensionList(extData);

        kp.Signature = reader.ReadOpaqueV();
        return kp;
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
