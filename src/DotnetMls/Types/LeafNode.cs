using DotnetMls.Codec;

namespace DotnetMls.Types;

/// <summary>
/// A leaf node in the ratchet tree (RFC 9420 Section 7.2).
/// </summary>
public sealed class LeafNode
{
    /// <summary>
    /// The HPKE public encryption key for this leaf.
    /// </summary>
    public byte[] EncryptionKey { get; set; } = Array.Empty<byte>();

    /// <summary>
    /// The signature public key for this leaf.
    /// </summary>
    public byte[] SignatureKey { get; set; } = Array.Empty<byte>();

    /// <summary>
    /// The credential associated with this leaf.
    /// </summary>
    public Credential Credential { get; set; } = new BasicCredential();

    /// <summary>
    /// The capabilities advertised by this leaf.
    /// </summary>
    public Capabilities Capabilities { get; set; } = new Capabilities();

    /// <summary>
    /// How this leaf node was created.
    /// </summary>
    public LeafNodeSource Source { get; set; }

    /// <summary>
    /// The lifetime of the leaf node. Only present when
    /// <see cref="Source"/> is <see cref="LeafNodeSource.KeyPackage"/>.
    /// </summary>
    public Lifetime? Lifetime { get; set; }

    /// <summary>
    /// The parent hash for commit-sourced leaf nodes (RFC 9420 §7.9.2).
    /// Present when <see cref="Source"/> is <see cref="LeafNodeSource.Commit"/>.
    /// </summary>
    public byte[] ParentHash { get; set; } = Array.Empty<byte>();

    /// <summary>
    /// Extensions associated with this leaf node.
    /// </summary>
    public Extension[] Extensions { get; set; } = Array.Empty<Extension>();

    /// <summary>
    /// The signature over the leaf node content.
    /// </summary>
    public byte[] Signature { get; set; } = Array.Empty<byte>();

    public LeafNode()
    {
    }

    public void WriteTo(TlsWriter writer)
    {
        writer.WriteOpaqueV(EncryptionKey);
        writer.WriteOpaqueV(SignatureKey);
        Credential.WriteTo(writer);
        Capabilities.WriteTo(writer);
        writer.WriteUint8((byte)Source);

        if (Source == LeafNodeSource.KeyPackage)
        {
            Lifetime!.WriteTo(writer);
        }
        else if (Source == LeafNodeSource.Commit)
        {
            writer.WriteOpaqueV(ParentHash);
        }

        writer.WriteVectorV(inner =>
        {
            foreach (var ext in Extensions)
            {
                ext.WriteTo(inner);
            }
        });

        writer.WriteOpaqueV(Signature);
    }

    public static LeafNode ReadFrom(TlsReader reader)
    {
        var node = new LeafNode();
        node.EncryptionKey = reader.ReadOpaqueV();
        node.SignatureKey = reader.ReadOpaqueV();
        node.Credential = Credential.ReadFrom(reader);
        node.Capabilities = Capabilities.ReadFrom(reader);
        node.Source = LeafNodeSourceExtensions.ReadLeafNodeSource(reader);

        if (node.Source == LeafNodeSource.KeyPackage)
        {
            node.Lifetime = Types.Lifetime.ReadFrom(reader);
        }
        else if (node.Source == LeafNodeSource.Commit)
        {
            node.ParentHash = reader.ReadOpaqueV();
        }

        byte[] extData = reader.ReadOpaqueV();
        node.Extensions = ReadExtensionList(extData);

        node.Signature = reader.ReadOpaqueV();
        return node;
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
