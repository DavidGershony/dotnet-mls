using DotnetMls.Codec;

namespace DotnetMls.Tree;

/// <summary>
/// A parent node in the ratchet tree (RFC 9420 Section 7.1).
///
/// struct {
///     HPKEPublicKey encryption_key;
///     opaque parent_hash&lt;V&gt;;
///     uint32 unmerged_leaves&lt;V&gt;;
/// } ParentNode;
/// </summary>
public sealed class ParentNode
{
    /// <summary>
    /// The HPKE public encryption key for this parent node.
    /// </summary>
    public byte[] EncryptionKey { get; set; } = Array.Empty<byte>();

    /// <summary>
    /// The parent hash value binding this node to its parent.
    /// Empty if this is the root or not yet computed.
    /// </summary>
    public byte[] ParentHash { get; set; } = Array.Empty<byte>();

    /// <summary>
    /// Leaf indices whose keys have not been merged into this node.
    /// These are leaves that were added to the group after the last
    /// UpdatePath that covered this node.
    /// </summary>
    public List<uint> UnmergedLeaves { get; set; } = new();

    /// <summary>
    /// The HPKE private key for this node, if known by the local member.
    /// Not serialized in the TLS encoding; kept only in local state.
    /// </summary>
    public byte[]? PrivateKey { get; set; }

    public ParentNode()
    {
    }

    public ParentNode(byte[] encryptionKey, byte[] parentHash, List<uint> unmergedLeaves)
    {
        EncryptionKey = encryptionKey;
        ParentHash = parentHash;
        UnmergedLeaves = unmergedLeaves;
    }

    /// <summary>
    /// Serializes this parent node using TLS encoding:
    /// opaqueV encryption_key + opaqueV parent_hash + vectorV of uint32 unmerged_leaves.
    /// </summary>
    public void WriteTo(TlsWriter writer)
    {
        writer.WriteOpaqueV(EncryptionKey);
        writer.WriteOpaqueV(ParentHash);
        writer.WriteVectorV(inner =>
        {
            foreach (uint leaf in UnmergedLeaves)
            {
                inner.WriteUint32(leaf);
            }
        });
    }

    /// <summary>
    /// Deserializes a parent node from TLS encoding.
    /// </summary>
    public static ParentNode ReadFrom(TlsReader reader)
    {
        byte[] encryptionKey = reader.ReadOpaqueV();
        byte[] parentHash = reader.ReadOpaqueV();

        byte[] unmergedData = reader.ReadOpaqueV();
        var unmergedLeaves = new List<uint>();
        if (unmergedData.Length > 0)
        {
            var sub = new TlsReader(unmergedData);
            while (!sub.IsEmpty)
            {
                unmergedLeaves.Add(sub.ReadUint32());
            }
        }

        return new ParentNode(encryptionKey, parentHash, unmergedLeaves);
    }

    /// <summary>
    /// Creates a deep copy of this parent node.
    /// </summary>
    public ParentNode Clone()
    {
        return new ParentNode(
            (byte[])EncryptionKey.Clone(),
            (byte[])ParentHash.Clone(),
            new List<uint>(UnmergedLeaves))
        {
            PrivateKey = PrivateKey != null ? (byte[])PrivateKey.Clone() : null
        };
    }
}
