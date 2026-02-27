using DotnetMls.Codec;

namespace DotnetMls.Types;

/// <summary>
/// An UpdatePath sent as part of a Commit to update the direct path
/// (RFC 9420 Section 7.6).
/// </summary>
public sealed class UpdatePath
{
    /// <summary>
    /// The new leaf node for the committer.
    /// </summary>
    public LeafNode LeafNode { get; set; } = new LeafNode();

    /// <summary>
    /// The path nodes from the committer's leaf up to the root.
    /// </summary>
    public UpdatePathNode[] Nodes { get; set; } = Array.Empty<UpdatePathNode>();

    public UpdatePath()
    {
    }

    public UpdatePath(LeafNode leafNode, UpdatePathNode[] nodes)
    {
        LeafNode = leafNode;
        Nodes = nodes;
    }

    public void WriteTo(TlsWriter writer)
    {
        LeafNode.WriteTo(writer);

        writer.WriteVectorV(inner =>
        {
            foreach (var node in Nodes)
            {
                node.WriteTo(inner);
            }
        });
    }

    public static UpdatePath ReadFrom(TlsReader reader)
    {
        var leafNode = LeafNode.ReadFrom(reader);

        byte[] nodesData = reader.ReadOpaqueV();
        var nodes = new List<UpdatePathNode>();
        if (nodesData.Length > 0)
        {
            var nodesReader = new TlsReader(nodesData);
            while (!nodesReader.IsEmpty)
            {
                nodes.Add(UpdatePathNode.ReadFrom(nodesReader));
            }
        }

        return new UpdatePath(leafNode, nodes.ToArray());
    }
}
