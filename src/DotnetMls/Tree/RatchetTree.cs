using DotnetMls.Codec;
using DotnetMls.Crypto;
using DotnetMls.Types;

namespace DotnetMls.Tree;

/// <summary>
/// The MLS ratchet tree (RFC 9420 Section 4, 7).
///
/// Maintains the binary tree of leaf and parent nodes used for
/// TreeKEM key agreement. Supports serialization for Welcome messages,
/// tree hashing, parent hashing, and node resolution.
/// </summary>
public sealed class RatchetTree
{
    private readonly List<TreeNode?> _nodes = new();

    /// <summary>
    /// The total number of node slots in the tree.
    /// </summary>
    public int NodeCount => _nodes.Count;

    /// <summary>
    /// The number of leaf positions in the tree.
    /// </summary>
    public uint LeafCount => _nodes.Count == 0 ? 0 : (uint)((_nodes.Count + 1) / 2);

    // ---- Node access ----

    /// <summary>
    /// Gets the node at the given index, or null if the slot is blank.
    /// </summary>
    /// <param name="index">The node index.</param>
    /// <returns>The tree node, or null if blank.</returns>
    public TreeNode? GetNode(uint index)
    {
        if (index >= (uint)_nodes.Count)
            return null;
        return _nodes[(int)index];
    }

    /// <summary>
    /// Sets the node at the given index. Pass null to blank the slot.
    /// </summary>
    /// <param name="index">The node index.</param>
    /// <param name="node">The tree node to set, or null to blank the slot.</param>
    public void SetNode(uint index, TreeNode? node)
    {
        EnsureCapacity(index);
        _nodes[(int)index] = node;
    }

    // ---- Leaf operations ----

    /// <summary>
    /// Gets the leaf node data at the given leaf index.
    /// Returns null if the leaf slot is blank or unoccupied.
    /// </summary>
    /// <param name="leafIndex">The leaf index (0-based among leaves).</param>
    /// <returns>The leaf node data, or null.</returns>
    public LeafNode? GetLeaf(uint leafIndex)
    {
        uint nodeIndex = TreeMath.LeafToNode(leafIndex);
        var node = GetNode(nodeIndex);
        if (node is TreeNode.Leaf leaf)
            return leaf.Value;
        return null;
    }

    /// <summary>
    /// Sets the leaf node data at the given leaf index.
    /// Pass null to blank the leaf.
    /// </summary>
    /// <param name="leafIndex">The leaf index (0-based among leaves).</param>
    /// <param name="leafNode">The leaf node data, or null to blank.</param>
    public void SetLeaf(uint leafIndex, LeafNode? leafNode)
    {
        uint nodeIndex = TreeMath.LeafToNode(leafIndex);
        if (leafNode != null)
            SetNode(nodeIndex, new TreeNode.Leaf(leafNode));
        else
            SetNode(nodeIndex, new TreeNode.Leaf(null));
    }

    /// <summary>
    /// Gets the parent node data at the given node index.
    /// Returns null if the parent slot is blank.
    /// </summary>
    /// <param name="nodeIndex">The node index (must be odd / a parent position).</param>
    /// <returns>The parent node data, or null.</returns>
    public ParentNode? GetParent(uint nodeIndex)
    {
        var node = GetNode(nodeIndex);
        if (node is TreeNode.Parent parent)
            return parent.Value;
        return null;
    }

    /// <summary>
    /// Sets the parent node data at the given node index.
    /// Pass null to blank the parent.
    /// </summary>
    /// <param name="nodeIndex">The node index (must be odd / a parent position).</param>
    /// <param name="parentNode">The parent node data, or null to blank.</param>
    public void SetParent(uint nodeIndex, ParentNode? parentNode)
    {
        if (parentNode != null)
            SetNode(nodeIndex, new TreeNode.Parent(parentNode));
        else
            SetNode(nodeIndex, new TreeNode.Parent(null));
    }

    // ---- Add / remove leaves ----

    /// <summary>
    /// Adds a new leaf to the tree. If there is an empty leaf slot, it is reused.
    /// Otherwise, the tree is extended with a new leaf and the necessary parent node.
    /// </summary>
    /// <param name="leaf">The leaf node to add.</param>
    /// <returns>The leaf index (0-based among leaves) of the new leaf.</returns>
    public uint AddLeaf(LeafNode leaf)
    {
        // Try to find an empty slot first
        uint? emptySlot = FindEmptyLeaf();
        if (emptySlot.HasValue)
        {
            SetLeaf(emptySlot.Value, leaf);
            return emptySlot.Value;
        }

        // Extend the tree
        if (_nodes.Count == 0)
        {
            // First leaf
            _nodes.Add(new TreeNode.Leaf(leaf));
            return 0;
        }

        // Add a blank parent node and a new leaf
        _nodes.Add(new TreeNode.Parent(null)); // parent at odd index
        _nodes.Add(new TreeNode.Leaf(leaf));    // leaf at even index

        return LeafCount - 1;
    }

    /// <summary>
    /// Blanks a leaf and all parent nodes on its direct path.
    /// Per RFC 9420 Section 7.7, removing a member blanks their leaf and
    /// all nodes on the direct path.
    /// </summary>
    /// <param name="leafIndex">The leaf index to blank.</param>
    public void BlankLeaf(uint leafIndex)
    {
        // Blank the leaf
        SetNode(TreeMath.LeafToNode(leafIndex), new TreeNode.Leaf(null));

        // Blank all parent nodes on the direct path
        var directPath = TreeMath.DirectPath(leafIndex, LeafCount);
        foreach (uint nodeIndex in directPath)
        {
            SetNode(nodeIndex, new TreeNode.Parent(null));
        }

        // Trim trailing blank nodes from the tree
        TrimTree();
    }

    /// <summary>
    /// Finds the first empty (blank) leaf slot in the tree.
    /// </summary>
    /// <returns>The leaf index of the first blank leaf, or null if none exist.</returns>
    public uint? FindEmptyLeaf()
    {
        for (uint i = 0; i < LeafCount; i++)
        {
            uint nodeIndex = TreeMath.LeafToNode(i);
            var node = GetNode(nodeIndex);
            if (node == null || (node is TreeNode.Leaf leafNode && leafNode.Value == null))
                return i;
        }
        return null;
    }

    // ---- Resolution ----

    /// <summary>
    /// Computes the resolution of a node per RFC 9420 Section 4.2.
    ///
    /// The resolution of a node is defined as follows:
    /// - resolution(blank leaf) = empty set
    /// - resolution(non-blank leaf) = { leaf }
    /// - resolution(blank parent) = resolution(left child) | resolution(right child)
    /// - resolution(non-blank parent) = { parent } | unmerged_leaves(parent)
    ///
    /// Returns node indices of the nodes in the resolution.
    /// </summary>
    /// <param name="nodeIndex">The node index to resolve.</param>
    /// <returns>A list of node indices forming the resolution.</returns>
    public List<uint> Resolution(uint nodeIndex)
    {
        var result = new List<uint>();
        ResolveInto(nodeIndex, result);
        return result;
    }

    private void ResolveInto(uint nodeIndex, List<uint> result)
    {
        var node = GetNode(nodeIndex);

        if (TreeMath.IsLeaf(nodeIndex))
        {
            // Leaf node
            if (node is TreeNode.Leaf leaf && leaf.Value != null)
            {
                result.Add(nodeIndex);
            }
            // Blank leaf: add nothing
            return;
        }

        // Parent node
        if (node is TreeNode.Parent parent && parent.Value != null)
        {
            // Non-blank parent: add itself plus unmerged leaves
            result.Add(nodeIndex);
            foreach (uint unmergedLeaf in parent.Value.UnmergedLeaves)
            {
                result.Add(TreeMath.LeafToNode(unmergedLeaf));
            }
            return;
        }

        // Blank parent: recurse into children
        uint nodeCount = (uint)_nodes.Count;
        if (nodeCount == 0)
            return;

        uint left = TreeMath.Left(nodeIndex);
        uint right = TreeMath.Right(nodeIndex);

        // Right child might be beyond tree bounds in a truncated tree
        ResolveInto(left, result);
        if (right < nodeCount)
        {
            ResolveInto(right, result);
        }
    }

    // ---- Tree hash (RFC 9420 Section 7.8) ----

    /// <summary>
    /// Computes the tree hash of a subtree rooted at the given node index.
    /// Per RFC 9420 Section 7.8:
    ///
    /// For leaf nodes:
    ///   TreeHashInput = uint8(1) || optional leaf_node
    ///   tree_hash = Hash(TreeHashInput)
    ///
    /// For parent nodes:
    ///   TreeHashInput = uint8(2) || optional parent_node || left_hash || right_hash
    ///   tree_hash = Hash(TreeHashInput)
    /// </summary>
    /// <param name="cs">The cipher suite for hashing.</param>
    /// <param name="nodeIndex">The root of the subtree to hash.</param>
    /// <returns>The tree hash bytes.</returns>
    public byte[] ComputeTreeHash(ICipherSuite cs, uint nodeIndex)
    {
        if (TreeMath.IsLeaf(nodeIndex))
        {
            return ComputeLeafTreeHash(cs, nodeIndex);
        }
        else
        {
            return ComputeParentTreeHash(cs, nodeIndex);
        }
    }

    private byte[] ComputeLeafTreeHash(ICipherSuite cs, uint nodeIndex)
    {
        // TreeHashInput for leaf:
        //   uint8 node_type = 1 (leaf)
        //   optional<LeafNode> leaf_node
        var input = TlsCodec.Serialize(writer =>
        {
            writer.WriteUint8(1); // leaf node type

            var node = GetNode(nodeIndex);
            if (node is TreeNode.Leaf leaf && leaf.Value != null)
            {
                writer.WriteUint8(1); // present
                leaf.Value.WriteTo(writer);
            }
            else
            {
                writer.WriteUint8(0); // absent (blank)
            }
        });

        return cs.Hash(input);
    }

    private byte[] ComputeParentTreeHash(ICipherSuite cs, uint nodeIndex)
    {
        // Compute child hashes first
        uint left = TreeMath.Left(nodeIndex);
        uint right = TreeMath.Right(nodeIndex);

        byte[] leftHash = ComputeTreeHash(cs, left);

        // Right child might be beyond the tree in a truncated tree
        byte[] rightHash;
        if (right < (uint)_nodes.Count)
        {
            rightHash = ComputeTreeHash(cs, right);
        }
        else
        {
            // Hash of an empty/absent subtree: treat as blank leaf
            rightHash = ComputeBlankSubtreeHash(cs, right);
        }

        // TreeHashInput for parent:
        //   uint8 node_type = 2 (parent)
        //   optional<ParentNode> parent_node
        //   opaque left_hash<V>
        //   opaque right_hash<V>
        var input = TlsCodec.Serialize(writer =>
        {
            writer.WriteUint8(2); // parent node type

            var node = GetNode(nodeIndex);
            if (node is TreeNode.Parent parent && parent.Value != null)
            {
                writer.WriteUint8(1); // present
                parent.Value.WriteTo(writer);
            }
            else
            {
                writer.WriteUint8(0); // absent (blank)
            }

            writer.WriteOpaqueV(leftHash);
            writer.WriteOpaqueV(rightHash);
        });

        return cs.Hash(input);
    }

    /// <summary>
    /// Computes the hash for a subtree that is entirely outside the tree bounds.
    /// This is treated as a tree of blank nodes.
    /// </summary>
    private byte[] ComputeBlankSubtreeHash(ICipherSuite cs, uint nodeIndex)
    {
        if (TreeMath.IsLeaf(nodeIndex))
        {
            // Blank leaf
            var input = TlsCodec.Serialize(writer =>
            {
                writer.WriteUint8(1); // leaf
                writer.WriteUint8(0); // absent
            });
            return cs.Hash(input);
        }

        uint left = TreeMath.Left(nodeIndex);
        uint right = TreeMath.Right(nodeIndex);

        byte[] leftHash = ComputeBlankSubtreeHash(cs, left);
        byte[] rightHash = ComputeBlankSubtreeHash(cs, right);

        var input2 = TlsCodec.Serialize(writer =>
        {
            writer.WriteUint8(2); // parent
            writer.WriteUint8(0); // absent
            writer.WriteOpaqueV(leftHash);
            writer.WriteOpaqueV(rightHash);
        });

        return cs.Hash(input2);
    }

    // ---- Parent hash (RFC 9420 Section 7.9) ----

    /// <summary>
    /// Computes the parent hash for a node per RFC 9420 Section 7.9.
    ///
    /// ParentHashInput = encryption_key || parent_hash_of_parent || original_sibling_tree_hash
    /// parent_hash = Hash(ParentHashInput)
    /// </summary>
    /// <param name="cs">The cipher suite for hashing.</param>
    /// <param name="nodeIndex">The parent node index to compute the hash for.</param>
    /// <param name="originalSiblingTreeHash">The tree hash of the sibling subtree
    /// before any modifications from the current commit.</param>
    /// <returns>The parent hash bytes.</returns>
    public byte[] ComputeParentHash(ICipherSuite cs, uint nodeIndex, byte[] originalSiblingTreeHash)
    {
        var parentNode = GetParent(nodeIndex);
        if (parentNode == null)
            throw new InvalidOperationException($"Cannot compute parent hash for blank node {nodeIndex}.");

        // ParentHashInput:
        //   HPKEPublicKey encryption_key
        //   opaque parent_hash<V>
        //   opaque original_sibling_tree_hash<V>
        var input = TlsCodec.Serialize(writer =>
        {
            writer.WriteOpaqueV(parentNode.EncryptionKey);
            writer.WriteOpaqueV(parentNode.ParentHash);
            writer.WriteOpaqueV(originalSiblingTreeHash);
        });

        return cs.Hash(input);
    }

    // ---- TLS Serialization ----

    /// <summary>
    /// Serializes the entire ratchet tree for inclusion in Welcome messages.
    ///
    /// TLS encoding per RFC 9420 §12.4.3.3: vector of optional&lt;Node&gt;.
    /// Node type (leaf vs parent) is determined by position (even=leaf, odd=parent),
    /// with NO explicit nodeType discriminator byte.
    /// Each entry: uint8(present=1/0), if present: serialized LeafNode or ParentNode.
    /// </summary>
    public void WriteTo(TlsWriter writer)
    {
        writer.WriteVectorV(inner =>
        {
            foreach (var node in _nodes)
            {
                if (node == null)
                {
                    inner.WriteUint8(0); // absent
                }
                else if (node is TreeNode.Leaf leaf)
                {
                    if (leaf.Value == null)
                    {
                        inner.WriteUint8(0); // blank leaf = absent
                    }
                    else
                    {
                        inner.WriteUint8(1); // present
                        leaf.Value.WriteTo(inner);
                    }
                }
                else if (node is TreeNode.Parent parent)
                {
                    if (parent.Value == null)
                    {
                        inner.WriteUint8(0); // blank parent = absent
                    }
                    else
                    {
                        inner.WriteUint8(1); // present
                        parent.Value.WriteTo(inner);
                    }
                }
            }
        });
    }

    /// <summary>
    /// Deserializes a ratchet tree from TLS encoding.
    /// </summary>
    public static RatchetTree ReadFrom(TlsReader reader)
    {
        var tree = new RatchetTree();

        byte[] treeData = reader.ReadOpaqueV();
        if (treeData.Length == 0)
            return tree;

        var sub = new TlsReader(treeData);
        uint nodeIndex = 0;

        while (!sub.IsEmpty)
        {
            byte present = sub.ReadUint8();
            if (present == 0)
            {
                // Blank node
                if (TreeMath.IsLeaf(nodeIndex))
                    tree._nodes.Add(new TreeNode.Leaf(null));
                else
                    tree._nodes.Add(new TreeNode.Parent(null));
            }
            else
            {
                // Present node - type determined by position, NOT by a discriminator byte
                // Per RFC 9420 §12.4.3.3: even positions are leaves, odd are parents
                if (TreeMath.IsLeaf(nodeIndex))
                {
                    var leafNode = LeafNode.ReadFrom(sub);
                    tree._nodes.Add(new TreeNode.Leaf(leafNode));
                }
                else
                {
                    var parentNode = ParentNode.ReadFrom(sub);
                    tree._nodes.Add(new TreeNode.Parent(parentNode));
                }
            }

            nodeIndex++;
        }

        return tree;
    }

    // ---- Occupied leaves ----

    /// <summary>
    /// Gets the leaf indices of all non-blank leaves in the tree.
    /// </summary>
    /// <returns>A list of occupied leaf indices (0-based among leaves).</returns>
    public List<uint> GetOccupiedLeaves()
    {
        var result = new List<uint>();
        for (uint i = 0; i < LeafCount; i++)
        {
            if (GetLeaf(i) != null)
                result.Add(i);
        }
        return result;
    }

    // ---- Clone ----

    /// <summary>
    /// Creates a deep copy of this ratchet tree.
    /// </summary>
    public RatchetTree Clone()
    {
        var copy = new RatchetTree();
        foreach (var node in _nodes)
        {
            if (node == null)
            {
                copy._nodes.Add(null);
            }
            else if (node is TreeNode.Leaf leaf)
            {
                copy._nodes.Add(leaf.Clone());
            }
            else if (node is TreeNode.Parent parent)
            {
                copy._nodes.Add(parent.Clone());
            }
        }
        return copy;
    }

    // ---- Helpers ----

    /// <summary>
    /// Returns true if the given node index is blank (absent or has null value).
    /// </summary>
    /// <param name="nodeIndex">The node index to check.</param>
    /// <returns>True if blank.</returns>
    public bool IsBlank(uint nodeIndex)
    {
        var node = GetNode(nodeIndex);
        if (node == null)
            return true;
        if (node is TreeNode.Leaf leaf)
            return leaf.Value == null;
        if (node is TreeNode.Parent parent)
            return parent.Value == null;
        return true;
    }

    /// <summary>
    /// Ensures the internal node list can accommodate the given index.
    /// Fills gaps with appropriately typed blank nodes (leaf or parent based on index parity).
    /// </summary>
    private void EnsureCapacity(uint index)
    {
        while ((uint)_nodes.Count <= index)
        {
            uint nextIndex = (uint)_nodes.Count;
            if (TreeMath.IsLeaf(nextIndex))
                _nodes.Add(new TreeNode.Leaf(null));
            else
                _nodes.Add(new TreeNode.Parent(null));
        }
    }

    /// <summary>
    /// Trims trailing blank nodes from the tree. The tree should always end with
    /// a leaf (even index), so we remove trailing blank leaf + blank parent pairs.
    /// </summary>
    private void TrimTree()
    {
        while (_nodes.Count >= 2)
        {
            int lastIndex = _nodes.Count - 1;
            int secondLast = _nodes.Count - 2;

            // Last node must be a leaf (even index), second-to-last must be a parent (odd index)
            var lastNode = _nodes[lastIndex];
            var secondLastNode = _nodes[secondLast];

            bool lastBlank = lastNode == null
                || (lastNode is TreeNode.Leaf leaf && leaf.Value == null);
            bool secondLastBlank = secondLastNode == null
                || (secondLastNode is TreeNode.Parent parent && parent.Value == null);

            if (lastBlank && secondLastBlank)
            {
                _nodes.RemoveAt(lastIndex);
                _nodes.RemoveAt(secondLast);
            }
            else
            {
                break;
            }
        }
    }
}
