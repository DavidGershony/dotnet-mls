using System.Numerics;

namespace DotnetMls.Tree;

/// <summary>
/// Static class implementing RFC 9420 Section 4 binary tree math.
///
/// The ratchet tree is a complete left-balanced binary tree.
/// Leaf nodes are at even indices (0, 2, 4, ...) and parent nodes at odd indices (1, 3, 5, ...).
/// For a group of N members there are N leaves and 2N - 1 total nodes.
/// </summary>
public static class TreeMath
{
    /// <summary>
    /// Returns the level of a node, defined as the number of trailing one-bits
    /// in the binary representation of the index. Leaves (even indices) have level 0.
    /// </summary>
    /// <param name="x">The node index.</param>
    /// <returns>The level of the node.</returns>
    public static uint Level(uint x)
    {
        // Count trailing ones = count trailing zeros of ~x
        // If x is all 1-bits (0xFFFFFFFF), BitOperations returns 32.
        // That would be an unrealistic tree size, but it is mathematically correct.
        return (uint)BitOperations.TrailingZeroCount(~x);
    }

    /// <summary>
    /// Returns the total number of nodes in a tree with the given number of leaves.
    /// </summary>
    /// <param name="leafCount">The number of leaves (members).</param>
    /// <returns>The total node count (2 * leafCount - 1), or 0 if leafCount is 0.</returns>
    public static uint NodeCount(uint leafCount) => leafCount == 0 ? 0 : 2 * leafCount - 1;

    /// <summary>
    /// Returns the index of the root node for a tree with the given number of leaves.
    /// </summary>
    /// <param name="leafCount">The number of leaves. Must be at least 1.</param>
    /// <returns>The root node index.</returns>
    /// <exception cref="ArgumentOutOfRangeException">Thrown when leafCount is 0.</exception>
    public static uint Root(uint leafCount)
    {
        if (leafCount == 0)
            throw new ArgumentOutOfRangeException(nameof(leafCount), "Tree must have at least one leaf.");

        if (leafCount == 1)
            return 0;

        // d = floor(log2(leafCount - 1)) + 1
        // root = (1 << d) - 1
        uint n = leafCount - 1;
        int d = 32 - BitOperations.LeadingZeroCount(n); // floor(log2(n)) + 1
        return (1u << d) - 1;
    }

    /// <summary>
    /// Returns the left child of a parent node.
    /// </summary>
    /// <param name="x">The parent node index. Must have Level(x) > 0.</param>
    /// <returns>The left child node index.</returns>
    /// <exception cref="InvalidOperationException">Thrown when x is a leaf node.</exception>
    public static uint Left(uint x)
    {
        uint k = Level(x);
        if (k == 0)
            throw new InvalidOperationException($"Node {x} is a leaf and has no children.");

        return x ^ (1u << (int)(k - 1));
    }

    /// <summary>
    /// Returns the right child of a parent node.
    /// </summary>
    /// <param name="x">The parent node index. Must have Level(x) > 0.</param>
    /// <returns>The right child node index.</returns>
    /// <exception cref="InvalidOperationException">Thrown when x is a leaf node.</exception>
    public static uint Right(uint x)
    {
        uint k = Level(x);
        if (k == 0)
            throw new InvalidOperationException($"Node {x} is a leaf and has no children.");

        return x ^ (3u << (int)(k - 1));
    }

    /// <summary>
    /// Returns the right child of a parent node, clamped to the tree bounds.
    /// Per RFC 9420 Appendix C: if the computed right child is beyond the tree,
    /// walk left until a valid node is found.
    /// This is used for tree operations (Sibling, Copath) but NOT for tree hash
    /// computation (which uses phantom blank subtrees via unclamped Right).
    /// </summary>
    /// <param name="x">The parent node index.</param>
    /// <param name="nodeCount">The total number of nodes in the tree.</param>
    /// <returns>The clamped right child node index.</returns>
    public static uint RightClamped(uint x, uint nodeCount)
    {
        uint r = Right(x);
        while (r >= nodeCount)
        {
            r = Left(r);
        }
        return r;
    }

    /// <summary>
    /// Returns the parent of a node within a tree of the given total node count.
    /// Handles the left-balanced tree structure where the computed parent may
    /// exceed the node count, requiring iteration upward.
    /// </summary>
    /// <param name="x">The node index.</param>
    /// <param name="nodeCount">The total number of nodes in the tree.</param>
    /// <returns>The parent node index.</returns>
    /// <exception cref="InvalidOperationException">Thrown when x is the root.</exception>
    public static uint Parent(uint x, uint nodeCount)
    {
        if (x == Root((nodeCount + 1) / 2))
            throw new InvalidOperationException($"Node {x} is the root and has no parent.");

        uint k = Level(x);
        uint p;

        // Determine if x is a left or right child by examining
        // the bit at position (k + 1).
        // If that bit is 0, x is a left child: parent = x + (1 << k).
        // If that bit is 1, x is a right child: parent = x - (1 << k).
        if (((x >> (int)(k + 1)) & 1) == 0)
        {
            p = x + (1u << (int)k);
        }
        else
        {
            p = x - (1u << (int)k);
        }

        // In a truncated (left-balanced) tree the computed parent may be
        // beyond the actual tree. If so, keep going up.
        // This happens when the right subtree doesn't exist.
        while (p >= nodeCount)
        {
            k = Level(p);
            if (((p >> (int)(k + 1)) & 1) == 0)
            {
                p = p + (1u << (int)k);
            }
            else
            {
                p = p - (1u << (int)k);
            }
        }

        return p;
    }

    /// <summary>
    /// Returns the sibling of a node (the other child of its parent).
    /// </summary>
    /// <param name="x">The node index.</param>
    /// <param name="nodeCount">The total number of nodes in the tree.</param>
    /// <returns>The sibling node index.</returns>
    public static uint Sibling(uint x, uint nodeCount)
    {
        uint p = Parent(x, nodeCount);

        if (x < p)
            return RightClamped(p, nodeCount);
        else
            return Left(p);
    }

    /// <summary>
    /// Returns whether the given node index represents a leaf (even index).
    /// </summary>
    /// <param name="x">The node index.</param>
    /// <returns>True if the node is a leaf.</returns>
    public static bool IsLeaf(uint x) => (x & 1) == 0;

    /// <summary>
    /// Converts a leaf index (0-based position among leaves) to a node index.
    /// </summary>
    /// <param name="leafIndex">The leaf index.</param>
    /// <returns>The corresponding node index.</returns>
    public static uint LeafToNode(uint leafIndex) => leafIndex * 2;

    /// <summary>
    /// Converts a node index to a leaf index. The node must be a leaf (even index).
    /// </summary>
    /// <param name="nodeIndex">The node index.</param>
    /// <returns>The corresponding leaf index.</returns>
    public static uint NodeToLeaf(uint nodeIndex) => nodeIndex / 2;

    /// <summary>
    /// Computes the direct path from a leaf to the root.
    /// The direct path excludes the leaf itself but includes the root.
    /// </summary>
    /// <param name="leafIndex">The leaf index (0-based among leaves).</param>
    /// <param name="leafCount">The number of leaves in the tree.</param>
    /// <returns>An array of node indices from the leaf's parent up to and including the root.</returns>
    public static uint[] DirectPath(uint leafIndex, uint leafCount)
    {
        if (leafCount <= 1)
            return Array.Empty<uint>();

        uint nodeCount = NodeCount(leafCount);
        uint root = Root(leafCount);
        uint node = LeafToNode(leafIndex);

        var path = new List<uint>();
        while (node != root)
        {
            node = Parent(node, nodeCount);
            path.Add(node);
        }

        return path.ToArray();
    }

    /// <summary>
    /// Computes the copath for a leaf: the siblings of each node on the direct path.
    /// The copath[i] is the sibling of DirectPath[i].
    /// </summary>
    /// <param name="leafIndex">The leaf index (0-based among leaves).</param>
    /// <param name="leafCount">The number of leaves in the tree.</param>
    /// <returns>An array of copath node indices, parallel to the direct path.</returns>
    public static uint[] Copath(uint leafIndex, uint leafCount)
    {
        if (leafCount <= 1)
            return Array.Empty<uint>();

        uint nodeCount = NodeCount(leafCount);
        uint root = Root(leafCount);
        uint node = LeafToNode(leafIndex);

        var copath = new List<uint>();

        // The copath starts with the sibling of the leaf itself,
        // then the sibling of each subsequent node on the direct path.
        while (node != root)
        {
            copath.Add(Sibling(node, nodeCount));
            node = Parent(node, nodeCount);
        }

        return copath.ToArray();
    }

    /// <summary>
    /// Computes the lowest common ancestor of two leaf nodes.
    /// This is the lowest node that appears on the direct paths of both leaves.
    /// </summary>
    /// <param name="leafA">The first leaf index (0-based among leaves).</param>
    /// <param name="leafB">The second leaf index (0-based among leaves).</param>
    /// <returns>The node index of the common ancestor.</returns>
    public static uint CommonAncestor(uint leafA, uint leafB)
    {
        uint a = LeafToNode(leafA);
        uint b = LeafToNode(leafB);

        // Walk upward from both nodes until they meet.
        // At each step, advance the node with the lower level.
        // If levels are equal but nodes differ, advance both.
        while (a != b)
        {
            uint levelA = Level(a);
            uint levelB = Level(b);

            if (levelA < levelB)
            {
                // Move a up: compute parent without node count
                // Using the bit-based formula directly since we don't know tree size
                a = ParentUnchecked(a);
            }
            else if (levelB < levelA)
            {
                b = ParentUnchecked(b);
            }
            else
            {
                // Same level, different nodes: move both up
                a = ParentUnchecked(a);
                b = ParentUnchecked(b);
            }
        }

        return a;
    }

    /// <summary>
    /// Computes the filtered direct path: the direct path nodes that are not blank.
    /// This is used for tree hash and parent hash computation.
    /// </summary>
    /// <param name="leafIndex">The leaf index.</param>
    /// <param name="leafCount">The number of leaves.</param>
    /// <param name="isBlank">A function that returns true if the given node index is blank.</param>
    /// <returns>An array of non-blank direct path node indices.</returns>
    public static uint[] FilteredDirectPath(uint leafIndex, uint leafCount, Func<uint, bool> isBlank)
    {
        var dp = DirectPath(leafIndex, leafCount);
        var filtered = new List<uint>();
        foreach (var node in dp)
        {
            if (!isBlank(node))
            {
                filtered.Add(node);
            }
        }
        return filtered.ToArray();
    }

    /// <summary>
    /// Computes the parent of a node in a full (non-truncated) binary tree.
    /// This does not check bounds and is used for CommonAncestor.
    /// </summary>
    private static uint ParentUnchecked(uint x)
    {
        uint k = Level(x);
        if (((x >> (int)(k + 1)) & 1) == 0)
            return x + (1u << (int)k);
        else
            return x - (1u << (int)k);
    }
}
