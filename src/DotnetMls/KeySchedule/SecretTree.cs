using DotnetMls.Crypto;

namespace DotnetMls.KeySchedule;

/// <summary>
/// Binary secret tree for per-sender encryption key derivation per RFC 9420 Section 9.
/// <para>
/// The tree mirrors the ratchet tree topology. The root receives the encryption_secret
/// from the epoch key schedule. Internal nodes derive left and right children:
/// <code>
///   left_secret  = ExpandWithLabel(parent_secret, "tree", [0x00], SecretSize)
///   right_secret = ExpandWithLabel(parent_secret, "tree", [0x01], SecretSize)
/// </code>
/// Each leaf has two ratchet chains (handshake and application). From a leaf secret:
/// <code>
///   handshake_ratchet_secret[0]   = ExpandWithLabel(leaf_secret, "handshake", "", SecretSize)
///   application_ratchet_secret[0] = ExpandWithLabel(leaf_secret, "application", "", SecretSize)
/// </code>
/// Each ratchet chain advances as:
/// <code>
///   secret[n+1] = ExpandWithLabel(secret[n], "secret", "", SecretSize)
///   key[n]      = ExpandWithLabel(secret[n], "key", "", AeadKeySize)
///   nonce[n]    = ExpandWithLabel(secret[n], "nonce", "", AeadNonceSize)
/// </code>
/// </para>
/// <para>
/// Secrets are derived lazily: tree nodes are only computed when a leaf's key material
/// is requested, and parent secrets are erased once both children have been derived.
/// </para>
/// </summary>
public sealed class SecretTree
{
    private readonly ICipherSuite _cs;
    private readonly uint _leafCount;
    private readonly int _nodeCount;

    // Lazy-computed node secrets indexed by tree node position.
    // null means the secret has been consumed or not yet derived.
    private readonly byte[]?[] _nodeSecrets;

    // Per-leaf ratchet state for handshake and application chains.
    private readonly RatchetState?[] _handshakeRatchets;
    private readonly RatchetState?[] _applicationRatchets;

    private static readonly byte[] LeftContext = "left"u8.ToArray();
    private static readonly byte[] RightContext = "right"u8.ToArray();

    /// <summary>The number of leaves in the tree.</summary>
    internal uint LeafCount => _leafCount;

    /// <summary>The total number of nodes (2*leafCount - 1).</summary>
    internal int NodeCount => _nodeCount;

    /// <summary>Gets a snapshot of the node secrets array for serialization.</summary>
    internal byte[]?[] NodeSecrets => _nodeSecrets;

    /// <summary>
    /// Gets the current handshake ratchet state for a leaf, or null if not yet initialized.
    /// </summary>
    internal (byte[] secret, uint generation)? GetHandshakeRatchetState(uint leafIndex)
    {
        if (leafIndex >= _leafCount) return null;
        var r = _handshakeRatchets[leafIndex];
        return r != null ? (r.Secret, r.Generation) : null;
    }

    /// <summary>
    /// Gets the current application ratchet state for a leaf, or null if not yet initialized.
    /// </summary>
    internal (byte[] secret, uint generation)? GetApplicationRatchetState(uint leafIndex)
    {
        if (leafIndex >= _leafCount) return null;
        var r = _applicationRatchets[leafIndex];
        return r != null ? (r.Secret, r.Generation) : null;
    }

    /// <summary>
    /// Restoration constructor: rebuilds a SecretTree from previously persisted state.
    /// </summary>
    internal SecretTree(
        ICipherSuite cs,
        uint leafCount,
        byte[]?[] nodeSecrets,
        (byte[] secret, uint generation)?[] handshakeRatchets,
        (byte[] secret, uint generation)?[] applicationRatchets)
    {
        _cs = cs;
        _leafCount = leafCount;
        _nodeCount = (int)(2 * leafCount - 1);
        _nodeSecrets = nodeSecrets;
        _handshakeRatchets = new RatchetState?[leafCount];
        _applicationRatchets = new RatchetState?[leafCount];

        for (uint i = 0; i < leafCount; i++)
        {
            if (i < handshakeRatchets.Length && handshakeRatchets[i] is { } hs)
                _handshakeRatchets[i] = new RatchetState(hs.secret, hs.generation);
            if (i < applicationRatchets.Length && applicationRatchets[i] is { } app)
                _applicationRatchets[i] = new RatchetState(app.secret, app.generation);
        }
    }

    /// <summary>
    /// Initializes a new secret tree from the epoch's encryption_secret and the group's leaf count.
    /// </summary>
    /// <param name="cs">The cipher suite providing cryptographic primitives.</param>
    /// <param name="encryptionSecret">The encryption_secret derived from the epoch key schedule.</param>
    /// <param name="leafCount">The number of leaves in the ratchet tree (group size).</param>
    /// <exception cref="ArgumentOutOfRangeException">Thrown when leafCount is zero.</exception>
    public SecretTree(ICipherSuite cs, byte[] encryptionSecret, uint leafCount)
    {
        if (leafCount == 0)
            throw new ArgumentOutOfRangeException(nameof(leafCount), "Leaf count must be at least 1.");

        _cs = cs;
        _leafCount = leafCount;

        // A binary tree over N leaves has 2*N - 1 nodes.
        _nodeCount = (int)(2 * leafCount - 1);
        _nodeSecrets = new byte[]?[_nodeCount];
        _handshakeRatchets = new RatchetState?[leafCount];
        _applicationRatchets = new RatchetState?[leafCount];

        // Place a copy of the encryption_secret at the root.
        // Must clone because EraseSecret will Array.Clear this when deriving children,
        // which would corrupt the caller's original array.
        _nodeSecrets[RootIndex()] = (byte[])encryptionSecret.Clone();
    }

    /// <summary>
    /// Gets the next handshake key, nonce, and generation for a given leaf (sender).
    /// Advances the handshake ratchet for this leaf by one generation.
    /// </summary>
    /// <param name="leafIndex">The leaf index of the sender (0-based).</param>
    /// <returns>A tuple of (key, nonce, generation) for the next handshake message.</returns>
    public (byte[] key, byte[] nonce, uint generation) GetHandshakeKeyAndNonce(uint leafIndex)
    {
        EnsureLeafDerived(leafIndex);
        var ratchet = GetOrInitHandshakeRatchet(leafIndex);
        return ConsumeRatchet(ratchet);
    }

    /// <summary>
    /// Gets the next application key, nonce, and generation for a given leaf (sender).
    /// Advances the application ratchet for this leaf by one generation.
    /// </summary>
    /// <param name="leafIndex">The leaf index of the sender (0-based).</param>
    /// <returns>A tuple of (key, nonce, generation) for the next application message.</returns>
    public (byte[] key, byte[] nonce, uint generation) GetApplicationKeyAndNonce(uint leafIndex)
    {
        EnsureLeafDerived(leafIndex);
        var ratchet = GetOrInitApplicationRatchet(leafIndex);
        return ConsumeRatchet(ratchet);
    }

    /// <summary>
    /// Gets the handshake key and nonce for a specific generation of a leaf.
    /// This is used for processing out-of-order messages. The ratchet must be
    /// at or before the requested generation. This call advances the ratchet
    /// to just past the requested generation.
    /// </summary>
    /// <param name="leafIndex">The leaf index of the sender.</param>
    /// <param name="generation">The target generation number.</param>
    /// <returns>A tuple of (key, nonce) for the specified generation.</returns>
    /// <exception cref="InvalidOperationException">
    /// Thrown when the requested generation has already been consumed.
    /// </exception>
    public (byte[] key, byte[] nonce) GetHandshakeKeyAndNonceForGeneration(uint leafIndex, uint generation)
    {
        if (_handshakeRatchets[leafIndex] == null)
            EnsureLeafDerived(leafIndex);
        var ratchet = GetOrInitHandshakeRatchet(leafIndex);
        return GetKeyAndNonceForGeneration(ratchet, generation);
    }

    /// <summary>
    /// Gets the application key and nonce for a specific generation of a leaf.
    /// This is used for processing out-of-order messages. The ratchet must be
    /// at or before the requested generation. This call advances the ratchet
    /// to just past the requested generation.
    /// </summary>
    /// <param name="leafIndex">The leaf index of the sender.</param>
    /// <param name="generation">The target generation number.</param>
    /// <returns>A tuple of (key, nonce) for the specified generation.</returns>
    /// <exception cref="InvalidOperationException">
    /// Thrown when the requested generation has already been consumed.
    /// </exception>
    public (byte[] key, byte[] nonce) GetApplicationKeyAndNonceForGeneration(uint leafIndex, uint generation)
    {
        if (_applicationRatchets[leafIndex] == null)
            EnsureLeafDerived(leafIndex);
        var ratchet = GetOrInitApplicationRatchet(leafIndex);
        return GetKeyAndNonceForGeneration(ratchet, generation);
    }

    // ---- Tree topology helpers ----
    // MLS uses a "left-balanced" binary tree where node indices follow the
    // same convention as the ratchet tree. Leaf nodes are at even indices:
    //   leaf i => node index 2*i
    // Parent/child relationships follow the standard left-balanced tree layout.

    /// <summary>
    /// Returns the node index for a given leaf index.
    /// In the MLS tree representation, leaf i is at node index 2*i.
    /// </summary>
    private static int LeafNodeIndex(uint leafIndex)
    {
        return (int)(2 * leafIndex);
    }

    /// <summary>
    /// Returns the root node index for the tree.
    /// </summary>
    private int RootIndex()
    {
        return Root(_nodeCount);
    }

    /// <summary>
    /// Computes the root index of a tree with <paramref name="nodeCount"/> nodes.
    /// </summary>
    private static int Root(int nodeCount)
    {
        // The root is at level = floor(log2(nodeCount)), positioned at (1 << level) - 1
        if (nodeCount == 1) return 0;
        var n = (uint)nodeCount;
        int level = Log2(n);
        return (1 << level) - 1;
    }

    /// <summary>
    /// Returns the level of a node (number of trailing 1-bits when viewing the index + 1 in binary).
    /// Leaves are at level 0; each subsequent parent level increases by 1.
    /// </summary>
    private static int Level(int nodeIndex)
    {
        if ((nodeIndex & 1) == 0) return 0;
        int k = 0;
        while (((nodeIndex >> k) & 1) == 1)
            k++;
        return k;
    }

    /// <summary>
    /// Returns the left child of an internal node.
    /// </summary>
    private static int Left(int nodeIndex)
    {
        int k = Level(nodeIndex);
        if (k == 0) throw new InvalidOperationException("Leaf nodes have no children.");
        return nodeIndex ^ (1 << (k - 1));
    }

    /// <summary>
    /// Returns the right child of an internal node, constrained to the tree size.
    /// </summary>
    private int Right(int nodeIndex)
    {
        int k = Level(nodeIndex);
        if (k == 0) throw new InvalidOperationException("Leaf nodes have no children.");
        int r = nodeIndex ^ (3 << (k - 1));
        // Clamp to tree bounds: if right child exceeds tree, walk down its left subtree
        while (r >= _nodeCount)
        {
            r = Left(r);
        }
        return r;
    }

    /// <summary>
    /// Returns the parent of a node within the tree.
    /// </summary>
    private int Parent(int nodeIndex)
    {
        int root = RootIndex();
        if (nodeIndex == root)
            throw new InvalidOperationException("Root node has no parent.");

        int k = Level(nodeIndex);
        // The parent is formed by toggling the bit at level k+1
        // and keeping the bit at level k set.
        int parentCandidate = (nodeIndex | (1 << k)) & ~(1 << (k + 1)) | (1 << (k + 1));
        // Simplified: parent = (nodeIndex & ~(1 << (k+1))) | (1 << k) ...
        // Actually the correct formula for left-balanced binary trees:
        // parent(x) depends on whether x is a left or right child.

        // Use the standard MLS formula:
        // If the node is to the left of the root, the parent bit-mask works as:
        //   parent(x) = x ^ (1 << (k+1))  if x is in certain positions
        // However, the robust approach: try both candidates and pick the one in range.
        int b = (1 << (k + 1));
        int p;
        if ((nodeIndex >> (k + 1) & 1) == 0)
        {
            // nodeIndex has bit k+1 cleared -> parent = nodeIndex + (1 << k)
            p = nodeIndex + (1 << k);
        }
        else
        {
            // nodeIndex has bit k+1 set -> parent = nodeIndex - (1 << k)
            p = nodeIndex - (1 << k);
        }

        // If parent is beyond tree, recurse up
        if (p >= _nodeCount)
        {
            return Parent(p);
        }
        return p;
    }

    /// <summary>
    /// Computes floor(log2(n)) for n > 0.
    /// </summary>
    private static int Log2(uint n)
    {
        int r = 0;
        while ((1u << (r + 1)) <= n) r++;
        return r;
    }

    // ---- Lazy tree derivation ----

    /// <summary>
    /// Ensures the leaf node at <paramref name="leafIndex"/> has its secret derived
    /// by lazily walking from the root down to the leaf.
    /// </summary>
    private void EnsureLeafDerived(uint leafIndex)
    {
        if (leafIndex >= _leafCount)
            throw new ArgumentOutOfRangeException(nameof(leafIndex),
                $"Leaf index {leafIndex} is out of range for tree with {_leafCount} leaves.");

        int leafNode = LeafNodeIndex(leafIndex);

        // If leaf secret is already available, nothing to do
        if (_nodeSecrets[leafNode] != null)
            return;

        // Find the path from root to this leaf, then derive downward
        DerivePathToLeaf(leafNode);
    }

    /// <summary>
    /// Derives node secrets along the path from the closest available ancestor
    /// down to the target node.
    /// </summary>
    private void DerivePathToLeaf(int targetNode)
    {
        // Build the path from target up to the first node that has a secret
        var path = new List<int>();
        int current = targetNode;

        while (_nodeSecrets[current] == null)
        {
            path.Add(current);
            current = Parent(current);
        }

        // Now 'current' has a secret. Derive downward through path (reversed).
        for (int i = path.Count - 1; i >= 0; i--)
        {
            int child = path[i];
            int parent = current;

            // Determine if child is left or right of parent
            int parentLeft = Left(parent);
            int parentRight = Right(parent);

            byte[] parentSecret = _nodeSecrets[parent]!;

            if (child == parentLeft || IsDescendantOf(child, parentLeft))
            {
                // Derive left child secret
                if (_nodeSecrets[parentLeft] == null)
                {
                    _nodeSecrets[parentLeft] = _cs.ExpandWithLabel(
                        parentSecret, "tree", LeftContext, _cs.SecretSize);
                }
                // Also derive right child if not yet derived (so we can erase parent)
                if (_nodeSecrets[parentRight] == null)
                {
                    _nodeSecrets[parentRight] = _cs.ExpandWithLabel(
                        parentSecret, "tree", RightContext, _cs.SecretSize);
                }
            }
            else
            {
                // Derive right child secret
                if (_nodeSecrets[parentRight] == null)
                {
                    _nodeSecrets[parentRight] = _cs.ExpandWithLabel(
                        parentSecret, "tree", RightContext, _cs.SecretSize);
                }
                // Also derive left child
                if (_nodeSecrets[parentLeft] == null)
                {
                    _nodeSecrets[parentLeft] = _cs.ExpandWithLabel(
                        parentSecret, "tree", LeftContext, _cs.SecretSize);
                }
            }

            // Erase the parent secret now that both children are derived
            EraseSecret(parent);

            // Move current to the child on the path
            if (child == parentLeft || IsDescendantOf(child, parentLeft))
                current = parentLeft;
            else
                current = parentRight;
        }
    }

    /// <summary>
    /// Returns true if <paramref name="node"/> is a descendant of <paramref name="ancestor"/>
    /// (or is equal to <paramref name="ancestor"/>).
    /// </summary>
    private bool IsDescendantOf(int node, int ancestor)
    {
        if (node == ancestor) return true;
        if (Level(ancestor) == 0) return false; // ancestor is a leaf; node can't be its descendant

        int left = Left(ancestor);
        int right = Right(ancestor);

        // Check if node is in the subtree rooted at ancestor
        // by comparing ranges. A subtree rooted at 'ancestor' covers
        // a contiguous range of leaves.
        var (ancestorMin, ancestorMax) = SubtreeRange(ancestor);
        return node >= ancestorMin && node <= ancestorMax;
    }

    /// <summary>
    /// Returns the range of node indices [min, max] in the subtree rooted at the given node.
    /// </summary>
    private (int min, int max) SubtreeRange(int nodeIndex)
    {
        int k = Level(nodeIndex);
        if (k == 0) return (nodeIndex, nodeIndex);

        // Walk down to leftmost and rightmost leaves
        int leftmost = nodeIndex;
        while (Level(leftmost) > 0)
            leftmost = Left(leftmost);

        int rightmost = nodeIndex;
        while (Level(rightmost) > 0)
        {
            int r = rightmost ^ (3 << (Level(rightmost) - 1));
            if (r >= _nodeCount)
                r = Left(r);
            rightmost = r;
        }

        return (leftmost, rightmost);
    }

    /// <summary>
    /// Overwrites a node secret with zeros and sets it to null.
    /// </summary>
    private void EraseSecret(int nodeIndex)
    {
        var secret = _nodeSecrets[nodeIndex];
        if (secret != null)
        {
            Array.Clear(secret, 0, secret.Length);
            _nodeSecrets[nodeIndex] = null;
        }
    }

    // ---- Ratchet operations ----

    private RatchetState GetOrInitHandshakeRatchet(uint leafIndex)
    {
        if (_handshakeRatchets[leafIndex] == null)
        {
            int leafNode = LeafNodeIndex(leafIndex);
            var leafSecret = _nodeSecrets[leafNode]
                ?? throw new InvalidOperationException($"Leaf {leafIndex} secret not available.");

            var initialSecret = _cs.ExpandWithLabel(
                leafSecret, "handshake", Array.Empty<byte>(), _cs.SecretSize);

            _handshakeRatchets[leafIndex] = new RatchetState(initialSecret, 0);

            // Check if both ratchets are initialized; if so, erase the leaf node secret
            if (_applicationRatchets[leafIndex] != null)
                EraseSecret(leafNode);
        }
        return _handshakeRatchets[leafIndex]!;
    }

    private RatchetState GetOrInitApplicationRatchet(uint leafIndex)
    {
        if (_applicationRatchets[leafIndex] == null)
        {
            int leafNode = LeafNodeIndex(leafIndex);
            var leafSecret = _nodeSecrets[leafNode]
                ?? throw new InvalidOperationException($"Leaf {leafIndex} secret not available.");

            var initialSecret = _cs.ExpandWithLabel(
                leafSecret, "application", Array.Empty<byte>(), _cs.SecretSize);

            _applicationRatchets[leafIndex] = new RatchetState(initialSecret, 0);

            // Check if both ratchets are initialized; if so, erase the leaf node secret
            if (_handshakeRatchets[leafIndex] != null)
                EraseSecret(leafNode);
        }
        return _applicationRatchets[leafIndex]!;
    }

    /// <summary>
    /// Consumes the current generation from a ratchet, returning key, nonce, and generation,
    /// then advances the ratchet to the next generation.
    /// </summary>
    private (byte[] key, byte[] nonce, uint generation) ConsumeRatchet(RatchetState ratchet)
    {
        var gen = ratchet.Generation;
        var genContext = GenerationContext(gen);

        var key = _cs.ExpandWithLabel(ratchet.Secret, "key", genContext, _cs.AeadKeySize);
        var nonce = _cs.ExpandWithLabel(ratchet.Secret, "nonce", genContext, _cs.AeadNonceSize);

        // Advance: secret[n+1] = DeriveTreeSecret(secret[n], "secret", n, SecretSize)
        var nextSecret = _cs.ExpandWithLabel(ratchet.Secret, "secret", genContext, _cs.SecretSize);

        // Erase old secret
        Array.Clear(ratchet.Secret, 0, ratchet.Secret.Length);

        ratchet.Secret = nextSecret;
        ratchet.Generation = gen + 1;

        return (key, nonce, gen);
    }

    /// <summary>
    /// Advances a ratchet to the specified generation and returns the key and nonce for that generation.
    /// </summary>
    private (byte[] key, byte[] nonce) GetKeyAndNonceForGeneration(RatchetState ratchet, uint generation)
    {
        if (generation < ratchet.Generation)
            throw new InvalidOperationException(
                $"Generation {generation} has already been consumed. Current generation is {ratchet.Generation}.");

        // Fast-forward the ratchet to the target generation
        while (ratchet.Generation < generation)
        {
            var genCtx = GenerationContext(ratchet.Generation);
            var nextSecret = _cs.ExpandWithLabel(
                ratchet.Secret, "secret", genCtx, _cs.SecretSize);
            Array.Clear(ratchet.Secret, 0, ratchet.Secret.Length);
            ratchet.Secret = nextSecret;
            ratchet.Generation++;
        }

        // Now ratchet.Generation == generation; derive key and nonce, then advance
        var targetCtx = GenerationContext(generation);
        var key = _cs.ExpandWithLabel(ratchet.Secret, "key", targetCtx, _cs.AeadKeySize);
        var nonce = _cs.ExpandWithLabel(ratchet.Secret, "nonce", targetCtx, _cs.AeadNonceSize);

        // Advance past the consumed generation
        var next = _cs.ExpandWithLabel(ratchet.Secret, "secret", targetCtx, _cs.SecretSize);
        Array.Clear(ratchet.Secret, 0, ratchet.Secret.Length);
        ratchet.Secret = next;
        ratchet.Generation++;

        return (key, nonce);
    }

    /// <summary>
    /// Encodes a generation number as a big-endian uint32 for DeriveTreeSecret context per RFC 9420 §9.
    /// </summary>
    private static byte[] GenerationContext(uint generation)
    {
        return new byte[]
        {
            (byte)(generation >> 24),
            (byte)(generation >> 16),
            (byte)(generation >> 8),
            (byte)(generation & 0xFF)
        };
    }

    /// <summary>
    /// Mutable state for a single ratchet chain (handshake or application).
    /// </summary>
    private sealed class RatchetState
    {
        public byte[] Secret;
        public uint Generation;

        public RatchetState(byte[] secret, uint generation)
        {
            Secret = secret;
            Generation = generation;
        }
    }
}
