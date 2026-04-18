using DotnetMls.Codec;
using DotnetMls.Crypto;
using DotnetMls.Types;

namespace DotnetMls.Tree;

/// <summary>
/// TreeKEM operations for MLS (RFC 9420 Section 7.6).
///
/// Provides Encap (encrypt path secrets for a commit) and Decap
/// (decrypt received path secrets from a commit).
/// </summary>
public static class TreeKem
{
    /// <summary>
    /// Encap: generates new path secrets for the sender's direct path,
    /// derives new HPKE key pairs for each node, encrypts path secrets
    /// to the resolution of each copath node, and returns the UpdatePath
    /// along with the commit secret.
    ///
    /// Per RFC 9420 Section 7.6:
    /// 1. Generate a fresh leaf secret (path_secret[0]).
    /// 2. For each node n on the filtered direct path:
    ///    - path_secret[n+1] = DeriveSecret(path_secret[n], "path")
    ///    - node_secret[n] = DeriveSecret(path_secret[n], "node")
    ///    - Derive HPKE key pair from node_secret[n]
    ///    - Set the node's public encryption key
    /// 3. For each direct path node, encrypt its path secret to the
    ///    resolution of the corresponding copath node.
    /// 4. commit_secret = DeriveSecret(path_secret[last], "path")
    /// </summary>
    /// <param name="tree">The ratchet tree (will be mutated with new node keys).</param>
    /// <param name="senderLeafIndex">The leaf index of the committer.</param>
    /// <param name="cs">The cipher suite.</param>
    /// <param name="newLeafNode">The updated leaf node for the committer.</param>
    /// <param name="groupContextFactory">Factory that returns the serialized provisional group context.
    /// Called after the tree is updated with all new public keys but before encryption.
    /// This allows the caller to compute the tree hash from the updated tree.</param>
    /// <param name="addedLeaves">Leaf indices of members added in this commit.
    /// Used to compute the filtered direct path per RFC 9420 §7.6.</param>
    /// <returns>A tuple of (UpdatePath to send, new leaf HPKE private key, commitSecret).</returns>
    public static (UpdatePath path, byte[] leafPrivateKey, byte[] commitSecret,
        IReadOnlyDictionary<uint, byte[]> pathSecretsByNode) Encap(
        RatchetTree tree,
        uint senderLeafIndex,
        ICipherSuite cs,
        LeafNode newLeafNode,
        Func<byte[]> groupContextFactory,
        IReadOnlyList<uint>? addedLeaves = null)
    {
        uint leafCount = tree.LeafCount;

        // Update the sender's leaf node
        tree.SetLeaf(senderLeafIndex, newLeafNode);

        // Compute the direct path and copath
        var directPath = TreeMath.DirectPath(senderLeafIndex, leafCount);
        var copath = TreeMath.Copath(senderLeafIndex, leafCount);

        // RFC 9420 §4.1.2: Compute filtered direct path — exclude entries whose
        // copath child has empty resolution. Uses FULL resolution per spec.
        // New members are excluded from HPKE encryption recipients (line 130)
        // but NOT from path filtering.
        var addedNodeIndices = new HashSet<uint>();
        if (addedLeaves != null)
            foreach (var al in addedLeaves)
                addedNodeIndices.Add(TreeMath.LeafToNode(al));

        var filteredDp = new List<uint>();
        var filteredCopath = new List<uint>();
        for (int i = 0; i < directPath.Length; i++)
        {
            var res = tree.Resolution(copath[i]);
            if (res.Count > 0)
            {
                filteredDp.Add(directPath[i]);
                filteredCopath.Add(copath[i]);
            }
        }

        // Blank the sender's direct path (all entries, not just filtered)
        foreach (uint n in directPath)
            tree.SetParent(n, null);

        // Generate the initial leaf secret
        byte[] pathSecret = cs.RandomBytes(cs.SecretSize);

        // Derive node key pair for the leaf
        var (leafPriv, leafPub) = DeriveKeyPair(cs, DeriveNodeSecret(cs, pathSecret));

        // Update the leaf's encryption key
        newLeafNode.EncryptionKey = leafPub;
        tree.SetLeaf(senderLeafIndex, newLeafNode);

        // Phase 1: Generate path secrets along the FILTERED direct path,
        // derive key pairs and update tree nodes only for filtered entries.
        var pathSecrets = new List<byte[]>();
        var nodePubs = new List<byte[]>();

        for (int i = 0; i < filteredDp.Count; i++)
        {
            uint nodeIndex = filteredDp[i];

            // Derive next path secret
            pathSecret = cs.DeriveSecret(pathSecret, "path");
            pathSecrets.Add(pathSecret);

            // Derive node key pair
            byte[] nodeSecret = DeriveNodeSecret(cs, pathSecret);
            var (nodePriv, nodePub) = DeriveKeyPair(cs, nodeSecret);
            nodePubs.Add(nodePub);

            // Update the parent node in the tree
            var parentNode = new ParentNode();
            parentNode.EncryptionKey = nodePub;
            parentNode.PrivateKey = nodePriv;
            parentNode.UnmergedLeaves = new List<uint>();
            tree.SetParent(nodeIndex, parentNode);
        }

        // Phase 2: Encrypt path secrets to copath resolutions.
        // Get the provisional context now that all public keys are set on the tree.
        byte[] groupContext = groupContextFactory();
        var updatePathNodes = new List<UpdatePathNode>();

        for (int i = 0; i < filteredDp.Count; i++)
        {
            uint copathNode = filteredCopath[i];
            var resolution = tree.Resolution(copathNode);
            // Exclude added members from encryption targets
            var encResolution = resolution.Where(n => !addedNodeIndices.Contains(n)).ToList();

            var encryptedSecrets = new List<HpkeCiphertext>();
            foreach (uint resNodeIndex in encResolution)
            {
                byte[] recipientPub = GetNodeEncryptionKey(tree, resNodeIndex);
                if (recipientPub.Length == 0)
                    continue;

                var ciphertext = EncryptPathSecret(cs, pathSecrets[i], recipientPub, groupContext);
                encryptedSecrets.Add(ciphertext);
            }

            updatePathNodes.Add(new UpdatePathNode(nodePubs[i], encryptedSecrets.ToArray()));
        }

        // Commit secret is derived from the last path secret
        byte[] commitSecret = cs.DeriveSecret(pathSecret, "path");

        // Build map of nodeIndex → pathSecret for Welcome path_secret derivation
        var psMap = new Dictionary<uint, byte[]>();
        for (int i = 0; i < filteredDp.Count; i++)
            psMap[filteredDp[i]] = pathSecrets[i];

        var updatePath = new UpdatePath(newLeafNode, updatePathNodes.ToArray());
        return (updatePath, leafPriv, commitSecret, psMap);
    }

    /// <summary>
    /// Decap: processes a received UpdatePath from a commit.
    /// Finds the appropriate encrypted path secret based on the receiver's position,
    /// decrypts it, derives all subsequent path secrets, updates the tree, and returns
    /// the commit secret.
    ///
    /// Per RFC 9420 Section 7.6:
    /// 1. Find which copath node the receiver is under (i.e., which encrypted
    ///    path secret to decrypt).
    /// 2. Decrypt the path secret for that node.
    /// 3. Derive subsequent path secrets up to the root.
    /// 4. Update tree nodes with new encryption keys from the UpdatePath.
    /// 5. Return the commit secret.
    /// </summary>
    /// <param name="tree">The ratchet tree (will be mutated with new node keys).</param>
    /// <param name="senderLeafIndex">The leaf index of the sender (committer).</param>
    /// <param name="updatePath">The received UpdatePath.</param>
    /// <param name="cs">The cipher suite.</param>
    /// <param name="myLeafIndex">The receiver's leaf index.</param>
    /// <param name="myPrivateKeys">Map from node index to HPKE private key for this member's keys.</param>
    /// <param name="groupContext">Serialized group context.</param>
    /// <returns>The commit secret for the key schedule.</returns>
    public static byte[] Decap(
        RatchetTree tree,
        uint senderLeafIndex,
        UpdatePath updatePath,
        ICipherSuite cs,
        uint myLeafIndex,
        Dictionary<uint, byte[]> myPrivateKeys,
        byte[] groupContext)
    {
        uint leafCount = tree.LeafCount;

        // Update sender's leaf node
        tree.SetLeaf(senderLeafIndex, updatePath.LeafNode);

        // Compute sender's direct path and copath
        var directPath = TreeMath.DirectPath(senderLeafIndex, leafCount);
        var copath = TreeMath.Copath(senderLeafIndex, leafCount);

        // Find our position: which copath node are we under?
        // We are under the copath node that is on our side of the tree.
        // More precisely, for each copath node, check if our leaf is in its resolution.
        int myPathPosition = -1;
        int myResolutionIndex = -1;

        for (int i = 0; i < copath.Length; i++)
        {
            uint copathNode = copath[i];
            var resolution = tree.Resolution(copathNode);

            for (int j = 0; j < resolution.Count; j++)
            {
                uint resNode = resolution[j];
                // Check if we have a private key for this resolution node
                if (myPrivateKeys.ContainsKey(resNode))
                {
                    myPathPosition = i;
                    myResolutionIndex = j;
                    break;
                }
            }

            if (myPathPosition >= 0)
                break;
        }

        if (myPathPosition < 0)
            throw new InvalidOperationException(
                "Could not find a decryptable path secret. The receiver has no private key " +
                "matching any resolution node on the sender's copath.");

        // Decrypt the path secret at our position
        var updateNode = updatePath.Nodes[myPathPosition];
        var encryptedSecret = updateNode.EncryptedPathSecret[myResolutionIndex];

        uint resolutionNodeIndex = tree.Resolution(copath[myPathPosition])[myResolutionIndex];
        byte[] myPrivateKey = myPrivateKeys[resolutionNodeIndex];

        byte[] pathSecret = DecryptPathSecret(
            cs, encryptedSecret, myPrivateKey, groupContext);

        // Now derive path secrets forward from this position, updating nodes
        // First, update all direct path nodes from position 0 to our position
        // with the public keys from the UpdatePath (we can't derive their secrets)
        for (int i = 0; i < myPathPosition; i++)
        {
            uint nodeIndex = directPath[i];
            var parentNode = tree.GetParent(nodeIndex) ?? new ParentNode();
            parentNode.EncryptionKey = updatePath.Nodes[i].EncryptionKey;
            parentNode.UnmergedLeaves = new List<uint>();
            tree.SetParent(nodeIndex, parentNode);
        }

        // From our position, derive secrets and update nodes
        for (int i = myPathPosition; i < directPath.Length; i++)
        {
            uint nodeIndex = directPath[i];

            byte[] nodeSecret = DeriveNodeSecret(cs, pathSecret);
            var (nodePriv, nodePub) = DeriveKeyPair(cs, nodeSecret);

            var parentNode = tree.GetParent(nodeIndex) ?? new ParentNode();
            parentNode.EncryptionKey = nodePub;
            parentNode.PrivateKey = nodePriv;
            parentNode.UnmergedLeaves = new List<uint>();
            tree.SetParent(nodeIndex, parentNode);

            // Derive next path secret for the next node up
            if (i < directPath.Length - 1)
            {
                pathSecret = cs.DeriveSecret(pathSecret, "path");
            }
        }

        // Commit secret is derived from the last path secret
        byte[] commitSecret = cs.DeriveSecret(pathSecret, "path");

        return commitSecret;
    }

    /// <summary>
    /// Simplified Decap overload that automatically finds private keys from
    /// the receiver's leaf and parent nodes in the tree.
    /// </summary>
    /// <param name="tree">The ratchet tree.</param>
    /// <param name="senderLeafIndex">The sender's leaf index.</param>
    /// <param name="updatePath">The received UpdatePath.</param>
    /// <param name="cs">The cipher suite.</param>
    /// <param name="myLeafIndex">The receiver's leaf index.</param>
    /// <param name="myLeafPrivateKey">The receiver's leaf HPKE private key.</param>
    /// <param name="groupContext">Serialized group context.</param>
    /// <returns>The commit secret.</returns>
    public static byte[] Decap(
        RatchetTree tree,
        uint senderLeafIndex,
        UpdatePath updatePath,
        ICipherSuite cs,
        uint myLeafIndex,
        byte[] myLeafPrivateKey,
        byte[] groupContext)
    {
        // Build the private key map from the receiver's known keys
        var privateKeys = new Dictionary<uint, byte[]>();

        // Add leaf private key
        uint myNodeIndex = TreeMath.LeafToNode(myLeafIndex);
        privateKeys[myNodeIndex] = myLeafPrivateKey;

        // Add any parent node private keys we might have
        uint leafCount = tree.LeafCount;
        var myDirectPath = TreeMath.DirectPath(myLeafIndex, leafCount);
        foreach (uint dpNode in myDirectPath)
        {
            var parentNode = tree.GetParent(dpNode);
            if (parentNode?.PrivateKey != null)
            {
                privateKeys[dpNode] = parentNode.PrivateKey;
            }
        }

        return Decap(tree, senderLeafIndex, updatePath, cs, myLeafIndex, privateKeys, groupContext);
    }

    // ---- Key derivation helpers ----

    /// <summary>
    /// Derives the node secret from a path secret.
    /// node_secret = DeriveSecret(path_secret, "node")
    /// </summary>
    private static byte[] DeriveNodeSecret(ICipherSuite cs, byte[] pathSecret)
    {
        return cs.DeriveSecret(pathSecret, "node");
    }

    /// <summary>
    /// Derives an HPKE key pair from a node secret.
    ///
    /// For X25519-based cipher suites, the private key is derived via
    /// ExpandWithLabel and the public key is computed from it.
    ///
    /// Per RFC 9420 Section 7.6, DeriveKeyPair uses the KEM's DeriveKeyPair function.
    /// For DHKEM(X25519), RFC 9180 Section 7.1.3:
    ///   DeriveKeyPair(ikm):
    ///     dkp_prk = LabeledExtract("", "dkp_prk", ikm)
    ///     sk = LabeledExpand(dkp_prk, "sk", "", Nsk=32)
    ///     return (sk, pk(sk))
    /// </summary>
    internal static (byte[] privateKey, byte[] publicKey) DeriveKeyPair(ICipherSuite cs, byte[] nodeSecret)
    {
        // KEM suite_id for DHKEM(X25519, HKDF-SHA256) = "KEM" || I2OSP(0x0020, 2)
        byte[] kemSuiteId = { 0x4B, 0x45, 0x4D, 0x00, 0x20 };
        byte[] hpkeV1 = System.Text.Encoding.ASCII.GetBytes("HPKE-v1");

        // LabeledExtract(salt="", label="dkp_prk", ikm=nodeSecret)
        // labeled_ikm = "HPKE-v1" || suite_id || "dkp_prk" || ikm
        byte[] dkpPrkLabel = System.Text.Encoding.ASCII.GetBytes("dkp_prk");
        byte[] labeledIkm = ConcatBytes(hpkeV1, kemSuiteId, dkpPrkLabel, nodeSecret);
        byte[] dkpPrk = cs.Extract(Array.Empty<byte>(), labeledIkm);

        // LabeledExpand(dkp_prk, label="sk", info="", L=32)
        // labeled_info = I2OSP(32, 2) || "HPKE-v1" || suite_id || "sk"
        byte[] skLabel = System.Text.Encoding.ASCII.GetBytes("sk");
        byte[] labeledInfo = ConcatBytes(new byte[] { 0x00, 0x20 }, hpkeV1, kemSuiteId, skLabel);
        byte[] sk = cs.Expand(dkpPrk, labeledInfo, 32);

        // Derive public key: pk = X25519(sk, basepoint)
        var x25519 = new X25519Provider();
        byte[] pk = x25519.GetPublicKey(sk);

        return (sk, pk);
    }

    /// <summary>Concatenates multiple byte arrays.</summary>
    private static byte[] ConcatBytes(params byte[][] arrays)
    {
        int total = 0;
        foreach (var a in arrays) total += a.Length;
        var result = new byte[total];
        int offset = 0;
        foreach (var a in arrays)
        {
            Buffer.BlockCopy(a, 0, result, offset, a.Length);
            offset += a.Length;
        }
        return result;
    }

    /// <summary>
    /// Encrypts a path secret to a recipient's public key using HPKE EncryptWithLabel.
    /// Per RFC 9420 §7.6: EncryptWithLabel(node_pub, "UpdatePathNode", group_context, path_secret)
    /// </summary>
    private static HpkeCiphertext EncryptPathSecret(
        ICipherSuite cs, byte[] pathSecret, byte[] recipientPub, byte[] groupContext)
    {
        // Build EncryptWithLabel info: { opaque label<V>; opaque content<V>; }
        // label = "MLS 1.0 UpdatePathNode", content = group_context
        byte[] info = Codec.TlsCodec.Serialize(w =>
        {
            w.WriteOpaqueV(System.Text.Encoding.UTF8.GetBytes("MLS 1.0 UpdatePathNode"));
            w.WriteOpaqueV(groupContext);
        });

        byte[] sealed_ = cs.HpkeSeal(recipientPub, info, Array.Empty<byte>(), pathSecret);

        const int kemOutputSize = 32; // X25519 public key size
        byte[] kemOutput = new byte[kemOutputSize];
        byte[] ciphertext = new byte[sealed_.Length - kemOutputSize];
        Array.Copy(sealed_, 0, kemOutput, 0, kemOutputSize);
        Array.Copy(sealed_, kemOutputSize, ciphertext, 0, ciphertext.Length);

        return new HpkeCiphertext(kemOutput, ciphertext);
    }

    /// <summary>
    /// Decrypts a path secret from an HpkeCiphertext using HPKE DecryptWithLabel.
    /// Per RFC 9420 §7.6: DecryptWithLabel(node_priv, "UpdatePathNode", group_context, kem_output, ciphertext)
    /// </summary>
    private static byte[] DecryptPathSecret(
        ICipherSuite cs, HpkeCiphertext ct, byte[] recipientPriv, byte[] groupContext)
    {
        byte[] info = Codec.TlsCodec.Serialize(w =>
        {
            w.WriteOpaqueV(System.Text.Encoding.UTF8.GetBytes("MLS 1.0 UpdatePathNode"));
            w.WriteOpaqueV(groupContext);
        });

        return cs.HpkeOpen(recipientPriv, ct.KemOutput, info, Array.Empty<byte>(), ct.Ciphertext);
    }

    /// <summary>
    /// Gets the encryption key for a node. For leaf nodes, this is the leaf's encryption key.
    /// For parent nodes, this is the parent's encryption key.
    /// </summary>
    private static byte[] GetNodeEncryptionKey(RatchetTree tree, uint nodeIndex)
    {
        if (TreeMath.IsLeaf(nodeIndex))
        {
            uint leafIndex = TreeMath.NodeToLeaf(nodeIndex);
            var leaf = tree.GetLeaf(leafIndex);
            return leaf?.EncryptionKey ?? Array.Empty<byte>();
        }
        else
        {
            var parent = tree.GetParent(nodeIndex);
            return parent?.EncryptionKey ?? Array.Empty<byte>();
        }
    }
}
