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
    /// <param name="groupContext">Serialized group context, used as HPKE encryption context.</param>
    /// <returns>A tuple of (UpdatePath to send, commitSecret for key schedule).</returns>
    public static (UpdatePath path, byte[] commitSecret) Encap(
        RatchetTree tree,
        uint senderLeafIndex,
        ICipherSuite cs,
        LeafNode newLeafNode,
        byte[] groupContext)
    {
        uint leafCount = tree.LeafCount;

        // Update the sender's leaf node
        tree.SetLeaf(senderLeafIndex, newLeafNode);

        // Compute the direct path and copath
        var directPath = TreeMath.DirectPath(senderLeafIndex, leafCount);
        var copath = TreeMath.Copath(senderLeafIndex, leafCount);

        // Generate the initial leaf secret
        byte[] pathSecret = cs.RandomBytes(cs.SecretSize);

        // Derive node key pair for the leaf
        var (leafPriv, leafPub) = DeriveKeyPair(cs, DeriveNodeSecret(cs, pathSecret));

        // Update the leaf's encryption key
        newLeafNode.EncryptionKey = leafPub;
        tree.SetLeaf(senderLeafIndex, newLeafNode);

        // Process each node on the direct path
        var updatePathNodes = new List<UpdatePathNode>();

        for (int i = 0; i < directPath.Length; i++)
        {
            uint nodeIndex = directPath[i];

            // Derive next path secret
            pathSecret = cs.DeriveSecret(pathSecret, "path");

            // Derive node key pair
            byte[] nodeSecret = DeriveNodeSecret(cs, pathSecret);
            var (nodePriv, nodePub) = DeriveKeyPair(cs, nodeSecret);

            // Update the parent node in the tree
            var parentNode = tree.GetParent(nodeIndex) ?? new ParentNode();
            parentNode.EncryptionKey = nodePub;
            parentNode.PrivateKey = nodePriv;
            parentNode.UnmergedLeaves = new List<uint>(); // Clear unmerged leaves
            tree.SetParent(nodeIndex, parentNode);

            // Encrypt the path secret to the resolution of the copath node
            uint copathNode = copath[i];
            var resolution = tree.Resolution(copathNode);

            var encryptedSecrets = new List<HpkeCiphertext>();
            foreach (uint resNodeIndex in resolution)
            {
                byte[] recipientPub = GetNodeEncryptionKey(tree, resNodeIndex);
                if (recipientPub.Length == 0)
                    continue;

                // HPKE encrypt: info = groupContext, aad = empty
                var ciphertext = EncryptPathSecret(cs, pathSecret, recipientPub, groupContext);
                encryptedSecrets.Add(ciphertext);
            }

            updatePathNodes.Add(new UpdatePathNode(nodePub, encryptedSecrets.ToArray()));
        }

        // Compute the commit secret: one more derivation beyond the last path secret
        byte[] commitSecret = cs.DeriveSecret(pathSecret, "path");

        var updatePath = new UpdatePath(newLeafNode, updatePathNodes.ToArray());
        return (updatePath, commitSecret);
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
    /// Encrypts a path secret to a recipient's public key using HPKE.
    /// </summary>
    private static HpkeCiphertext EncryptPathSecret(
        ICipherSuite cs, byte[] pathSecret, byte[] recipientPub, byte[] groupContext)
    {
        // HPKE single-shot seal
        // info = "MLS 1.0 UpdatePathNode" (group context is used as info)
        // aad = group_context
        byte[] sealed_ = cs.HpkeSeal(recipientPub, groupContext, Array.Empty<byte>(), pathSecret);

        // HpkeSeal returns enc || ct, where enc is the KEM output (32 bytes for X25519)
        // and ct is ciphertext + tag
        const int kemOutputSize = 32; // X25519 public key size
        byte[] kemOutput = new byte[kemOutputSize];
        byte[] ciphertext = new byte[sealed_.Length - kemOutputSize];
        Array.Copy(sealed_, 0, kemOutput, 0, kemOutputSize);
        Array.Copy(sealed_, kemOutputSize, ciphertext, 0, ciphertext.Length);

        return new HpkeCiphertext(kemOutput, ciphertext);
    }

    /// <summary>
    /// Decrypts a path secret from an HpkeCiphertext using the recipient's private key.
    /// </summary>
    private static byte[] DecryptPathSecret(
        ICipherSuite cs, HpkeCiphertext ct, byte[] recipientPriv, byte[] groupContext)
    {
        return cs.HpkeOpen(recipientPriv, ct.KemOutput, groupContext, Array.Empty<byte>(), ct.Ciphertext);
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
