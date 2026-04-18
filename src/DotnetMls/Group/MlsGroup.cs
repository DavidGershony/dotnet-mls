using System.Security.Cryptography;
using DotnetMls.Codec;
using DotnetMls.Crypto;
using DotnetMls.KeySchedule;
using DotnetMls.Message;
using DotnetMls.Tree;
using DotnetMls.Types;

namespace DotnetMls.Group;

/// <summary>
/// The core MLS group state machine (RFC 9420).
///
/// Manages the complete lifecycle of an MLS group including:
/// - Group creation and member addition via Welcome
/// - Proposal generation (Add, Remove, Update)
/// - Commit creation and processing
/// - Application message encryption and decryption
/// - Secret export and member enumeration
///
/// Thread safety: This class is NOT thread-safe. External synchronization
/// is required if accessed from multiple threads.
/// </summary>
public sealed class MlsGroup
{
    // -- Internal state --
    private readonly ICipherSuite _cs;
    private readonly MlsGroupConfig _config;
    private byte[] _groupId;
    private ulong _epoch;
    private RatchetTree _tree;
    private uint _myLeafIndex;
    private byte[] _mySigningPrivateKey;
    private byte[] _myHpkePrivateKey; // leaf HPKE private key
    private GroupContext _groupContext;
    private KeyScheduleEpoch _keySchedule;
    private TranscriptHash _transcriptHash;
    private SecretTree _secretTree;
    private Extension[] _extensions;

    // Pending commit state (for the committer to merge after acknowledgement)
    private PendingCommitState? _pendingCommit;

    // Proposal cache for standalone proposals referenced by hash in Commits
    private readonly Dictionary<string, (Proposal Proposal, uint SenderLeaf)> _proposalCache = new();

    // PSK stores for resumption and external PSKs
    private readonly Dictionary<ulong, byte[]> _resumptionPsks = new();
    private readonly Dictionary<string, byte[]> _externalPsks = new();

    // -- Properties --

    /// <summary>The unique group identifier.</summary>
    public byte[] GroupId => _groupId;

    /// <summary>The current epoch number.</summary>
    public ulong Epoch => _epoch;

    /// <summary>The local member's leaf index in the ratchet tree.</summary>
    public uint MyLeafIndex => _myLeafIndex;

    /// <summary>The cipher suite identifier used by this group.</summary>
    public ushort CipherSuiteId => _cs.Id;

    /// <summary>The current ratchet tree.</summary>
    public RatchetTree Tree => _tree;

    /// <summary>The current group context.</summary>
    public GroupContext GroupContext => _groupContext;

    /// <summary>The current epoch's key schedule.</summary>
    public KeyScheduleEpoch KeySchedule => _keySchedule;

    // -- Create a new group --

    /// <summary>
    /// Creates a new MLS group with the caller as the sole member.
    /// </summary>
    /// <param name="cs">The cipher suite to use for the group.</param>
    /// <param name="identity">The creator's identity bytes for BasicCredential.</param>
    /// <param name="signingPrivateKey">The creator's private signing key.</param>
    /// <param name="signingPublicKey">The creator's public signing key.</param>
    /// <param name="groupId">The group identifier, or null to generate a random one.</param>
    /// <param name="extensions">Group-level extensions, or null for none.</param>
    /// <param name="config">Group configuration, or null for defaults.</param>
    /// <returns>A new MlsGroup with the creator as leaf 0.</returns>
    public static MlsGroup CreateGroup(
        ICipherSuite cs,
        byte[] identity,
        byte[] signingPrivateKey,
        byte[] signingPublicKey,
        byte[]? groupId = null,
        Extension[]? extensions = null,
        MlsGroupConfig? config = null)
    {
        config ??= MlsGroupConfig.Default;
        groupId ??= cs.RandomBytes(16);
        extensions ??= Array.Empty<Extension>();

        var group = new MlsGroup(cs, config);
        group._groupId = groupId;
        group._epoch = 0;
        group._mySigningPrivateKey = signingPrivateKey;
        group._extensions = extensions;

        // Generate HPKE key pair for our leaf
        var (hpkePriv, hpkePub) = cs.GenerateHpkeKeyPair();
        group._myHpkePrivateKey = hpkePriv;

        // Create our leaf node
        var leafNode = new LeafNode
        {
            EncryptionKey = hpkePub,
            SignatureKey = signingPublicKey,
            Credential = new BasicCredential(identity),
            Capabilities = CreateDefaultCapabilities(cs),
            Source = LeafNodeSource.Commit, // group creator uses Commit source
            Extensions = Array.Empty<Extension>()
        };
        // Create the tree with our leaf (need index for TBS signing)
        group._tree = new RatchetTree();
        group._myLeafIndex = group._tree.AddLeaf(leafNode);

        // Sign the leaf node (creator is always leaf 0)
        SignLeafNode(cs, leafNode, signingPrivateKey, groupId, group._myLeafIndex);

        // Initialize transcript hash (epoch 0: both hashes start empty)
        group._transcriptHash = new TranscriptHash(cs.HashSize);

        // Compute tree hash
        var root = TreeMath.Root(group._tree.LeafCount);
        byte[] treeHash = group._tree.ComputeTreeHash(cs, root);

        // Build group context
        group._groupContext = new GroupContext
        {
            Version = ProtocolVersion.Mls10,
            CipherSuite = cs.Id,
            GroupId = groupId,
            Epoch = 0,
            TreeHash = treeHash,
            ConfirmedTranscriptHash = group._transcriptHash.ConfirmedTranscriptHash,
            Extensions = extensions
        };

        // Derive key schedule (epoch 0: random init_secret, zero commit_secret)
        byte[] initSecret = cs.RandomBytes(cs.SecretSize);
        byte[] commitSecret = new byte[cs.SecretSize]; // all zeros
        byte[] serializedContext = SerializeGroupContext(group._groupContext);

        group._keySchedule = KeyScheduleEpoch.Create(cs, initSecret, commitSecret, serializedContext);
        group._secretTree = new SecretTree(cs, group._keySchedule.EncryptionSecret, group._tree.LeafCount);

        return group;
    }

    // -- Create a KeyPackage --

    /// <summary>
    /// Creates a KeyPackage for a prospective member to use when being added to a group.
    /// </summary>
    /// <param name="cs">The cipher suite.</param>
    /// <param name="identity">The member's identity bytes for BasicCredential.</param>
    /// <param name="signingPrivateKey">The member's private signing key.</param>
    /// <param name="signingPublicKey">The member's public signing key.</param>
    /// <param name="initPrivateKey">Output: the init HPKE private key (caller must store this).</param>
    /// <param name="hpkePrivateKey">Output: the leaf HPKE private key (caller must store this).</param>
    /// <returns>The signed KeyPackage.</returns>
    public static KeyPackage CreateKeyPackage(
        ICipherSuite cs,
        byte[] identity,
        byte[] signingPrivateKey,
        byte[] signingPublicKey,
        out byte[] initPrivateKey,
        out byte[] hpkePrivateKey,
        ushort[]? supportedExtensionTypes = null)
    {
        // Generate init key pair (one-time use for Welcome)
        var (initPriv, initPub) = cs.GenerateHpkeKeyPair();
        initPrivateKey = initPriv;

        // Generate leaf HPKE key pair
        var (hpkePriv, hpkePub) = cs.GenerateHpkeKeyPair();
        hpkePrivateKey = hpkePriv;

        var capabilities = CreateDefaultCapabilities(cs);
        if (supportedExtensionTypes is { Length: > 0 })
            capabilities.Extensions = supportedExtensionTypes;

        var leafNode = new LeafNode
        {
            EncryptionKey = hpkePub,
            SignatureKey = signingPublicKey,
            Credential = new BasicCredential(identity),
            Capabilities = capabilities,
            Source = LeafNodeSource.KeyPackage,
            Lifetime = new Lifetime(0, ulong.MaxValue),
            Extensions = Array.Empty<Extension>()
        };

        // Sign leaf node for KeyPackage (no group_id context for key packages)
        SignLeafNode(cs, leafNode, signingPrivateKey, null);

        var keyPackage = new KeyPackage
        {
            Version = ProtocolVersion.Mls10,
            CipherSuite = cs.Id,
            InitKey = initPub,
            LeafNode = leafNode,
            Extensions = Array.Empty<Extension>()
        };

        // Sign the key package
        byte[] kpContent = TlsCodec.Serialize(writer =>
        {
            writer.WriteUint16(keyPackage.Version);
            writer.WriteUint16(keyPackage.CipherSuite);
            writer.WriteOpaqueV(keyPackage.InitKey);
            keyPackage.LeafNode.WriteTo(writer);
            writer.WriteVectorV(inner =>
            {
                foreach (var ext in keyPackage.Extensions)
                    ext.WriteTo(inner);
            });
        });
        keyPackage.Signature = cs.SignWithLabel(signingPrivateKey, "KeyPackageTBS", kpContent);

        return keyPackage;
    }

    // -- Proposal generation --

    /// <summary>
    /// Creates Add proposals for the given key packages.
    /// </summary>
    /// <param name="keyPackages">The key packages of members to add.</param>
    /// <returns>A list of Add proposals.</returns>
    public List<Proposal> ProposeAdd(KeyPackage[] keyPackages)
    {
        return keyPackages.Select(kp => (Proposal)new AddProposal(kp)).ToList();
    }

    /// <summary>
    /// Creates a Remove proposal to remove the member at the given leaf index.
    /// </summary>
    /// <param name="leafIndex">The leaf index of the member to remove.</param>
    /// <returns>A Remove proposal.</returns>
    public Proposal ProposeRemove(uint leafIndex)
    {
        return new RemoveProposal(leafIndex);
    }

    /// <summary>
    /// Creates a self-update proposal with new key material.
    /// </summary>
    /// <returns>A tuple of (Update proposal, new HPKE private key for the caller to store).</returns>
    public (Proposal proposal, byte[] newHpkePrivateKey) ProposeSelfUpdate()
    {
        var (newHpkePriv, newHpkePub) = _cs.GenerateHpkeKeyPair();
        var currentLeaf = _tree.GetLeaf(_myLeafIndex)!;

        var newLeafNode = new LeafNode
        {
            EncryptionKey = newHpkePub,
            SignatureKey = currentLeaf.SignatureKey,
            Credential = currentLeaf.Credential,
            Capabilities = currentLeaf.Capabilities,
            Source = LeafNodeSource.Update,
            Extensions = currentLeaf.Extensions
        };
        SignLeafNode(_cs, newLeafNode, _mySigningPrivateKey, _groupId, _myLeafIndex);

        return (new UpdateProposal(newLeafNode), newHpkePriv);
    }

    // -- Commit --

    /// <summary>
    /// Creates a Commit message that applies the given proposals.
    /// The commit includes an UpdatePath for forward secrecy.
    /// After sending, call <see cref="MergePendingCommit"/> to apply the new state.
    /// </summary>
    /// <param name="proposals">The proposals to include, or null for an empty commit.</param>
    /// <returns>A tuple of (PublicMessage containing the Commit, Welcome for new members or null).</returns>
    public (PrivateMessage commitMessage, Welcome? welcome) Commit(List<Proposal>? proposals = null)
    {
        proposals ??= new List<Proposal>();

        // Clone the tree for tentative state
        var tentativeTree = _tree.Clone();

        // Apply proposals to the tentative tree and collect new members
        var newMembers = new List<(KeyPackage kp, byte[] initKey)>();
        var addedLeaves = new List<uint>();
        var tentativeExtensions = (Extension[])_extensions.Clone();

        foreach (var proposal in proposals)
        {
            if (proposal is AddProposal add)
            {
                var leafNode = add.KeyPackage.LeafNode;
                ValidateAddLeafCapabilities(leafNode, ProtocolVersion.Mls10, _cs.Id);
                uint newIdx = tentativeTree.AddLeaf(leafNode);
                addedLeaves.Add(newIdx);
                newMembers.Add((add.KeyPackage, add.KeyPackage.InitKey));
            }
            else if (proposal is RemoveProposal remove)
            {
                tentativeTree.BlankLeaf(remove.LeafIndex);
            }
            else if (proposal is GroupContextExtensionsProposal gce)
            {
                ValidateGroupContextExtensions(gce.Extensions, tentativeTree);
                tentativeExtensions = gce.Extensions;
            }
            // UpdateProposal is handled via the UpdatePath below
        }

        // Generate new leaf node for the committer with fresh key material.
        // EncryptionKey is a placeholder — Encap will overwrite it with the derived key.
        var (_, newHpkePub) = _cs.GenerateHpkeKeyPair();
        var currentLeaf = _tree.GetLeaf(_myLeafIndex)!;
        // OpenMLS valn1210: the UpdatePath leaf node capabilities MUST support all
        // GroupContext extensions. Merge the leaf's own extension types plus all
        // GroupContext extension types into the capabilities.
        var caps = currentLeaf.Capabilities;
        var requiredExtTypes = currentLeaf.Extensions
            .Select(e => e.ExtensionType)
            .Concat(_groupContext.Extensions.Select(e => e.ExtensionType))
            .Distinct()
            .ToArray();
        if (requiredExtTypes.Any(t => !caps.Extensions.Contains(t)))
        {
            caps = new Capabilities
            {
                Versions = caps.Versions,
                CipherSuites = caps.CipherSuites,
                Extensions = caps.Extensions.Union(requiredExtTypes).ToArray(),
                Proposals = caps.Proposals,
                Credentials = caps.Credentials
            };
        }

        var newLeafNode = new LeafNode
        {
            EncryptionKey = newHpkePub,
            SignatureKey = currentLeaf.SignatureKey,
            Credential = currentLeaf.Credential,
            Capabilities = caps,
            Source = LeafNodeSource.Commit,
            Extensions = currentLeaf.Extensions
        };
        // NOTE: Do NOT sign yet — Encap will set the final EncryptionKey,
        // and we need to compute parent_hash first.

        // Build tentative group context for TreeKEM.
        // RFC 9420 §12.4.2: The provisional GroupContext uses epoch+1, the
        // tree hash AFTER public state is applied, and the OLD confirmed_transcript_hash.
        var tentativeContext = new GroupContext
        {
            Version = ProtocolVersion.Mls10,
            CipherSuite = _cs.Id,
            GroupId = _groupId,
            Epoch = _epoch + 1,
            TreeHash = Array.Empty<byte>(), // filled by factory below
            ConfirmedTranscriptHash = _groupContext.ConfirmedTranscriptHash,
            Extensions = tentativeExtensions
        };

        // Save tree BEFORE Encap modifies it (for sibling tree hash in parent_hash)
        var originalTree = tentativeTree.Clone();

        // Run TreeKEM Encap: derives path secrets, sets parent nodes, and
        // overwrites newLeafNode.EncryptionKey with the Encap-derived leaf key.
        // The groupContext factory is called after the tree is updated with all
        // new public keys (Phase 1) but before encryption (Phase 2).
        // Inside the factory, we compute parent hashes, add unmerged leaves for
        // added members, and sign the leaf so the tree hash matches ProcessCommitCore.
        var (updatePath, newHpkePriv, commitSecret) = TreeKem.Encap(
            tentativeTree, _myLeafIndex, _cs, newLeafNode, () =>
            {
                // Compute filtered direct path: exclude nodes whose copath child
                // has empty resolution. Uses FULL resolution (including new members)
                // per RFC 9420 §4.1.2. New members are only excluded from HPKE
                // encryption recipients, not from path filtering.
                var dp = TreeMath.DirectPath(_myLeafIndex, tentativeTree.LeafCount);
                var addedNodeIndices = new HashSet<uint>(addedLeaves.Select(l => TreeMath.LeafToNode(l)));
                var cp = TreeMath.Copath(_myLeafIndex, tentativeTree.LeafCount);
                var fdp = new List<uint>();
                for (int i = 0; i < dp.Length; i++)
                {
                    var res = tentativeTree.Resolution(cp[i]);
                    if (res.Count > 0)
                        fdp.Add(dp[i]);
                }

                // Compute parent hashes on the filtered DP (from root down)
                for (int i = fdp.Count - 2; i >= 0; i--)
                {
                    uint nodeIdx = fdp[i];
                    uint parentIdx = fdp[i + 1];
                    uint siblingIdx = nodeIdx < parentIdx
                        ? TreeMath.Right(parentIdx)
                        : TreeMath.Left(parentIdx);
                    byte[] siblingTreeHash = originalTree.ComputeTreeHash(_cs, siblingIdx);
                    byte[] parentHash = tentativeTree.ComputeParentHash(_cs, parentIdx, siblingTreeHash);
                    tentativeTree.GetParent(nodeIdx)!.ParentHash = parentHash;
                }

                // Compute the leaf's parent_hash
                if (fdp.Count > 0)
                {
                    uint firstParent = fdp[0];
                    uint leafNodeIdx = TreeMath.LeafToNode(_myLeafIndex);
                    uint lc = TreeMath.Left(firstParent);
                    uint rc = TreeMath.Right(firstParent);
                    uint siblingOfFirst = (leafNodeIdx == lc) ? rc : lc;
                    byte[] siblingTreeHash = originalTree.ComputeTreeHash(_cs, siblingOfFirst);
                    newLeafNode.ParentHash = tentativeTree.ComputeParentHash(_cs, firstParent, siblingTreeHash);
                }

                // Sign the leaf with final EncryptionKey, ParentHash, and group context
                SignLeafNode(_cs, newLeafNode, _mySigningPrivateKey, _groupId, _myLeafIndex);
                tentativeTree.SetLeaf(_myLeafIndex, newLeafNode);

                // Add unmerged leaves for added members on non-filtered ancestors
                var fdpSet = new HashSet<uint>(fdp);
                foreach (uint addedLeaf in addedLeaves)
                {
                    var addedDp2 = TreeMath.DirectPath(addedLeaf, tentativeTree.LeafCount);
                    foreach (uint dpNode in addedDp2)
                    {
                        if (!fdpSet.Contains(dpNode))
                        {
                            var pn = tentativeTree.GetParent(dpNode);
                            if (pn != null)
                                pn.UnmergedLeaves.Add(addedLeaf);
                        }
                    }
                }

                var root = TreeMath.Root(tentativeTree.LeafCount);
                tentativeContext.TreeHash = tentativeTree.ComputeTreeHash(_cs, root);
                return SerializeGroupContext(tentativeContext);
            }, addedLeaves);

        // Parent hashes and leaf signing are done inside the Encap factory above.
        // Update the UpdatePath's leaf node to the signed version
        updatePath = new UpdatePath(newLeafNode, updatePath.Nodes);

        // Build the Commit message
        var proposalOrRefs = proposals.Select(p =>
            (ProposalOrRef)new InlineProposal(p)).ToArray();
        var commit = new Commit(proposalOrRefs, updatePath);

        // Serialize the commit content
        byte[] commitBytes = TlsCodec.Serialize(writer => commit.WriteTo(writer));

        // Build FramedContent for the commit
        var framedContent = new FramedContent
        {
            GroupId = _groupId,
            Epoch = _epoch,
            Sender = new Sender(SenderType.Member, _myLeafIndex),
            AuthenticatedData = Array.Empty<byte>(),
            ContentType = ContentType.Commit,
            Content = commitBytes
        };

        // Build the FramedContentTBS for signing
        byte[] serializedCurrentContext = SerializeGroupContext(_groupContext);
        byte[] tbs = MessageFraming.BuildFramedContentTbs(
            WireFormat.MlsPrivateMessage, framedContent, serializedCurrentContext);

        // Sign the FramedContent BEFORE computing transcript hash,
        // since ConfirmedTranscriptHashInput includes the signature (RFC 9420 §8.2).
        byte[] signature = _cs.SignWithLabel(_mySigningPrivateKey, "FramedContentTBS", tbs);

        // Compute new confirmed transcript hash per RFC 9420 §8.2:
        // ConfirmedTranscriptHashInput = wire_format || content || signature
        byte[] confirmedInput = MessageFraming.BuildConfirmedTranscriptHashInput(
            WireFormat.MlsPrivateMessage, framedContent, signature);
        var tentativeTranscriptHash = _transcriptHash.Clone();

        // Compute tree hash of the updated tree
        var root = TreeMath.Root(tentativeTree.LeafCount);
        byte[] treeHash = tentativeTree.ComputeTreeHash(_cs, root);

        // Build tentative confirmed hash to derive key schedule and confirmation tag
        byte[] newConfirmedTranscriptHash = _cs.Hash(
            Concat(_transcriptHash.InterimTranscriptHash, confirmedInput));

        // Finalize the group context with real values
        tentativeContext.TreeHash = treeHash;
        tentativeContext.ConfirmedTranscriptHash = newConfirmedTranscriptHash;
        byte[] newContextBytes = SerializeGroupContext(tentativeContext);

        // Derive the new key schedule
        var newKeySchedule = KeyScheduleEpoch.Create(
            _cs, _keySchedule.InitSecret, commitSecret, newContextBytes);

        // Compute confirmation tag
        byte[] confirmationTag = newKeySchedule.ComputeConfirmationTag(
            _cs, newConfirmedTranscriptHash);

        // Update transcript hash with both confirmed and interim
        tentativeTranscriptHash.Update(_cs, confirmedInput, confirmationTag);
        byte[] newInterimTranscriptHash = tentativeTranscriptHash.InterimTranscriptHash;

        var auth = new FramedContentAuthData(signature, confirmationTag);

        // Encrypt as PrivateMessage (matching Rust MDK / marmot-ts wire format)
        var privateMessage = MessageFraming.EncryptPrivateMessage(
            framedContent, auth, _cs, _secretTree,
            _keySchedule.SenderDataSecret, _myLeafIndex, _config.Padding);

        // Build Welcome for new members
        Welcome? welcome = null;
        if (newMembers.Count > 0)
        {
            welcome = BuildWelcome(
                tentativeTree, tentativeContext, newKeySchedule,
                newMembers, confirmationTag);
        }

        // Store pending commit state
        _pendingCommit = new PendingCommitState
        {
            Tree = tentativeTree,
            Epoch = _epoch + 1,
            GroupContext = tentativeContext,
            KeySchedule = newKeySchedule,
            ConfirmedTranscriptHash = newConfirmedTranscriptHash,
            InterimTranscriptHash = newInterimTranscriptHash,
            MyHpkePrivateKey = newHpkePriv,
            CommitSecret = commitSecret,
            Extensions = tentativeExtensions
        };

        return (privateMessage, welcome);
    }

    // -- Merge pending commit --

    /// <summary>
    /// Merges the pending commit state, transitioning the group to the new epoch.
    /// Call this after the commit has been acknowledged or for self-commit scenarios.
    /// </summary>
    /// <exception cref="InvalidOperationException">Thrown when there is no pending commit.</exception>
    public void MergePendingCommit()
    {
        if (_pendingCommit == null)
            throw new InvalidOperationException("No pending commit to merge.");

        _tree = _pendingCommit.Tree;
        _epoch = _pendingCommit.Epoch;
        _groupContext = _pendingCommit.GroupContext;
        _keySchedule = _pendingCommit.KeySchedule;
        _transcriptHash = new TranscriptHash(
            _pendingCommit.ConfirmedTranscriptHash,
            _pendingCommit.InterimTranscriptHash);
        _myHpkePrivateKey = _pendingCommit.MyHpkePrivateKey;
        _extensions = _pendingCommit.Extensions;
        _secretTree = new SecretTree(
            _cs, _keySchedule.EncryptionSecret, _tree.LeafCount);
        _pendingCommit = null;
    }

    /// <summary>
    /// Clears the pending commit without applying it.
    /// </summary>
    public void ClearPendingCommit() => _pendingCommit = null;

    // -- Process a received commit --

    /// <summary>
    /// Processes a Commit from another group member, transitioning the group to the new epoch.
    /// Verifies the signature, confirmation tag, and applies all proposals.
    /// </summary>
    /// <param name="commitMessage">The PublicMessage containing the Commit.</param>
    /// <exception cref="ArgumentException">Thrown when the message is not a Commit.</exception>
    /// <exception cref="InvalidOperationException">
    /// Thrown when the sender leaf is blank, the signature is invalid,
    /// or the confirmation tag is invalid.
    /// </exception>
    public void ProcessCommit(PrivateMessage commitMessage)
    {
        // Decrypt the PrivateMessage to recover FramedContent and auth
        var (content, auth) = MessageFraming.DecryptPrivateMessage(
            commitMessage, _cs, _secretTree, _keySchedule.SenderDataSecret);

        ProcessCommitCore(content, auth, WireFormat.MlsPrivateMessage);
    }

    /// <summary>
    /// Processes a Commit received as a PublicMessage, transitioning to the new epoch.
    /// Verifies the membership tag, signature, confirmation tag, and applies all proposals.
    /// </summary>
    public void ProcessCommit(PublicMessage commitMessage)
    {
        var content = commitMessage.Content;
        var auth = commitMessage.Auth;

        byte[] serializedContext = SerializeGroupContext(_groupContext);

        if (content.Sender.SenderType == SenderType.NewMemberCommit)
        {
            // RFC 9420 §12.4.3.2: an external joiner's commit. The signer key
            // comes from the UpdatePath's LeafNode (they're not yet in the tree),
            // and there is no membership tag because they're not yet a member.
            var parsedCommit = Types.Commit.ReadFrom(new TlsReader(content.Content));
            if (parsedCommit.Path == null)
                throw new InvalidOperationException("External commit must include an UpdatePath.");

            byte[] tbs = MessageFraming.BuildFramedContentTbs(
                WireFormat.MlsPublicMessage, content, serializedContext);
            if (!_cs.VerifyWithLabel(
                    parsedCommit.Path.LeafNode.SignatureKey, "FramedContentTBS", tbs, auth.Signature))
                throw new InvalidOperationException("Invalid external commit signature.");
        }
        else
        {
            bool valid = MessageFraming.VerifyPublicMessage(
                commitMessage,
                _tree.GetLeaf(content.Sender.LeafIndex)!.SignatureKey,
                serializedContext,
                _cs,
                _keySchedule.MembershipKey);
            if (!valid)
                throw new InvalidOperationException("Invalid public message signature or membership tag.");
        }

        ProcessCommitCore(content, auth, WireFormat.MlsPublicMessage);
    }

    /// <summary>
    /// Caches a standalone proposal (received as a PublicMessage) for later reference
    /// in a Commit via ProposalReference.
    /// </summary>
    public void CacheProposal(PublicMessage proposalMessage)
    {
        var content = proposalMessage.Content;
        var auth = proposalMessage.Auth;

        // Build AuthenticatedContent = wire_format || content || auth
        byte[] authContent = TlsCodec.Serialize(w =>
        {
            w.WriteUint16((ushort)WireFormat.MlsPublicMessage);
            content.WriteTo(w);
            auth.WriteTo(w, content.ContentType);
        });

        // Compute ProposalRef = RefHash("MLS 1.0 Proposal Reference", AuthenticatedContent)
        byte[] propRef = _cs.RefHash("MLS 1.0 Proposal Reference", authContent);
        string refKey = Convert.ToHexString(propRef).ToLowerInvariant();

        var proposal = Proposal.ReadFrom(new TlsReader(content.Content));
        _proposalCache[refKey] = (proposal, content.Sender.LeafIndex);
    }

    /// <summary>
    /// Core commit processing shared between PrivateMessage and PublicMessage paths.
    /// Implements RFC 9420 §12.4 commit processing.
    /// </summary>
    private void ProcessCommitCore(
        FramedContent content,
        FramedContentAuthData auth,
        WireFormat wireFormat)
    {
        if (content.ContentType != ContentType.Commit)
            throw new ArgumentException("Not a commit message.");

        bool isExternalCommit = content.Sender.SenderType == SenderType.NewMemberCommit;
        byte[] serializedContext = SerializeGroupContext(_groupContext);

        // Parse the commit
        var commit = Types.Commit.ReadFrom(new TlsReader(content.Content));

        uint senderLeaf;
        if (isExternalCommit)
        {
            // External joiner's signature is already verified by the caller using
            // commit.Path.LeafNode.SignatureKey (they aren't in the tree yet).
            if (commit.Path == null)
                throw new InvalidOperationException("External commit must include an UpdatePath.");
            senderLeaf = uint.MaxValue; // placeholder; resolved after we pick the slot
        }
        else
        {
            senderLeaf = content.Sender.LeafIndex;
            var senderLeafNode = _tree.GetLeaf(senderLeaf);
            if (senderLeafNode == null)
                throw new InvalidOperationException("Sender leaf is blank.");

            byte[] senderPublicKey = senderLeafNode.SignatureKey;
            byte[] tbs = MessageFraming.BuildFramedContentTbs(
                wireFormat, content, serializedContext);
            if (!_cs.VerifyWithLabel(senderPublicKey, "FramedContentTBS", tbs, auth.Signature))
                throw new InvalidOperationException("Invalid commit signature.");
        }

        // Clone tree for tentative processing
        var tentativeTree = _tree.Clone();
        var tentativeExtensions = (Extension[])_extensions.Clone();

        // ---- RFC 9420 §12.4: Resolve proposals by type ----
        // Proposals are applied in type order: GCE → Update → Remove (desc) → Add
        // PSK proposals don't modify the tree but are collected in commit order.
        var pskIds = new List<PreSharedKeyId>();
        var updates = new List<(UpdateProposal Prop, uint SenderLeaf)>();
        var removes = new List<RemoveProposal>();
        var adds = new List<AddProposal>();
        var gces = new List<GroupContextExtensionsProposal>();
        ExternalInitProposal? externalInit = null;

        foreach (var por in commit.Proposals)
        {
            Proposal proposal;
            uint proposerLeaf = senderLeaf;
            if (por is InlineProposal inline)
            {
                proposal = inline.Proposal;
            }
            else if (por is ProposalReference pref)
            {
                string refKey = Convert.ToHexString(pref.Reference).ToLowerInvariant();
                if (!_proposalCache.TryGetValue(refKey, out var cached))
                    throw new InvalidOperationException($"Unknown proposal reference: {refKey}");
                proposal = cached.Proposal;
                proposerLeaf = cached.SenderLeaf;
            }
            else
            {
                continue;
            }

            if (proposal is AddProposal add) adds.Add(add);
            else if (proposal is RemoveProposal remove) removes.Add(remove);
            else if (proposal is UpdateProposal update) updates.Add((update, proposerLeaf));
            else if (proposal is PreSharedKeyProposal pskProp) pskIds.Add(pskProp.Psk);
            else if (proposal is GroupContextExtensionsProposal gce) gces.Add(gce);
            else if (proposal is ExternalInitProposal ei) externalInit = ei;
        }

        if (isExternalCommit && externalInit == null)
            throw new InvalidOperationException(
                "External commit is missing an ExternalInit proposal.");
        if (!isExternalCommit && externalInit != null)
            throw new InvalidOperationException(
                "ExternalInit proposal appeared in a non-external commit.");

        // Apply in type order: GCE → Update → Remove → Add
        foreach (var gce in gces)
        {
            ValidateGroupContextExtensions(gce.Extensions, tentativeTree);
            tentativeExtensions = gce.Extensions;
        }

        foreach (var (update, propLeaf) in updates)
        {
            // RFC 9420 §12.1.2: verify the Update proposal's LeafNode signature,
            // and confirm the signer matches the proposer's existing leaf.
            if (update.LeafNode.Source != LeafNodeSource.Update)
                throw new InvalidOperationException(
                    $"Update proposal LeafNode source must be Update, got {update.LeafNode.Source}.");
            var currentLeafAtSender = tentativeTree.GetLeaf(propLeaf);
            if (currentLeafAtSender == null)
                throw new InvalidOperationException(
                    $"Update proposal from blank leaf {propLeaf}.");
            if (!currentLeafAtSender.SignatureKey.AsSpan().SequenceEqual(update.LeafNode.SignatureKey))
                throw new InvalidOperationException(
                    $"Update proposal signature key does not match leaf {propLeaf}.");
            if (!VerifyLeafNodeSignature(_cs, update.LeafNode, _groupId, propLeaf))
                throw new InvalidOperationException(
                    $"Invalid Update proposal LeafNode signature at leaf {propLeaf}.");

            tentativeTree.SetLeaf(propLeaf, update.LeafNode);
            var updateDp = TreeMath.DirectPath(propLeaf, tentativeTree.LeafCount);
            foreach (uint dpNode in updateDp)
                tentativeTree.SetParent(dpNode, null);
        }

        foreach (var remove in removes.OrderByDescending(r => r.LeafIndex))
        {
            // Clean unmerged_leaves for removed member
            for (int ni = 1; ni < tentativeTree.NodeCount; ni += 2)
            {
                var pn = tentativeTree.GetParent((uint)ni);
                if (pn != null)
                    pn.UnmergedLeaves.Remove(remove.LeafIndex);
            }
            uint removeNodeIdx = TreeMath.LeafToNode(remove.LeafIndex);
            tentativeTree.SetNode(removeNodeIdx, new TreeNode.Leaf(null));
            var removeDp = TreeMath.DirectPath(remove.LeafIndex, tentativeTree.LeafCount);
            foreach (uint dpNode in removeDp)
                tentativeTree.SetParent(dpNode, null);
        }

        // Trim tree after all removes
        if (removes.Count > 0)
            tentativeTree.TrimTree();

        var addedLeaves = new List<uint>();
        foreach (var add in adds)
        {
            ValidateAddLeafCapabilities(add.KeyPackage.LeafNode, ProtocolVersion.Mls10, _cs.Id);
            uint newLeafIdx = tentativeTree.AddLeaf(add.KeyPackage.LeafNode);
            addedLeaves.Add(newLeafIdx);
        }

        // External commit: place the joiner into the tree. RFC 9420 §12.4.3.2:
        // - If the commit removes an existing leaf (their prior membership),
        //   that leaf's slot is reused.
        // - Otherwise, they take a blank slot or extend the tree, like AddLeaf.
        if (isExternalCommit)
        {

            ValidateAddLeafCapabilities(commit.Path!.LeafNode, ProtocolVersion.Mls10, _cs.Id);
            uint joinerLeaf;
            if (removes.Count > 0)
            {
                joinerLeaf = removes.OrderBy(r => r.LeafIndex).First().LeafIndex;
                tentativeTree.SetLeaf(joinerLeaf, commit.Path.LeafNode);
            }
            else
            {
                joinerLeaf = tentativeTree.AddLeaf(commit.Path.LeafNode);
            }
            senderLeaf = joinerLeaf;
            addedLeaves.Add(joinerLeaf);
        }

        // ---- Process UpdatePath if present ----
        byte[] commitSecret;
        if (commit.Path != null)
        {
            // Save tree state AFTER proposals but BEFORE UpdatePath for sibling tree hash
            var originalTree = tentativeTree.Clone();

            // RFC 9420 §7.2: a Commit-source LeafNode must carry a parent_hash.
            var pathLeaf = commit.Path.LeafNode;
            if (pathLeaf.Source != LeafNodeSource.Commit)
                throw new InvalidOperationException(
                    $"UpdatePath LeafNode source must be Commit, got {pathLeaf.Source}.");
            if (pathLeaf.ParentHash.Length == 0)
                throw new InvalidOperationException(
                    "UpdatePath LeafNode has empty parent_hash.");

            // Apply UpdatePath public state to tentative tree
            tentativeTree.SetLeaf(senderLeaf, commit.Path.LeafNode);
            var senderDp = TreeMath.DirectPath(senderLeaf, tentativeTree.LeafCount);
            var senderCopath = TreeMath.Copath(senderLeaf, tentativeTree.LeafCount);
            foreach (uint n in senderDp)
                tentativeTree.SetParent(n, null);

            // RFC 9420 §4.1.2: Filtered direct path excludes entries whose copath
            // child has empty resolution. Resolution uses the FULL set of nodes
            // (including newly added members). New members are only excluded from
            // the HPKE encryption recipients, not from the path filtering itself.
            var addedNodeIndices = new HashSet<uint>(addedLeaves.Select(l => TreeMath.LeafToNode(l)));
            var filteredDp = new List<uint>();
            var filteredCopath = new List<uint>();
            for (int i = 0; i < senderDp.Length; i++)
            {
                var res = tentativeTree.Resolution(senderCopath[i]);
                if (res.Count > 0)
                {
                    filteredDp.Add(senderDp[i]);
                    filteredCopath.Add(senderCopath[i]);
                }
            }

            // Set public keys from UpdatePath on filtered direct path nodes
            for (int i = 0; i < filteredDp.Count; i++)
            {
                tentativeTree.SetParent(filteredDp[i], new ParentNode
                {
                    EncryptionKey = commit.Path.Nodes[i].EncryptionKey,
                    UnmergedLeaves = new List<uint>(),
                });
            }

            // Compute parent hashes (from root down) — needed before provisional tree hash
            for (int i = filteredDp.Count - 2; i >= 0; i--)
            {
                uint nodeIdx = filteredDp[i];
                uint parentIdx = filteredDp[i + 1];
                uint siblingIdx = nodeIdx < parentIdx
                    ? TreeMath.Right(parentIdx)
                    : TreeMath.Left(parentIdx);
                byte[] siblingTreeHash = originalTree.ComputeTreeHash(_cs, siblingIdx);
                byte[] parentHash = tentativeTree.ComputeParentHash(_cs, parentIdx, siblingTreeHash);
                tentativeTree.GetParent(nodeIdx)!.ParentHash = parentHash;
            }

            // RFC 9420 §12.4.2 step 5: For each added member, add to unmerged_leaves
            // of each non-blank ancestor NOT on the sender's filtered direct path.
            var filteredDpSet = new HashSet<uint>(filteredDp);
            foreach (uint addedLeaf in addedLeaves)
            {
                var addedDp = TreeMath.DirectPath(addedLeaf, tentativeTree.LeafCount);
                foreach (uint dpNode in addedDp)
                {
                    if (!filteredDpSet.Contains(dpNode))
                    {
                        var pn = tentativeTree.GetParent(dpNode);
                        if (pn != null)
                            pn.UnmergedLeaves.Add(addedLeaf);
                    }
                }
            }

            // Compute provisional tree hash for HPKE context
            // (includes parent hashes and unmerged leaves)
            uint root = TreeMath.Root(tentativeTree.LeafCount);
            byte[] provisionalTreeHash = tentativeTree.ComputeTreeHash(_cs, root);

            // RFC 9420 §12.4.2: Provisional GroupContext for EncryptWithLabel uses
            // new epoch + new tree_hash but OLD confirmed_transcript_hash.
            var provisionalGroupContext = new GroupContext
            {
                Version = ProtocolVersion.Mls10,
                CipherSuite = _cs.Id,
                GroupId = _groupId,
                Epoch = _epoch + 1,
                TreeHash = provisionalTreeHash,
                ConfirmedTranscriptHash = _groupContext.ConfirmedTranscriptHash,
                Extensions = tentativeExtensions,
            };
            byte[] provisionalCtxBytes = SerializeGroupContext(provisionalGroupContext);

            // Build EncryptWithLabel info: { opaque label<V>; opaque content<V>; }
            byte[] provisionalEncryptInfo = TlsCodec.Serialize(w =>
            {
                w.WriteOpaqueV(System.Text.Encoding.UTF8.GetBytes("MLS 1.0 UpdatePathNode"));
                w.WriteOpaqueV(provisionalCtxBytes);
            });

            // Find our decryption position in the filtered copath
            // Build private key map from our leaf + known parent node keys
            var myPrivateKeys = new Dictionary<uint, byte[]>();
            uint myNodeIdx = TreeMath.LeafToNode(_myLeafIndex);
            myPrivateKeys[myNodeIdx] = _myHpkePrivateKey;
            var myDp = TreeMath.DirectPath(_myLeafIndex, _tree.LeafCount);
            foreach (uint dpNode in myDp)
            {
                var pn = _tree.GetParent(dpNode);
                if (pn?.PrivateKey != null)
                    myPrivateKeys[dpNode] = pn.PrivateKey;
            }

            int copathPos = -1;
            int resPos = -1;
            uint resNodeIdx = uint.MaxValue;
            for (int i = 0; i < filteredCopath.Count; i++)
            {
                var resolution = originalTree.Resolution(filteredCopath[i]);
                var encResolution = resolution.Where(n => !addedNodeIndices.Contains(n)).ToList();
                for (int j = 0; j < encResolution.Count; j++)
                {
                    if (myPrivateKeys.ContainsKey(encResolution[j]))
                    {
                        copathPos = i;
                        resPos = j;
                        resNodeIdx = encResolution[j];
                        break;
                    }
                }
                if (copathPos >= 0) break;
            }

            if (copathPos < 0)
                throw new InvalidOperationException(
                    $"Cannot find decryptable path secret for leaf {_myLeafIndex} from sender {senderLeaf}.");

            // Decrypt path secret using EncryptWithLabel format
            var ct = commit.Path.Nodes[copathPos].EncryptedPathSecret[resPos];
            byte[] myPrivKey = myPrivateKeys[resNodeIdx];
            byte[] pathSecret = _cs.HpkeOpen(myPrivKey, ct.KemOutput,
                provisionalEncryptInfo, Array.Empty<byte>(), ct.Ciphertext);

            // Derive forward: compute private keys for all filtered DP nodes from copathPos onward
            byte[] currentPathSecret = pathSecret;
            for (int i = copathPos; i < filteredDp.Count; i++)
            {
                byte[] nodeSecret = _cs.DeriveSecret(currentPathSecret, "node");
                var (nodePriv, _) = TreeKem.DeriveKeyPair(_cs, nodeSecret);
                var pn = tentativeTree.GetParent(filteredDp[i]);
                if (pn != null)
                    pn.PrivateKey = nodePriv;

                if (i < filteredDp.Count - 1)
                    currentPathSecret = _cs.DeriveSecret(currentPathSecret, "path");
            }
            commitSecret = _cs.DeriveSecret(currentPathSecret, "path");
        }
        else
        {
            // No UpdatePath: commit_secret = zeros
            commitSecret = new byte[_cs.SecretSize];

            // RFC 9420 §7.7: When there's no UpdatePath, add each newly added leaf
            // to unmerged_leaves of ALL non-blank parent nodes on its direct path.
            foreach (uint addedLeaf in addedLeaves)
            {
                var addedDp = TreeMath.DirectPath(addedLeaf, tentativeTree.LeafCount);
                foreach (uint dpNode in addedDp)
                {
                    var pn = tentativeTree.GetParent(dpNode);
                    if (pn != null)
                        pn.UnmergedLeaves.Add(addedLeaf);
                }
            }
        }

        // Compute new epoch state
        var root2 = TreeMath.Root(tentativeTree.LeafCount);
        byte[] treeHash = tentativeTree.ComputeTreeHash(_cs, root2);

        // Build ConfirmedTranscriptHashInput per RFC 9420 §8.2
        byte[] confirmedInput = MessageFraming.BuildConfirmedTranscriptHashInput(
            wireFormat, content, auth.Signature);
        byte[] newConfirmedTranscriptHash = _cs.Hash(
            Concat(_transcriptHash.InterimTranscriptHash, confirmedInput));

        var newGroupContext = new GroupContext
        {
            Version = ProtocolVersion.Mls10,
            CipherSuite = _cs.Id,
            GroupId = _groupId,
            Epoch = _epoch + 1,
            TreeHash = treeHash,
            ConfirmedTranscriptHash = newConfirmedTranscriptHash,
            Extensions = tentativeExtensions
        };
        byte[] newContextBytes = SerializeGroupContext(newGroupContext);

        // Compute PSK secret if needed
        byte[]? pskSecret = null;
        if (pskIds.Count > 0)
        {
            var pskInputs = pskIds.Select(id =>
            {
                byte[] pskValue = Array.Empty<byte>();
                if (id.PskType == PskType.Resumption &&
                    _resumptionPsks.TryGetValue(id.ResumptionEpoch, out var rPsk))
                    pskValue = rPsk;
                else if (id.PskType == PskType.External &&
                         _externalPsks.TryGetValue(Convert.ToHexString(id.PskId).ToLowerInvariant(), out var ePsk))
                    pskValue = ePsk;
                return new PskSecretDerivation.PskInput { Id = id, PskValue = pskValue };
            }).ToArray();
            pskSecret = PskSecretDerivation.ComputePskSecret(_cs, pskInputs);
        }

        byte[] initSecretForNewEpoch;
        if (isExternalCommit)
        {
            // RFC 9420 §12.4.3.2: init_secret comes from the ExternalInit shared_secret,
            // derived by HPKE Decap against external_priv (itself derived from the
            // current epoch's external_secret).
            var (externalPriv, _) = _cs.DeriveHpkeKeyPair(_keySchedule.ExternalSecret);
            initSecretForNewEpoch = _cs.HpkeDecap(externalInit!.KemOutput, externalPriv);
        }
        else
        {
            initSecretForNewEpoch = _keySchedule.InitSecret;
        }

        var newKeySchedule = KeyScheduleEpoch.Create(
            _cs, initSecretForNewEpoch, commitSecret, newContextBytes, pskSecret);

        // Verify confirmation tag
        byte[] expectedTag = newKeySchedule.ComputeConfirmationTag(
            _cs, newConfirmedTranscriptHash);
        if (auth.ConfirmationTag == null ||
            !CryptographicOperations.FixedTimeEquals(expectedTag, auth.ConfirmationTag))
            throw new InvalidOperationException("Invalid confirmation tag.");

        // Update transcript hash
        var newTranscriptHash = _transcriptHash.Clone();
        newTranscriptHash.Update(_cs, confirmedInput, auth.ConfirmationTag);

        // Apply the new state
        _tree = tentativeTree;
        _epoch = _epoch + 1;
        _groupContext = newGroupContext;
        _keySchedule = newKeySchedule;
        _transcriptHash = newTranscriptHash;
        _secretTree = new SecretTree(
            _cs, _keySchedule.EncryptionSecret, _tree.LeafCount);
        _extensions = tentativeExtensions;
        _resumptionPsks[_epoch] = newKeySchedule.ResumptionPsk;
        _proposalCache.Clear();
    }

    // -- Process Welcome (join a group) --

    /// <summary>
    /// Processes a Welcome message to join an existing group.
    /// Decrypts the group secrets, recovers the group info and ratchet tree,
    /// verifies the confirmation tag, and constructs the group state.
    /// </summary>
    /// <param name="cs">The cipher suite for the group.</param>
    /// <param name="welcome">The Welcome message to process.</param>
    /// <param name="myKeyPackage">The key package that was used to add this member.</param>
    /// <param name="myInitPrivateKey">The init HPKE private key from CreateKeyPackage.</param>
    /// <param name="myHpkePrivateKey">The leaf HPKE private key from CreateKeyPackage.</param>
    /// <param name="mySigningPrivateKey">The member's private signing key.</param>
    /// <param name="config">Group configuration, or null for defaults.</param>
    /// <param name="externalTree">Optional ratchet tree bytes if not in GroupInfo extensions.</param>
    /// <param name="externalPsks">Optional map of PSK ID hex → PSK value for external PSKs.</param>
    /// <returns>An MlsGroup representing the joined group state.</returns>
    public static MlsGroup ProcessWelcome(
        ICipherSuite cs,
        Welcome welcome,
        KeyPackage myKeyPackage,
        byte[] myInitPrivateKey,
        byte[] myHpkePrivateKey,
        byte[] mySigningPrivateKey,
        MlsGroupConfig? config = null,
        byte[]? externalTree = null,
        Dictionary<string, byte[]>? externalPsks = null)
    {
        config ??= MlsGroupConfig.Default;

        // RFC 9420 §12.4.3.1: the Welcome's cipher suite must match our KeyPackage's.
        // A mismatch means the group uses a different cipher suite than we committed to.
        if (welcome.CipherSuite != myKeyPackage.CipherSuite)
            throw new InvalidOperationException(
                $"Welcome cipher suite 0x{welcome.CipherSuite:X4} does not match KeyPackage cipher suite 0x{myKeyPackage.CipherSuite:X4}.");
        if (welcome.CipherSuite != cs.Id)
            throw new InvalidOperationException(
                $"Welcome cipher suite 0x{welcome.CipherSuite:X4} does not match provided cipher suite 0x{cs.Id:X4}.");

        // Compute our key package reference
        byte[] myKpBytes = TlsCodec.Serialize(writer => myKeyPackage.WriteTo(writer));
        var myKpRef = KeyPackageRef.Compute(cs, myKpBytes);

        // Find the encrypted group secrets for our key package
        EncryptedGroupSecrets? mySecrets = null;
        foreach (var egs in welcome.Secrets)
        {
            if (egs.NewMember.AsSpan().SequenceEqual(myKpRef.Value))
            {
                mySecrets = egs;
                break;
            }
        }

        if (mySecrets == null)
            throw new InvalidOperationException(
                "Welcome does not contain secrets for our key package.");

        // Decrypt the group secrets using our init key (EncryptWithLabel per RFC 9420 §5.1.3)
        byte[] hpkeInfo = BuildEncryptContext("Welcome", welcome.EncryptedGroupInfo);
        byte[] groupSecretsBytes = cs.HpkeOpen(
            myInitPrivateKey,
            mySecrets.EncryptedGroupSecretsValue.KemOutput,
            hpkeInfo,
            Array.Empty<byte>(), // aad
            mySecrets.EncryptedGroupSecretsValue.Ciphertext);

        var gsReader = new TlsReader(groupSecretsBytes);
        var groupSecrets = GroupSecrets.ReadFrom(gsReader);

        // Derive welcome_secret via intermediate_secret per RFC 9420 §8
        // Compute PSK secret from GroupSecrets.psks and external PSKs
        byte[] pskSecret;
        if (groupSecrets.Psks.Length > 0)
        {
            var pskInputs = groupSecrets.Psks.Select(id =>
            {
                byte[] pskValue = Array.Empty<byte>();
                if (id.PskType == PskType.External && externalPsks != null)
                {
                    string pskIdHex = Convert.ToHexString(id.PskId).ToLowerInvariant();
                    if (externalPsks.TryGetValue(pskIdHex, out var ePsk))
                        pskValue = ePsk;
                }
                return new PskSecretDerivation.PskInput { Id = id, PskValue = pskValue };
            }).ToArray();
            pskSecret = PskSecretDerivation.ComputePskSecret(cs, pskInputs);
        }
        else
        {
            pskSecret = new byte[cs.SecretSize]; // zeros(Nh) when no PSKs
        }
        byte[] intermediateSecret = cs.Extract(groupSecrets.JoinerSecret, pskSecret);
        byte[] welcomeSecret = cs.DeriveSecret(intermediateSecret, "welcome");
        byte[] welcomeKey = cs.ExpandWithLabel(
            welcomeSecret, "key", Array.Empty<byte>(), cs.AeadKeySize);
        byte[] welcomeNonce = cs.ExpandWithLabel(
            welcomeSecret, "nonce", Array.Empty<byte>(), cs.AeadNonceSize);

        // Decrypt the group info
        byte[] groupInfoBytes = cs.AeadDecrypt(
            welcomeKey, welcomeNonce, Array.Empty<byte>(), welcome.EncryptedGroupInfo);

        var giReader = new TlsReader(groupInfoBytes);
        var groupInfo = GroupInfo.ReadFrom(giReader);

        // Extract the ratchet tree from the GroupInfo extensions or external source
        RatchetTree tree;
        if (externalTree != null)
        {
            tree = RatchetTree.ReadFrom(new TlsReader(externalTree));
        }
        else
        {
            byte[]? ratchetTreeData = null;
            foreach (var ext in groupInfo.Extensions)
            {
                if (ext.ExtensionType == ExtensionType.RatchetTree)
                {
                    ratchetTreeData = ext.ExtensionData;
                    break;
                }
            }

            if (ratchetTreeData != null)
            {
                var treeReader = new TlsReader(ratchetTreeData);
                tree = RatchetTree.ReadFrom(treeReader);
            }
            else
            {
                throw new InvalidOperationException(
                    "Welcome GroupInfo does not contain ratchet_tree extension and no external tree provided.");
            }
        }

        // Find our leaf index by matching signature key
        uint myLeafIndex = uint.MaxValue;
        for (uint i = 0; i < tree.LeafCount; i++)
        {
            var leaf = tree.GetLeaf(i);
            if (leaf != null &&
                leaf.SignatureKey.AsSpan().SequenceEqual(myKeyPackage.LeafNode.SignatureKey))
            {
                myLeafIndex = i;
                break;
            }
        }

        if (myLeafIndex == uint.MaxValue)
            throw new InvalidOperationException(
                "Could not find our leaf in the ratchet tree.");

        // Derive key schedule from joiner_secret using the FromJoinerSecret factory
        var groupContext = groupInfo.GroupContext;
        byte[] serializedContext = SerializeGroupContext(groupContext);
        var keySchedule = KeyScheduleEpoch.FromJoinerSecret(
            cs, groupSecrets.JoinerSecret, serializedContext, pskSecret);

        // Verify confirmation tag
        byte[] expectedTag = keySchedule.ComputeConfirmationTag(
            cs, groupContext.ConfirmedTranscriptHash);
        if (!CryptographicOperations.FixedTimeEquals(expectedTag, groupInfo.ConfirmationTag))
            throw new InvalidOperationException("Invalid confirmation tag in GroupInfo.");

        // Compute interim transcript hash: Hash(confirmed || InterimTranscriptHashInput)
        // InterimTranscriptHashInput = struct { MAC confirmation_tag; } where MAC = opaque<V>
        byte[] interimInput = TlsCodec.Serialize(w => w.WriteOpaqueV(groupInfo.ConfirmationTag));
        byte[] interimHash = cs.Hash(
            Concat(groupContext.ConfirmedTranscriptHash, interimInput));

        // Derive parent node private keys from path_secret if provided
        // RFC 9420 §12.4.3.1: path_secret is at the common ancestor of committer and joiner
        var privateKeys = new Dictionary<uint, byte[]>();
        uint myNodeIdx = TreeMath.LeafToNode(myLeafIndex);
        privateKeys[myNodeIdx] = myHpkePrivateKey;

        if (groupSecrets.PathSecret != null)
        {
            uint committerLeaf = groupInfo.Signer;
            var myDp = TreeMath.DirectPath(myLeafIndex, tree.LeafCount);
            uint commonAncestor = TreeMath.CommonAncestor(committerLeaf, myLeafIndex);

            int startIdx = -1;
            for (int i = 0; i < myDp.Length; i++)
            {
                if (myDp[i] == commonAncestor)
                {
                    startIdx = i;
                    break;
                }
            }

            if (startIdx >= 0)
            {
                byte[] pathSecret = groupSecrets.PathSecret;
                for (int i = startIdx; i < myDp.Length; i++)
                {
                    byte[] nodeSecret = cs.DeriveSecret(pathSecret, "node");
                    var (nodePriv, _) = TreeKem.DeriveKeyPair(cs, nodeSecret);
                    privateKeys[myDp[i]] = nodePriv;
                    var parentNode = tree.GetParent(myDp[i]);
                    if (parentNode != null)
                        parentNode.PrivateKey = nodePriv;
                    if (i < myDp.Length - 1)
                        pathSecret = cs.DeriveSecret(pathSecret, "path");
                }
            }
        }

        // Build the group object
        var group = new MlsGroup(cs, config);
        group._groupId = groupContext.GroupId;
        group._epoch = groupContext.Epoch;
        group._tree = tree;
        group._myLeafIndex = myLeafIndex;
        group._mySigningPrivateKey = mySigningPrivateKey;
        group._myHpkePrivateKey = myHpkePrivateKey;
        group._groupContext = groupContext;
        group._keySchedule = keySchedule;
        group._transcriptHash = new TranscriptHash(
            groupContext.ConfirmedTranscriptHash, interimHash);
        group._secretTree = new SecretTree(
            cs, keySchedule.EncryptionSecret, tree.LeafCount);
        group._extensions = groupContext.Extensions;
        group._resumptionPsks[groupContext.Epoch] = keySchedule.ResumptionPsk;
        if (externalPsks != null)
        {
            foreach (var kvp in externalPsks)
                group._externalPsks[kvp.Key] = kvp.Value;
        }

        // Store private keys in the group for Decap during commit processing
        foreach (var (nodeIdx, privKey) in privateKeys)
        {
            if (nodeIdx != myNodeIdx)
            {
                var parentNode = tree.GetParent(nodeIdx);
                if (parentNode != null)
                    parentNode.PrivateKey = privKey;
            }
        }

        return group;
    }

    // -- External Commit (join without a Welcome) --

    /// <summary>
    /// Joins a group via an External Commit (RFC 9420 §12.4.3.2) using a
    /// published <see cref="GroupInfo"/> that carries the <c>external_pub</c>
    /// extension. Returns the commit message to broadcast to the group and the
    /// local <see cref="MlsGroup"/> in the new epoch. The commit must be
    /// accepted by every existing member via <see cref="ProcessCommit(PublicMessage)"/>.
    /// </summary>
    /// <param name="cs">The cipher suite. Must match the group's cipher suite.</param>
    /// <param name="groupInfo">A signed GroupInfo from a current member.</param>
    /// <param name="identity">The joiner's identity bytes for BasicCredential.</param>
    /// <param name="signingPrivateKey">The joiner's private signing key.</param>
    /// <param name="signingPublicKey">The joiner's public signing key.</param>
    /// <param name="config">Group configuration, or null for defaults.</param>
    /// <returns>A tuple of (commit PublicMessage to broadcast, new MlsGroup).</returns>
    public static (PublicMessage commitMessage, MlsGroup group) JoinExternal(
        ICipherSuite cs,
        GroupInfo groupInfo,
        byte[] identity,
        byte[] signingPrivateKey,
        byte[] signingPublicKey,
        MlsGroupConfig? config = null)
    {
        config ??= MlsGroupConfig.Default;

        // Cipher suite must match
        if (groupInfo.GroupContext.CipherSuite != cs.Id)
            throw new InvalidOperationException(
                $"GroupInfo cipher suite 0x{groupInfo.GroupContext.CipherSuite:X4} does not match 0x{cs.Id:X4}.");

        // Extract ratchet_tree and external_pub extensions
        byte[]? ratchetTreeData = null;
        byte[]? externalPubKey = null;
        foreach (var ext in groupInfo.Extensions)
        {
            if (ext.ExtensionType == ExtensionType.RatchetTree)
                ratchetTreeData = ext.ExtensionData;
            else if (ext.ExtensionType == ExtensionType.ExternalPub)
            {
                var epReader = new TlsReader(ext.ExtensionData);
                externalPubKey = epReader.ReadOpaqueV();
            }
        }
        if (ratchetTreeData == null)
            throw new InvalidOperationException("GroupInfo is missing the ratchet_tree extension.");
        if (externalPubKey == null)
            throw new InvalidOperationException("GroupInfo is missing the external_pub extension.");

        var tree = RatchetTree.ReadFrom(new TlsReader(ratchetTreeData));

        // Verify the GroupInfo signature using the signer's current leaf.
        var signerLeaf = tree.GetLeaf(groupInfo.Signer)
            ?? throw new InvalidOperationException(
                $"GroupInfo signer leaf {groupInfo.Signer} is blank.");
        byte[] giTbs = TlsCodec.Serialize(writer =>
        {
            groupInfo.GroupContext.WriteTo(writer);
            writer.WriteVectorV(inner =>
            {
                foreach (var ext in groupInfo.Extensions)
                    ext.WriteTo(inner);
            });
            writer.WriteOpaqueV(groupInfo.ConfirmationTag);
            writer.WriteUint32(groupInfo.Signer);
        });
        if (!cs.VerifyWithLabel(signerLeaf.SignatureKey, "GroupInfoTBS", giTbs, groupInfo.Signature))
            throw new InvalidOperationException("Invalid GroupInfo signature.");

        // HPKE Encap against external_pub → shared_secret becomes new init_secret.
        var (kemOutput, sharedSecret) = cs.HpkeEncap(externalPubKey);

        // Build our new leaf node (source = Commit).
        var (hpkePriv, hpkePub) = cs.GenerateHpkeKeyPair();
        var newLeafNode = new LeafNode
        {
            EncryptionKey = hpkePub,
            SignatureKey = signingPublicKey,
            Credential = new BasicCredential(identity),
            Capabilities = CreateDefaultCapabilities(cs),
            Source = LeafNodeSource.Commit,
            Extensions = Array.Empty<Extension>()
        };

        // Place ourselves into the tentative tree. AddLeaf reuses a blank slot
        // when available, otherwise extends — same slot the receiver will use.
        // The placeholder hpkePriv is replaced with the leaf key derived by Encap.
        _ = hpkePriv;
        var tentativeTree = tree.Clone();
        uint myLeafIndex = tentativeTree.AddLeaf(newLeafNode);
        var addedLeaves = new List<uint> { myLeafIndex };

        byte[] groupId = groupInfo.GroupContext.GroupId;
        var tentativeExtensions = groupInfo.GroupContext.Extensions;

        // Provisional GroupContext (epoch+1, tree_hash filled by factory,
        // confirmed_transcript_hash carries over from current GroupInfo).
        var tentativeContext = new GroupContext
        {
            Version = ProtocolVersion.Mls10,
            CipherSuite = cs.Id,
            GroupId = groupId,
            Epoch = groupInfo.GroupContext.Epoch + 1,
            TreeHash = Array.Empty<byte>(),
            ConfirmedTranscriptHash = groupInfo.GroupContext.ConfirmedTranscriptHash,
            Extensions = tentativeExtensions
        };

        var originalTree = tentativeTree.Clone();

        var (updatePath, newHpkePriv, commitSecret) = TreeKem.Encap(
            tentativeTree, myLeafIndex, cs, newLeafNode, () =>
            {
                // External commit: joiner IS the added member. Use encryption
                // resolution (excluding self) for filtered path since we don't
                // encrypt to ourselves. This matches the Encap behavior.
                var dp = TreeMath.DirectPath(myLeafIndex, tentativeTree.LeafCount);
                var externalAddedNodeIndices = new HashSet<uint> { TreeMath.LeafToNode(myLeafIndex) };
                var cp = TreeMath.Copath(myLeafIndex, tentativeTree.LeafCount);
                var fdp = new List<uint>();
                for (int i = 0; i < dp.Length; i++)
                {
                    var res = tentativeTree.Resolution(cp[i]);
                    if (res.Count > 0)
                        fdp.Add(dp[i]);
                }


                for (int i = fdp.Count - 2; i >= 0; i--)
                {
                    uint nodeIdx = fdp[i];
                    uint parentIdx = fdp[i + 1];
                    uint siblingIdx = nodeIdx < parentIdx
                        ? TreeMath.Right(parentIdx)
                        : TreeMath.Left(parentIdx);
                    byte[] siblingTreeHash = originalTree.ComputeTreeHash(cs, siblingIdx);
                    byte[] parentHash = tentativeTree.ComputeParentHash(cs, parentIdx, siblingTreeHash);
                    tentativeTree.GetParent(nodeIdx)!.ParentHash = parentHash;
                }

                if (fdp.Count > 0)
                {
                    uint firstParent = fdp[0];
                    uint leafNodeIdx = TreeMath.LeafToNode(myLeafIndex);
                    uint lc = TreeMath.Left(firstParent);
                    uint rc = TreeMath.Right(firstParent);
                    uint siblingOfFirst = (leafNodeIdx == lc) ? rc : lc;
                    byte[] siblingTreeHash = originalTree.ComputeTreeHash(cs, siblingOfFirst);
                    newLeafNode.ParentHash = tentativeTree.ComputeParentHash(cs, firstParent, siblingTreeHash);
                }
                else
                {
                    newLeafNode.ParentHash = new byte[cs.HashSize];
                }

                SignLeafNode(cs, newLeafNode, signingPrivateKey, groupId, myLeafIndex);
                tentativeTree.SetLeaf(myLeafIndex, newLeafNode);

                var root0 = TreeMath.Root(tentativeTree.LeafCount);
                tentativeContext.TreeHash = tentativeTree.ComputeTreeHash(cs, root0);
                return SerializeGroupContext(tentativeContext);
            }, addedLeaves);

        updatePath = new UpdatePath(newLeafNode, updatePath.Nodes);

        // Build Commit with a single inline ExternalInit proposal.
        var externalInit = new ExternalInitProposal(kemOutput);
        var proposalOrRefs = new ProposalOrRef[] { new InlineProposal(externalInit) };
        var commit = new Commit(proposalOrRefs, updatePath);
        byte[] commitBytes = TlsCodec.Serialize(writer => commit.WriteTo(writer));

        // FramedContent with NewMemberCommit sender. The committer's leaf_index
        // is the slot we just occupied.
        var framedContent = new FramedContent
        {
            GroupId = groupId,
            Epoch = groupInfo.GroupContext.Epoch,
            Sender = new Sender(SenderType.NewMemberCommit, 0),
            AuthenticatedData = Array.Empty<byte>(),
            ContentType = ContentType.Commit,
            Content = commitBytes
        };

        byte[] serializedCurrentContext = SerializeGroupContext(groupInfo.GroupContext);
        byte[] tbs = MessageFraming.BuildFramedContentTbs(
            WireFormat.MlsPublicMessage, framedContent, serializedCurrentContext);
        byte[] signature = cs.SignWithLabel(signingPrivateKey, "FramedContentTBS", tbs);

        byte[] confirmedInput = MessageFraming.BuildConfirmedTranscriptHashInput(
            WireFormat.MlsPublicMessage, framedContent, signature);

        // Finalize GroupContext with the final tree hash and confirmed transcript hash.
        var rootFinal = TreeMath.Root(tentativeTree.LeafCount);
        byte[] finalTreeHash = tentativeTree.ComputeTreeHash(cs, rootFinal);
        tentativeContext.TreeHash = finalTreeHash;
        // InterimTranscriptHash prior to this commit uses the GroupInfo's confirmation tag.
        byte[] priorInterim;
        {
            byte[] interimInput = TlsCodec.Serialize(w => w.WriteOpaqueV(groupInfo.ConfirmationTag));
            priorInterim = cs.Hash(
                Concat(groupInfo.GroupContext.ConfirmedTranscriptHash, interimInput));
        }
        byte[] newConfirmedTranscriptHash = cs.Hash(Concat(priorInterim, confirmedInput));
        tentativeContext.ConfirmedTranscriptHash = newConfirmedTranscriptHash;
        byte[] newContextBytes = SerializeGroupContext(tentativeContext);

        // New key schedule: init_secret = shared_secret from ExternalInit (§12.4.3.2),
        // commit_secret from TreeKEM, no prior epoch init_secret.
        var newKeySchedule = KeyScheduleEpoch.Create(
            cs, sharedSecret, commitSecret, newContextBytes);

        byte[] confirmationTag = newKeySchedule.ComputeConfirmationTag(
            cs, newConfirmedTranscriptHash);
        var auth = new FramedContentAuthData(signature, confirmationTag);

        // External commits are sent as PublicMessage (no membership tag because
        // the sender isn't yet a member).
        var publicMessage = new PublicMessage(framedContent, auth, membershipTag: null);

        // Build the new group state.
        var newTranscriptHash = new TranscriptHash(cs.HashSize);
        // The transcript hash for the new epoch is (confirmed, interim) where
        // interim is computed from the confirmation tag of this commit.
        byte[] newInterimInput = TlsCodec.Serialize(w => w.WriteOpaqueV(confirmationTag));
        byte[] newInterimHash = cs.Hash(Concat(newConfirmedTranscriptHash, newInterimInput));

        var group = new MlsGroup(cs, config);
        group._groupId = groupId;
        group._epoch = tentativeContext.Epoch;
        group._tree = tentativeTree;
        group._myLeafIndex = myLeafIndex;
        group._mySigningPrivateKey = signingPrivateKey;
        group._myHpkePrivateKey = newHpkePriv;
        group._groupContext = tentativeContext;
        group._keySchedule = newKeySchedule;
        group._transcriptHash = new TranscriptHash(newConfirmedTranscriptHash, newInterimHash);
        group._secretTree = new SecretTree(cs, newKeySchedule.EncryptionSecret, tentativeTree.LeafCount);
        group._extensions = tentativeExtensions;
        group._resumptionPsks[group._epoch] = newKeySchedule.ResumptionPsk;

        return (publicMessage, group);
    }

    // -- Encrypt an application message --

    /// <summary>
    /// Encrypts an application message as a PrivateMessage.
    /// </summary>
    /// <param name="plaintext">The application data to encrypt.</param>
    /// <returns>An encrypted PrivateMessage ready for transmission.</returns>
    public PrivateMessage EncryptApplicationMessage(byte[] plaintext)
    {
        var content = new FramedContent
        {
            GroupId = _groupId,
            Epoch = _epoch,
            Sender = new Sender(SenderType.Member, _myLeafIndex),
            AuthenticatedData = Array.Empty<byte>(),
            ContentType = ContentType.Application,
            Content = plaintext
        };

        return MessageFraming.CreatePrivateMessage(
            content,
            _mySigningPrivateKey,
            SerializeGroupContext(_groupContext),
            _cs,
            _secretTree,
            _keySchedule.SenderDataSecret,
            null, // no confirmation tag for application messages
            _myLeafIndex,
            _config.Padding);
    }

    // -- Decrypt an application message --

    /// <summary>
    /// Decrypts a received PrivateMessage containing application data.
    /// Verifies the sender's signature on the decrypted content.
    /// </summary>
    /// <param name="msg">The encrypted PrivateMessage to decrypt.</param>
    /// <returns>A tuple of (decrypted plaintext, sender's leaf index).</returns>
    /// <exception cref="InvalidOperationException">
    /// Thrown when the sender leaf is blank or the signature is invalid.
    /// </exception>
    public (byte[] plaintext, uint senderLeafIndex) DecryptApplicationMessage(PrivateMessage msg)
    {
        var (content, auth) = MessageFraming.DecryptPrivateMessage(
            msg, _cs, _secretTree, _keySchedule.SenderDataSecret);

        // Verify signature
        uint senderLeaf = content.Sender.LeafIndex;
        var senderLeafNode = _tree.GetLeaf(senderLeaf);
        if (senderLeafNode == null)
            throw new InvalidOperationException("Sender leaf is blank.");

        byte[] tbs = MessageFraming.BuildFramedContentTbs(
            WireFormat.MlsPrivateMessage, content, SerializeGroupContext(_groupContext));
        if (!_cs.VerifyWithLabel(
                senderLeafNode.SignatureKey, "FramedContentTBS", tbs, auth.Signature))
            throw new InvalidOperationException("Invalid message signature.");

        return (content.Content, senderLeaf);
    }

    // -- Export a secret --

    /// <summary>
    /// Derives an exported secret using the MLS exporter mechanism.
    /// </summary>
    /// <param name="label">The exporter label.</param>
    /// <param name="context">The exporter context.</param>
    /// <param name="length">The desired output length in bytes.</param>
    /// <returns>The exported secret bytes.</returns>
    public byte[] ExportSecret(string label, byte[] context, int length)
    {
        return _keySchedule.DeriveExporterSecret(_cs, label, context, length);
    }

    // -- External join support --

    /// <summary>
    /// Produces a signed GroupInfo describing this group's current epoch,
    /// suitable for publishing to non-members who want to join via an
    /// External Commit (RFC 9420 §12.4.3.2). The GroupInfo carries two
    /// extensions: <c>ratchet_tree</c> with the current tree, and
    /// <c>external_pub</c> with the epoch's external HPKE public key.
    /// </summary>
    public GroupInfo GetGroupInfo()
    {
        byte[] treeBytes = TlsCodec.Serialize(writer => _tree.WriteTo(writer));
        var treeExtension = new Extension(ExtensionType.RatchetTree, treeBytes);

        byte[] externalPubBytes = TlsCodec.Serialize(w => w.WriteOpaqueV(_keySchedule.ExternalPub));
        var externalPubExtension = new Extension(ExtensionType.ExternalPub, externalPubBytes);

        var groupInfo = new GroupInfo
        {
            GroupContext = _groupContext,
            ConfirmationTag = _keySchedule.ComputeConfirmationTag(
                _cs, _groupContext.ConfirmedTranscriptHash),
            Signer = _myLeafIndex,
            Extensions = new[] { treeExtension, externalPubExtension }
        };

        byte[] giTbs = TlsCodec.Serialize(writer =>
        {
            groupInfo.GroupContext.WriteTo(writer);
            writer.WriteVectorV(inner =>
            {
                foreach (var ext in groupInfo.Extensions)
                    ext.WriteTo(inner);
            });
            writer.WriteOpaqueV(groupInfo.ConfirmationTag);
            writer.WriteUint32(groupInfo.Signer);
        });
        groupInfo.Signature = _cs.SignWithLabel(
            _mySigningPrivateKey, "GroupInfoTBS", giTbs);

        return groupInfo;
    }

    // -- Get members --

    /// <summary>
    /// Returns a list of all current group members with their leaf indices and identities.
    /// </summary>
    /// <returns>A list of (leafIndex, identity) tuples for non-blank leaves with BasicCredentials.</returns>
    public List<(uint leafIndex, byte[] identity)> GetMembers()
    {
        var members = new List<(uint, byte[])>();
        for (uint i = 0; i < _tree.LeafCount; i++)
        {
            var leaf = _tree.GetLeaf(i);
            if (leaf != null && leaf.Credential is BasicCredential bc)
            {
                members.Add((i, bc.Identity));
            }
        }
        return members;
    }

    // ---- Helper: Build Welcome message ----

    private Welcome BuildWelcome(
        RatchetTree tree,
        GroupContext groupContext,
        KeyScheduleEpoch keySchedule,
        List<(KeyPackage kp, byte[] initKey)> newMembers,
        byte[] confirmationTag)
    {
        // Build GroupInfo
        // Include the ratchet_tree extension in GroupInfo
        byte[] treeBytes = TlsCodec.Serialize(writer => tree.WriteTo(writer));
        var treeExtension = new Extension(ExtensionType.RatchetTree, treeBytes);

        var groupInfo = new GroupInfo
        {
            GroupContext = groupContext,
            ConfirmationTag = confirmationTag,
            Signer = _myLeafIndex,
            Extensions = new[] { treeExtension }
        };

        // Sign GroupInfo
        byte[] giTbs = TlsCodec.Serialize(writer =>
        {
            groupInfo.GroupContext.WriteTo(writer);
            writer.WriteVectorV(inner =>
            {
                foreach (var ext in groupInfo.Extensions)
                    ext.WriteTo(inner);
            });
            writer.WriteOpaqueV(groupInfo.ConfirmationTag);
            writer.WriteUint32(groupInfo.Signer);
        });
        groupInfo.Signature = _cs.SignWithLabel(
            _mySigningPrivateKey, "GroupInfoTBS", giTbs);

        // Serialize and encrypt GroupInfo
        byte[] groupInfoBytes = TlsCodec.Serialize(writer => groupInfo.WriteTo(writer));
        byte[] encryptedGroupInfo = _cs.AeadEncrypt(
            keySchedule.WelcomeKey, keySchedule.WelcomeNonce,
            Array.Empty<byte>(), groupInfoBytes);

        // Build GroupSecrets and encrypt for each new member
        var encryptedSecretsList = new List<EncryptedGroupSecrets>();
        foreach (var (kp, initKey) in newMembers)
        {
            var groupSecrets = new GroupSecrets
            {
                JoinerSecret = keySchedule.JoinerSecret,
                PathSecret = null, // Path secret is for tree reconstruction; omitted for simplicity
                Psks = Array.Empty<PreSharedKeyId>()
            };

            byte[] gsBytes = TlsCodec.Serialize(writer => groupSecrets.WriteTo(writer));

            // HPKE EncryptWithLabel to the new member's init key (RFC 9420 §5.1.3)
            // HpkeSeal returns kem_output || ciphertext concatenated
            byte[] hpkeInfo = BuildEncryptContext("Welcome", encryptedGroupInfo);
            byte[] sealed_ = _cs.HpkeSeal(
                initKey, hpkeInfo, Array.Empty<byte>(), gsBytes);

            // Split the sealed bytes into KEM output and ciphertext
            // For X25519, KEM output is 32 bytes
            const int kemOutputSize = 32;
            byte[] kemOutput = new byte[kemOutputSize];
            byte[] ciphertext = new byte[sealed_.Length - kemOutputSize];
            Array.Copy(sealed_, 0, kemOutput, 0, kemOutputSize);
            Array.Copy(sealed_, kemOutputSize, ciphertext, 0, ciphertext.Length);

            // Compute key package reference
            byte[] kpBytes = TlsCodec.Serialize(writer => kp.WriteTo(writer));
            var kpRef = KeyPackageRef.Compute(_cs, kpBytes);

            encryptedSecretsList.Add(new EncryptedGroupSecrets(
                kpRef.Value,
                new HpkeCiphertext(kemOutput, ciphertext)));
        }

        return new Welcome(_cs.Id, encryptedSecretsList.ToArray(), encryptedGroupInfo);
    }

    // ---- Helper: Apply a single proposal to the tree ----

    private static void ApplyProposal(
        RatchetTree tree, Proposal proposal, ref Extension[] extensions,
        uint senderLeaf = uint.MaxValue)
    {
        if (proposal is AddProposal add)
        {
            tree.AddLeaf(add.KeyPackage.LeafNode);
        }
        else if (proposal is RemoveProposal remove)
        {
            tree.BlankLeaf(remove.LeafIndex);
        }
        else if (proposal is UpdateProposal update)
        {
            // If sender is known, use it directly; otherwise match by signature key
            if (senderLeaf != uint.MaxValue)
            {
                tree.SetLeaf(senderLeaf, update.LeafNode);
            }
            else
            {
                for (uint i = 0; i < tree.LeafCount; i++)
                {
                    var leaf = tree.GetLeaf(i);
                    if (leaf != null &&
                        leaf.SignatureKey.AsSpan().SequenceEqual(update.LeafNode.SignatureKey))
                    {
                        tree.SetLeaf(i, update.LeafNode);
                        break;
                    }
                }
            }
        }
        else if (proposal is GroupContextExtensionsProposal gce)
        {
            extensions = gce.Extensions;
        }
    }

    // ---- Helper: Sign / verify a leaf node ----

    /// <summary>
    /// Builds the LeafNodeTBS per RFC 9420 §7.2. Source-specific context:
    ///   - KeyPackage: no additional context
    ///   - Update/Commit: group_id&lt;V&gt; + uint32 leaf_index
    /// </summary>
    private static byte[] BuildLeafNodeTbs(LeafNode leafNode, byte[]? groupId, uint leafIndex)
    {
        return TlsCodec.Serialize(writer =>
        {
            writer.WriteOpaqueV(leafNode.EncryptionKey);
            writer.WriteOpaqueV(leafNode.SignatureKey);
            leafNode.Credential.WriteTo(writer);
            leafNode.Capabilities.WriteTo(writer);
            writer.WriteUint8((byte)leafNode.Source);
            if (leafNode.Source == LeafNodeSource.KeyPackage && leafNode.Lifetime != null)
            {
                leafNode.Lifetime.WriteTo(writer);
            }
            else if (leafNode.Source == LeafNodeSource.Commit)
            {
                writer.WriteOpaqueV(leafNode.ParentHash);
            }
            writer.WriteVectorV(inner =>
            {
                foreach (var ext in leafNode.Extensions)
                    ext.WriteTo(inner);
            });
            if (leafNode.Source == LeafNodeSource.Update ||
                leafNode.Source == LeafNodeSource.Commit)
            {
                if (groupId != null)
                    writer.WriteOpaqueV(groupId);
                writer.WriteUint32(leafIndex);
            }
        });
    }

    /// <summary>
    /// Signs a leaf node per RFC 9420 Section 7.2.
    /// </summary>
    private static void SignLeafNode(
        ICipherSuite cs, LeafNode leafNode, byte[] signingPrivateKey,
        byte[]? groupId, uint leafIndex = 0)
    {
        byte[] tbs = BuildLeafNodeTbs(leafNode, groupId, leafIndex);
        leafNode.Signature = cs.SignWithLabel(signingPrivateKey, "LeafNodeTBS", tbs);
    }

    /// <summary>
    /// Verifies a leaf node's signature per RFC 9420 §7.2.
    /// </summary>
    private static bool VerifyLeafNodeSignature(
        ICipherSuite cs, LeafNode leafNode, byte[]? groupId, uint leafIndex)
    {
        byte[] tbs = BuildLeafNodeTbs(leafNode, groupId, leafIndex);
        return cs.VerifyWithLabel(
            leafNode.SignatureKey, "LeafNodeTBS", tbs, leafNode.Signature);
    }

    /// <summary>
    /// Validates a proposed GroupContext extensions list (RFC 9420 §12.1.7):
    /// each extension type must be a known GroupContext extension or be
    /// supported by every current member's advertised capabilities.
    /// </summary>
    private static void ValidateGroupContextExtensions(
        Extension[] extensions, RatchetTree tree)
    {
        foreach (var ext in extensions)
        {
            // Extension types valid in GroupContext per RFC 9420 §17.3 and §12.1.7.
            if (ext.ExtensionType == ExtensionType.RequiredCapabilities ||
                ext.ExtensionType == ExtensionType.ExternalSenders)
                continue;

            // Otherwise, every non-blank leaf must advertise this type.
            for (uint i = 0; i < tree.LeafCount; i++)
            {
                var leaf = tree.GetLeaf(i);
                if (leaf == null) continue;
                if (Array.IndexOf(leaf.Capabilities.Extensions, ext.ExtensionType) < 0)
                    throw new InvalidOperationException(
                        $"GroupContext extension 0x{ext.ExtensionType:X4} is not supported by leaf {i}.");
            }
        }
    }

    /// <summary>
    /// Validates that the added LeafNode advertises support for the group's
    /// protocol version and cipher suite (RFC 9420 §12.1.1).
    /// </summary>
    private static void ValidateAddLeafCapabilities(LeafNode leaf, ushort groupVersion, ushort groupCipherSuite)
    {
        if (Array.IndexOf(leaf.Capabilities.Versions, groupVersion) < 0)
            throw new InvalidOperationException(
                $"Added leaf does not advertise support for protocol version 0x{groupVersion:X4}.");
        if (Array.IndexOf(leaf.Capabilities.CipherSuites, groupCipherSuite) < 0)
            throw new InvalidOperationException(
                $"Added leaf does not advertise support for cipher suite 0x{groupCipherSuite:X4}.");
    }

    // ---- Helper: Create default capabilities ----

    private static Capabilities CreateDefaultCapabilities(ICipherSuite cs)
    {
        return new Capabilities
        {
            Versions = new ushort[] { ProtocolVersion.Mls10 },
            CipherSuites = new ushort[] { cs.Id },
            Extensions = Array.Empty<ushort>(),
            Proposals = Array.Empty<ushort>(),
            Credentials = new ushort[] { (ushort)CredentialType.Basic }
        };
    }

    // ---- Helper: Serialize group context ----

    private static byte[] SerializeGroupContext(GroupContext gc)
    {
        return TlsCodec.Serialize(writer => gc.WriteTo(writer));
    }

    // ---- Helper: Concatenate byte arrays ----

    /// <summary>
    /// Builds the EncryptContext info for EncryptWithLabel (RFC 9420 §5.1.3):
    ///   struct { opaque label&lt;V&gt;; opaque content&lt;V&gt;; } EncryptContext;
    ///   label = "MLS 1.0 " + Label
    /// </summary>
    private static byte[] BuildEncryptContext(string label, byte[] content)
    {
        return TlsCodec.Serialize(writer =>
        {
            byte[] fullLabel = System.Text.Encoding.ASCII.GetBytes("MLS 1.0 " + label);
            writer.WriteOpaqueV(fullLabel);
            writer.WriteOpaqueV(content);
        });
    }

    private static byte[] Concat(byte[] a, byte[] b)
    {
        var result = new byte[a.Length + b.Length];
        Buffer.BlockCopy(a, 0, result, 0, a.Length);
        Buffer.BlockCopy(b, 0, result, a.Length, b.Length);
        return result;
    }

    // -- Serialization (persistence) --

    private const byte SerializationVersion = 1;

    /// <summary>
    /// Serializes the complete group state to a TlsWriter for persistence.
    /// This is a custom binary format, NOT the MLS wire format.
    /// </summary>
    public void WriteTo(TlsWriter writer)
    {
        // Version
        writer.WriteUint8(SerializationVersion);

        // Core identity
        writer.WriteUint16(_cs.Id);
        writer.WriteOpaqueV(_groupId);
        writer.WriteUint64(_epoch);
        writer.WriteUint32(_myLeafIndex);
        writer.WriteOpaqueV(_mySigningPrivateKey);
        writer.WriteOpaqueV(_myHpkePrivateKey);

        // GroupContext (uses its own WriteTo)
        _groupContext.WriteTo(writer);

        // RatchetTree
        _tree.WriteTo(writer);

        // Transcript hashes
        writer.WriteOpaqueV(_transcriptHash.ConfirmedTranscriptHash);
        writer.WriteOpaqueV(_transcriptHash.InterimTranscriptHash);

        // KeyScheduleEpoch - all 14 secrets
        writer.WriteOpaqueV(_keySchedule.InitSecret);
        writer.WriteOpaqueV(_keySchedule.SenderDataSecret);
        writer.WriteOpaqueV(_keySchedule.EncryptionSecret);
        writer.WriteOpaqueV(_keySchedule.ExporterSecret);
        writer.WriteOpaqueV(_keySchedule.EpochAuthenticator);
        writer.WriteOpaqueV(_keySchedule.ExternalSecret);
        writer.WriteOpaqueV(_keySchedule.ConfirmationKey);
        writer.WriteOpaqueV(_keySchedule.MembershipKey);
        writer.WriteOpaqueV(_keySchedule.ResumptionPsk);
        writer.WriteOpaqueV(_keySchedule.ExternalPub);
        writer.WriteOpaqueV(_keySchedule.JoinerSecret);
        writer.WriteOpaqueV(_keySchedule.WelcomeSecret);
        writer.WriteOpaqueV(_keySchedule.WelcomeKey);
        writer.WriteOpaqueV(_keySchedule.WelcomeNonce);

        // Extensions
        writer.WriteUint32((uint)_extensions.Length);
        foreach (var ext in _extensions)
            ext.WriteTo(writer);

        // MlsGroupConfig
        writer.WriteUint32((uint)_config.OutOfOrderTolerance);
        writer.WriteUint32((uint)_config.MaxForwardDistance);

        // SecretTree state
        var nodeSecrets = _secretTree.NodeSecrets;
        writer.WriteUint32((uint)_secretTree.NodeCount);
        for (int i = 0; i < _secretTree.NodeCount; i++)
        {
            if (nodeSecrets[i] != null)
            {
                writer.WriteUint8(1);
                writer.WriteOpaqueV(nodeSecrets[i]!);
            }
            else
            {
                writer.WriteUint8(0);
            }
        }

        uint leafCount = _secretTree.LeafCount;
        writer.WriteUint32(leafCount);
        for (uint i = 0; i < leafCount; i++)
        {
            var hs = _secretTree.GetHandshakeRatchetState(i);
            var app = _secretTree.GetApplicationRatchetState(i);
            byte flags = 0;
            if (hs != null) flags |= 1;
            if (app != null) flags |= 2;
            writer.WriteUint8(flags);

            if (hs != null)
            {
                writer.WriteOpaqueV(hs.Value.secret);
                writer.WriteUint32(hs.Value.generation);
            }
            if (app != null)
            {
                writer.WriteOpaqueV(app.Value.secret);
                writer.WriteUint32(app.Value.generation);
            }
        }
    }

    /// <summary>
    /// Deserializes a complete group state from a TlsReader.
    /// </summary>
    public static MlsGroup ReadFrom(TlsReader reader, ICipherSuite cs)
    {
        byte version = reader.ReadUint8();
        if (version != SerializationVersion)
            throw new InvalidOperationException($"Unsupported MlsGroup serialization version: {version}");

        ushort cipherSuiteId = reader.ReadUint16();
        if (cipherSuiteId != cs.Id)
            throw new InvalidOperationException($"Cipher suite mismatch: expected 0x{cs.Id:X4}, got 0x{cipherSuiteId:X4}");

        byte[] groupId = reader.ReadOpaqueV();
        ulong epoch = reader.ReadUint64();
        uint myLeafIndex = reader.ReadUint32();
        byte[] mySigningPrivateKey = reader.ReadOpaqueV();
        byte[] myHpkePrivateKey = reader.ReadOpaqueV();

        var groupContext = GroupContext.ReadFrom(reader);
        var tree = RatchetTree.ReadFrom(reader);

        byte[] confirmedTranscriptHash = reader.ReadOpaqueV();
        byte[] interimTranscriptHash = reader.ReadOpaqueV();

        // KeyScheduleEpoch - 14 secrets
        byte[] initSecret = reader.ReadOpaqueV();
        byte[] senderDataSecret = reader.ReadOpaqueV();
        byte[] encryptionSecret = reader.ReadOpaqueV();
        byte[] exporterSecret = reader.ReadOpaqueV();
        byte[] epochAuthenticator = reader.ReadOpaqueV();
        byte[] externalSecret = reader.ReadOpaqueV();
        byte[] confirmationKey = reader.ReadOpaqueV();
        byte[] membershipKey = reader.ReadOpaqueV();
        byte[] resumptionPsk = reader.ReadOpaqueV();
        byte[] externalPub = reader.ReadOpaqueV();
        byte[] joinerSecret = reader.ReadOpaqueV();
        byte[] welcomeSecret = reader.ReadOpaqueV();
        byte[] welcomeKey = reader.ReadOpaqueV();
        byte[] welcomeNonce = reader.ReadOpaqueV();

        var keySchedule = new KeyScheduleEpoch(
            initSecret, senderDataSecret, encryptionSecret, exporterSecret,
            epochAuthenticator, externalSecret, confirmationKey, membershipKey,
            resumptionPsk, externalPub, joinerSecret, welcomeSecret,
            welcomeKey, welcomeNonce);

        // Extensions
        uint extensionCount = reader.ReadUint32();
        var extensions = new Extension[extensionCount];
        for (uint i = 0; i < extensionCount; i++)
            extensions[i] = Extension.ReadFrom(reader);

        // MlsGroupConfig
        int outOfOrderTolerance = (int)reader.ReadUint32();
        int maxForwardDistance = (int)reader.ReadUint32();
        var config = new MlsGroupConfig
        {
            OutOfOrderTolerance = outOfOrderTolerance,
            MaxForwardDistance = maxForwardDistance
        };

        // SecretTree state
        int nodeCount = (int)reader.ReadUint32();
        var nodeSecrets = new byte[]?[nodeCount];
        for (int i = 0; i < nodeCount; i++)
        {
            byte hasSecret = reader.ReadUint8();
            if (hasSecret != 0)
                nodeSecrets[i] = reader.ReadOpaqueV();
        }

        uint leafCount = reader.ReadUint32();
        var handshakeRatchets = new (byte[] secret, uint generation)?[leafCount];
        var applicationRatchets = new (byte[] secret, uint generation)?[leafCount];
        for (uint i = 0; i < leafCount; i++)
        {
            byte flags = reader.ReadUint8();
            if ((flags & 1) != 0)
            {
                byte[] secret = reader.ReadOpaqueV();
                uint gen = reader.ReadUint32();
                handshakeRatchets[i] = (secret, gen);
            }
            if ((flags & 2) != 0)
            {
                byte[] secret = reader.ReadOpaqueV();
                uint gen = reader.ReadUint32();
                applicationRatchets[i] = (secret, gen);
            }
        }

        var secretTree = new SecretTree(cs, leafCount, nodeSecrets, handshakeRatchets, applicationRatchets);

        var group = new MlsGroup(cs, config);
        group._groupId = groupId;
        group._epoch = epoch;
        group._myLeafIndex = myLeafIndex;
        group._mySigningPrivateKey = mySigningPrivateKey;
        group._myHpkePrivateKey = myHpkePrivateKey;
        group._groupContext = groupContext;
        group._tree = tree;
        group._transcriptHash = new TranscriptHash(confirmedTranscriptHash, interimTranscriptHash);
        group._keySchedule = keySchedule;
        group._secretTree = secretTree;
        group._extensions = extensions;

        return group;
    }

    /// <summary>
    /// Exports the group state as a byte array.
    /// </summary>
    public byte[] Export()
    {
        return TlsCodec.Serialize(writer => WriteTo(writer));
    }

    /// <summary>
    /// Imports a group state from a byte array.
    /// </summary>
    public static MlsGroup Import(byte[] data, ICipherSuite cs)
    {
        var reader = new TlsReader(data);
        return ReadFrom(reader, cs);
    }

    // -- Private constructor for factory methods --

    private MlsGroup(ICipherSuite cs, MlsGroupConfig config)
    {
        _cs = cs;
        _config = config;
        _groupId = Array.Empty<byte>();
        _tree = new RatchetTree();
        _groupContext = new GroupContext();
        _keySchedule = null!;
        _transcriptHash = null!;
        _secretTree = null!;
        _extensions = Array.Empty<Extension>();
        _mySigningPrivateKey = Array.Empty<byte>();
        _myHpkePrivateKey = Array.Empty<byte>();
    }
}

/// <summary>
/// Stores the tentative state of a pending commit that has not yet been merged.
/// </summary>
internal sealed class PendingCommitState
{
    public required RatchetTree Tree { get; init; }
    public required ulong Epoch { get; init; }
    public required GroupContext GroupContext { get; init; }
    public required KeyScheduleEpoch KeySchedule { get; init; }
    public required byte[] ConfirmedTranscriptHash { get; init; }
    public required byte[] InterimTranscriptHash { get; init; }
    public required byte[] MyHpkePrivateKey { get; init; }
    public required byte[] CommitSecret { get; init; }
    public required Extension[] Extensions { get; init; }
}
