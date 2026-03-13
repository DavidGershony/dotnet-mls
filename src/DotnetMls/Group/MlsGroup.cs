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
        // Sign the leaf node
        SignLeafNode(cs, leafNode, signingPrivateKey, groupId);

        // Create the tree with our leaf
        group._tree = new RatchetTree();
        group._myLeafIndex = group._tree.AddLeaf(leafNode);

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
        SignLeafNode(_cs, newLeafNode, _mySigningPrivateKey, _groupId);

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
    public (PublicMessage commitMessage, Welcome? welcome) Commit(List<Proposal>? proposals = null)
    {
        proposals ??= new List<Proposal>();

        // Clone the tree for tentative state
        var tentativeTree = _tree.Clone();

        // Apply proposals to the tentative tree and collect new members
        var newMembers = new List<(KeyPackage kp, byte[] initKey)>();
        var tentativeExtensions = (Extension[])_extensions.Clone();

        foreach (var proposal in proposals)
        {
            if (proposal is AddProposal add)
            {
                var leafNode = add.KeyPackage.LeafNode;
                tentativeTree.AddLeaf(leafNode);
                newMembers.Add((add.KeyPackage, add.KeyPackage.InitKey));
            }
            else if (proposal is RemoveProposal remove)
            {
                tentativeTree.BlankLeaf(remove.LeafIndex);
            }
            else if (proposal is GroupContextExtensionsProposal gce)
            {
                tentativeExtensions = gce.Extensions;
            }
            // UpdateProposal is handled via the UpdatePath below
        }

        // Generate new leaf node for the committer with fresh key material
        var (newHpkePriv, newHpkePub) = _cs.GenerateHpkeKeyPair();
        var currentLeaf = _tree.GetLeaf(_myLeafIndex)!;
        var newLeafNode = new LeafNode
        {
            EncryptionKey = newHpkePub,
            SignatureKey = currentLeaf.SignatureKey,
            Credential = currentLeaf.Credential,
            Capabilities = currentLeaf.Capabilities,
            Source = LeafNodeSource.Commit,
            Extensions = currentLeaf.Extensions
        };
        SignLeafNode(_cs, newLeafNode, _mySigningPrivateKey, _groupId);

        // Build tentative group context for TreeKEM (with placeholders)
        var tentativeContext = new GroupContext
        {
            Version = ProtocolVersion.Mls10,
            CipherSuite = _cs.Id,
            GroupId = _groupId,
            Epoch = _epoch + 1,
            TreeHash = Array.Empty<byte>(),
            ConfirmedTranscriptHash = Array.Empty<byte>(),
            Extensions = tentativeExtensions
        };
        byte[] tentativeContextBytes = SerializeGroupContext(tentativeContext);

        // Run TreeKEM Encap to generate the UpdatePath and commit secret
        var (updatePath, commitSecret) = TreeKem.Encap(
            tentativeTree, _myLeafIndex, _cs, newLeafNode, tentativeContextBytes);

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

        // Build the FramedContentTBS for signing and transcript hash
        byte[] serializedCurrentContext = SerializeGroupContext(_groupContext);
        byte[] tbs = MessageFraming.BuildFramedContentTbs(
            WireFormat.MlsPublicMessage, framedContent, serializedCurrentContext);

        // Compute new confirmed transcript hash
        // confirmed_transcript_hash = Hash(interim_transcript_hash || content_tbs)
        byte[] newConfirmedTranscriptHash = _cs.Hash(
            Concat(_transcriptHash.InterimTranscriptHash, tbs));

        // Compute tree hash of the updated tree
        var root = TreeMath.Root(tentativeTree.LeafCount);
        byte[] treeHash = tentativeTree.ComputeTreeHash(_cs, root);

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

        // Compute interim transcript hash
        byte[] newInterimTranscriptHash = _cs.Hash(
            Concat(newConfirmedTranscriptHash, confirmationTag));

        // Sign the FramedContent
        byte[] signature = _cs.SignWithLabel(_mySigningPrivateKey, "FramedContentTBS", tbs);
        var auth = new FramedContentAuthData(signature, confirmationTag);

        // Compute membership tag using the CURRENT epoch's membership key
        byte[] tbm = MessageFraming.BuildAuthenticatedContentTbm(
            tbs, auth, ContentType.Commit);
        byte[] membershipTag = _cs.Mac(_keySchedule.MembershipKey, tbm);

        var publicMessage = new PublicMessage(framedContent, auth, membershipTag);

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

        return (publicMessage, welcome);
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
    public void ProcessCommit(PublicMessage commitMessage)
    {
        var content = commitMessage.Content;
        if (content.ContentType != ContentType.Commit)
            throw new ArgumentException("Not a commit message.");

        // Verify signature
        uint senderLeaf = content.Sender.LeafIndex;
        var senderLeafNode = _tree.GetLeaf(senderLeaf);
        if (senderLeafNode == null)
            throw new InvalidOperationException("Sender leaf is blank.");

        byte[] senderPublicKey = senderLeafNode.SignatureKey;
        byte[] serializedContext = SerializeGroupContext(_groupContext);

        byte[] tbs = MessageFraming.BuildFramedContentTbs(
            WireFormat.MlsPublicMessage, content, serializedContext);
        if (!_cs.VerifyWithLabel(senderPublicKey, "FramedContentTBS", tbs, commitMessage.Auth.Signature))
            throw new InvalidOperationException("Invalid commit signature.");

        // Parse the commit from the content bytes
        var commitReader = new TlsReader(content.Content);
        var commit = Types.Commit.ReadFrom(commitReader);

        // Clone tree for tentative processing
        var tentativeTree = _tree.Clone();
        var tentativeExtensions = (Extension[])_extensions.Clone();

        // Apply proposals
        foreach (var por in commit.Proposals)
        {
            if (por is InlineProposal inline)
            {
                ApplyProposal(tentativeTree, inline.Proposal, ref tentativeExtensions);
            }
            // ProposalReference handling would require a proposal cache (not yet implemented)
        }

        // Process UpdatePath if present
        byte[] commitSecret;
        if (commit.Path != null)
        {
            // Build tentative context for Decap
            var tentativeContext = new GroupContext
            {
                Version = ProtocolVersion.Mls10,
                CipherSuite = _cs.Id,
                GroupId = _groupId,
                Epoch = _epoch + 1,
                TreeHash = Array.Empty<byte>(),
                ConfirmedTranscriptHash = Array.Empty<byte>(),
                Extensions = tentativeExtensions
            };
            byte[] tentativeContextBytes = SerializeGroupContext(tentativeContext);

            commitSecret = TreeKem.Decap(
                tentativeTree, senderLeaf, commit.Path, _cs,
                _myLeafIndex, _myHpkePrivateKey, tentativeContextBytes);
        }
        else
        {
            commitSecret = new byte[_cs.SecretSize]; // No path = zero commit secret
        }

        // Compute new epoch state
        var root = TreeMath.Root(tentativeTree.LeafCount);
        byte[] treeHash = tentativeTree.ComputeTreeHash(_cs, root);

        byte[] newConfirmedTranscriptHash = _cs.Hash(
            Concat(_transcriptHash.InterimTranscriptHash, tbs));

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

        var newKeySchedule = KeyScheduleEpoch.Create(
            _cs, _keySchedule.InitSecret, commitSecret, newContextBytes);

        // Verify confirmation tag
        byte[] expectedTag = newKeySchedule.ComputeConfirmationTag(
            _cs, newConfirmedTranscriptHash);
        if (commitMessage.Auth.ConfirmationTag == null ||
            !CryptographicOperations.FixedTimeEquals(expectedTag, commitMessage.Auth.ConfirmationTag))
            throw new InvalidOperationException("Invalid confirmation tag.");

        byte[] newInterimTranscriptHash = _cs.Hash(
            Concat(newConfirmedTranscriptHash, commitMessage.Auth.ConfirmationTag));

        // Apply the new state
        _tree = tentativeTree;
        _epoch = _epoch + 1;
        _groupContext = newGroupContext;
        _keySchedule = newKeySchedule;
        _transcriptHash = new TranscriptHash(
            newConfirmedTranscriptHash, newInterimTranscriptHash);
        _secretTree = new SecretTree(
            _cs, _keySchedule.EncryptionSecret, _tree.LeafCount);
        _extensions = tentativeExtensions;
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
    /// <returns>An MlsGroup representing the joined group state.</returns>
    public static MlsGroup ProcessWelcome(
        ICipherSuite cs,
        Welcome welcome,
        KeyPackage myKeyPackage,
        byte[] myInitPrivateKey,
        byte[] myHpkePrivateKey,
        byte[] mySigningPrivateKey,
        MlsGroupConfig? config = null)
    {
        config ??= MlsGroupConfig.Default;

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
        byte[] pskSecret = new byte[cs.SecretSize]; // zeros(Nh) when no PSKs
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

        // Extract the ratchet tree from the GroupInfo extensions
        RatchetTree tree;
        byte[]? ratchetTreeData = null;
        foreach (var ext in groupInfo.Extensions)
        {
            if (ext.ExtensionType == 0x0002) // ratchet_tree
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
                "Welcome GroupInfo does not contain ratchet_tree extension.");
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
            cs, groupSecrets.JoinerSecret, serializedContext);

        // Verify confirmation tag
        byte[] expectedTag = keySchedule.ComputeConfirmationTag(
            cs, groupContext.ConfirmedTranscriptHash);
        if (!CryptographicOperations.FixedTimeEquals(expectedTag, groupInfo.ConfirmationTag))
            throw new InvalidOperationException("Invalid confirmation tag in GroupInfo.");

        // Compute interim transcript hash from confirmed + confirmation_tag
        byte[] interimHash = cs.Hash(
            Concat(groupContext.ConfirmedTranscriptHash, groupInfo.ConfirmationTag));

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

        return group;
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
        var treeExtension = new Extension(0x0002, treeBytes);

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
        RatchetTree tree, Proposal proposal, ref Extension[] extensions)
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
            // Find leaf with matching signature key and update it
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
        else if (proposal is GroupContextExtensionsProposal gce)
        {
            extensions = gce.Extensions;
        }
    }

    // ---- Helper: Sign a leaf node ----

    /// <summary>
    /// Signs a leaf node per RFC 9420 Section 7.2.
    /// The LeafNodeTBS includes all leaf fields except the signature,
    /// followed by source-specific context (group_id for Update/Commit).
    /// </summary>
    private static void SignLeafNode(
        ICipherSuite cs, LeafNode leafNode, byte[] signingPrivateKey, byte[]? groupId)
    {
        byte[] tbs = TlsCodec.Serialize(writer =>
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
            writer.WriteVectorV(inner =>
            {
                foreach (var ext in leafNode.Extensions)
                    ext.WriteTo(inner);
            });
            // LeafNodeTBS includes source-specific context:
            // For Update/Commit: group_id
            // For KeyPackage: nothing extra
            if (leafNode.Source == LeafNodeSource.Update ||
                leafNode.Source == LeafNodeSource.Commit)
            {
                if (groupId != null)
                    writer.WriteOpaqueV(groupId);
            }
        });

        leafNode.Signature = cs.SignWithLabel(signingPrivateKey, "LeafNodeTBS", tbs);
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
