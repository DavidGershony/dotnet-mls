using System.Text.Json;
using DotnetMls.Codec;
using DotnetMls.Crypto;
using DotnetMls.KeySchedule;
using DotnetMls.Message;
using DotnetMls.Types;
using Xunit;

namespace DotnetMls.Tests;

/// <summary>
/// Tests for CreatePrivateMessage encrypt → DecryptPrivateMessage round-trip.
/// Validates that the C# encrypt path produces output that the C# decrypt path can process.
/// </summary>
public class CreatePrivateMessageTests
{
    private static readonly JsonSerializerOptions JsonOpts = new()
    {
        PropertyNamingPolicy = JsonNamingPolicy.SnakeCaseLower,
    };

    private static string VectorPath(string fileName) =>
        Path.Combine(AppContext.BaseDirectory, "TestVectors", fileName);

    private static byte[] Hex(string hex) =>
        string.IsNullOrEmpty(hex) ? Array.Empty<byte>() : Convert.FromHexString(hex);

    /// <summary>
    /// Uses the message-protection test vector's keys and secrets to encrypt an application
    /// message via CreatePrivateMessage, then decrypts it via DecryptPrivateMessage.
    /// This must round-trip successfully.
    /// </summary>
    [Fact]
    public void CreatePrivateMessage_Application_RoundTrips()
    {
        var vectors = JsonSerializer.Deserialize<Rfc9420TestVectorTests.MessageProtectionVector[]>(
            File.ReadAllText(VectorPath("message-protection.json")), JsonOpts)!;
        var v = vectors.First(x => x.CipherSuite == 1);
        var cs = new CipherSuite0x0001();

        byte[] appData = System.Text.Encoding.UTF8.GetBytes("Round-trip application message");

        var framedContent = new FramedContent
        {
            GroupId = Hex(v.GroupId),
            Epoch = v.Epoch,
            Sender = new Sender { SenderType = SenderType.Member, LeafIndex = 0 },
            AuthenticatedData = Array.Empty<byte>(),
            ContentType = ContentType.Application,
            Content = appData,
        };

        var groupContext = new GroupContext
        {
            Version = ProtocolVersion.Mls10,
            CipherSuite = (ushort)v.CipherSuite,
            GroupId = Hex(v.GroupId),
            Epoch = v.Epoch,
            TreeHash = Hex(v.TreeHash),
            ConfirmedTranscriptHash = Hex(v.ConfirmedTranscriptHash),
        };
        byte[] serializedCtx = TlsCodec.Serialize(w => groupContext.WriteTo(w));

        // Encrypt
        var encTree = new SecretTree(cs, Hex(v.EncryptionSecret), 2);
        var privateMsg = MessageFraming.CreatePrivateMessage(
            framedContent, Hex(v.SignaturePriv), serializedCtx, cs,
            encTree, Hex(v.SenderDataSecret), null, 0, new byte[4]);

        // Decrypt with a fresh tree
        var decTree = new SecretTree(cs, Hex(v.EncryptionSecret), 2);
        var (decContent, decAuth) = MessageFraming.DecryptPrivateMessage(
            privateMsg, cs, decTree, Hex(v.SenderDataSecret));

        Assert.Equal(ContentType.Application, decContent.ContentType);
        Assert.Equal(appData, decContent.Content);
        Assert.Equal(Hex(v.GroupId), decContent.GroupId);
        Assert.Equal(v.Epoch, decContent.Epoch);
    }

    [Fact]
    public void CreatePrivateMessage_Proposal_RoundTrips()
    {
        var vectors = JsonSerializer.Deserialize<Rfc9420TestVectorTests.MessageProtectionVector[]>(
            File.ReadAllText(VectorPath("message-protection.json")), JsonOpts)!;
        var v = vectors.First(x => x.CipherSuite == 1);
        var cs = new CipherSuite0x0001();

        byte[] proposalData = Hex(v.Proposal);

        var framedContent = new FramedContent
        {
            GroupId = Hex(v.GroupId),
            Epoch = v.Epoch,
            Sender = new Sender { SenderType = SenderType.Member, LeafIndex = 1 },
            AuthenticatedData = Array.Empty<byte>(),
            ContentType = ContentType.Proposal,
            Content = proposalData,
        };

        var groupContext = new GroupContext
        {
            Version = ProtocolVersion.Mls10,
            CipherSuite = (ushort)v.CipherSuite,
            GroupId = Hex(v.GroupId),
            Epoch = v.Epoch,
            TreeHash = Hex(v.TreeHash),
            ConfirmedTranscriptHash = Hex(v.ConfirmedTranscriptHash),
        };
        byte[] serializedCtx = TlsCodec.Serialize(w => groupContext.WriteTo(w));

        var encTree = new SecretTree(cs, Hex(v.EncryptionSecret), 2);
        var privateMsg = MessageFraming.CreatePrivateMessage(
            framedContent, Hex(v.SignaturePriv), serializedCtx, cs,
            encTree, Hex(v.SenderDataSecret), null, 1, new byte[4]);

        var decTree = new SecretTree(cs, Hex(v.EncryptionSecret), 2);
        var (decContent, _) = MessageFraming.DecryptPrivateMessage(
            privateMsg, cs, decTree, Hex(v.SenderDataSecret));

        Assert.Equal(ContentType.Proposal, decContent.ContentType);
        Assert.Equal(proposalData, decContent.Content);
    }

    [Fact]
    public void CreatePrivateMessage_Commit_RoundTrips()
    {
        var vectors = JsonSerializer.Deserialize<Rfc9420TestVectorTests.MessageProtectionVector[]>(
            File.ReadAllText(VectorPath("message-protection.json")), JsonOpts)!;
        var v = vectors.First(x => x.CipherSuite == 1);
        var cs = new CipherSuite0x0001();

        byte[] commitData = Hex(v.Commit);
        byte[] confirmTag = new byte[32];
        for (int i = 0; i < 32; i++) confirmTag[i] = (byte)(i + 1);

        var framedContent = new FramedContent
        {
            GroupId = Hex(v.GroupId),
            Epoch = v.Epoch,
            Sender = new Sender { SenderType = SenderType.Member, LeafIndex = 0 },
            AuthenticatedData = Array.Empty<byte>(),
            ContentType = ContentType.Commit,
            Content = commitData,
        };

        var groupContext = new GroupContext
        {
            Version = ProtocolVersion.Mls10,
            CipherSuite = (ushort)v.CipherSuite,
            GroupId = Hex(v.GroupId),
            Epoch = v.Epoch,
            TreeHash = Hex(v.TreeHash),
            ConfirmedTranscriptHash = Hex(v.ConfirmedTranscriptHash),
        };
        byte[] serializedCtx = TlsCodec.Serialize(w => groupContext.WriteTo(w));

        var encTree = new SecretTree(cs, Hex(v.EncryptionSecret), 2);
        var privateMsg = MessageFraming.CreatePrivateMessage(
            framedContent, Hex(v.SignaturePriv), serializedCtx, cs,
            encTree, Hex(v.SenderDataSecret), confirmTag, 0, new byte[4]);

        var decTree = new SecretTree(cs, Hex(v.EncryptionSecret), 2);
        var (decContent, decAuth) = MessageFraming.DecryptPrivateMessage(
            privateMsg, cs, decTree, Hex(v.SenderDataSecret));

        Assert.Equal(ContentType.Commit, decContent.ContentType);
        Assert.Equal(commitData, decContent.Content);
        Assert.NotNull(decAuth.ConfirmationTag);
        Assert.Equal(confirmTag, decAuth.ConfirmationTag);
    }

    /// <summary>
    /// Minimal test: verify the key/nonce from encrypt matches decrypt for the same tree.
    /// </summary>
    [Fact]
    public void SecretTree_GetKeyAndNonce_Matches_GetKeyAndNonceForGeneration()
    {
        var cs = new CipherSuite0x0001();
        byte[] encSecret = new byte[32];
        for (int i = 0; i < 32; i++) encSecret[i] = (byte)(i + 1);

        // Two trees sharing the same encSecret reference.
        // Before the fix, treeA.EraseSecret would corrupt treeB's root.
        var treeA = new SecretTree(cs, encSecret, 2);
        var (keyA, nonceA, genA) = treeA.GetApplicationKeyAndNonce(0);
        Assert.Equal(0u, genA);

        var treeB = new SecretTree(cs, encSecret, 2);
        var (keyB, nonceB) = treeB.GetApplicationKeyAndNonceForGeneration(0, 0);

        Assert.True(keyA.SequenceEqual(keyB),
            $"KEY MISMATCH:\n" +
            $"  GetApplicationKeyAndNonce: {Convert.ToHexString(keyA)}\n" +
            $"  GetForGeneration(0,0):     {Convert.ToHexString(keyB)}");
        Assert.True(nonceA.SequenceEqual(nonceB),
            $"NONCE MISMATCH:\n" +
            $"  GetApplicationKeyAndNonce: {Convert.ToHexString(nonceA)}\n" +
            $"  GetForGeneration(0,0):     {Convert.ToHexString(nonceB)}");
    }

    /// <summary>
    /// Tests that getting handshake key first doesn't affect application key derivation.
    /// </summary>
    [Fact]
    public void SecretTree_Handshake_Then_Application_Same_As_Application_Only()
    {
        var cs = new CipherSuite0x0001();
        byte[] encSecret = new byte[32];
        for (int i = 0; i < 32; i++) encSecret[i] = (byte)(i + 1);

        // Tree A: get only application key
        var treeA = new SecretTree(cs, encSecret, 2);
        var (keyA, nonceA, genA) = treeA.GetApplicationKeyAndNonce(0);

        // Tree B: get handshake key first, then application key
        var treeB = new SecretTree(cs, encSecret, 2);
        var (hKeyB, hNonceB, hGenB) = treeB.GetHandshakeKeyAndNonce(0);
        var (keyB, nonceB, genB) = treeB.GetApplicationKeyAndNonce(0);

        Assert.Equal(keyA, keyB);
        Assert.Equal(nonceA, nonceB);
    }
}
