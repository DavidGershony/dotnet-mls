using DotnetMls.Codec;
using DotnetMls.Crypto;
using DotnetMls.Group;
using DotnetMls.Types;
using Xunit;
using Xunit.Abstractions;

namespace DotnetMls.Tests;

/// <summary>
/// Diagnostic test: creates a 3-member group step by step, dumping the tree hash,
/// GroupContext, and exporter secret at each epoch.
///
/// Finding: 1:1 chat with Whitenoise/OpenMLS works, but 3-user group breaks.
/// The exporter secret diverges at epoch 2 (after the second AddMember commit).
/// This test verifies all 3 members agree on the exporter secret within dotnet-mls.
/// </summary>
public class ThreeUserKeyScheduleTests
{
    private readonly ITestOutputHelper _output;
    private readonly ICipherSuite _cs = new CipherSuite0x0001();

    public ThreeUserKeyScheduleTests(ITestOutputHelper output) => _output = output;

    [Fact]
    public void ThreeUser_ExporterSecret_AllMembersAgree()
    {
        _output.WriteLine("=== 3-user group: exporter secret at each epoch ===\n");

        // Alice creates group
        var (aliceSigPriv, aliceSigPub) = _cs.GenerateSignatureKeyPair();
        var aliceGroup = MlsGroup.CreateGroup(_cs, "alice"u8.ToArray(), aliceSigPriv, aliceSigPub);
        DumpState("Alice (epoch 0)", aliceGroup);

        // Bob's KeyPackage
        var (bobSigPriv, bobSigPub) = _cs.GenerateSignatureKeyPair();
        var bobKp = MlsGroup.CreateKeyPackage(_cs, "bob"u8.ToArray(), bobSigPriv, bobSigPub,
            out var bobInitPriv, out var bobHpkePriv);

        // Alice adds Bob → epoch 1
        var addBob = aliceGroup.ProposeAdd(new[] { bobKp });
        var (commitBob, welcomeBob) = aliceGroup.Commit(addBob);
        aliceGroup.MergePendingCommit();
        DumpState("Alice (epoch 1, after adding Bob)", aliceGroup);

        // Bob joins via Welcome
        Assert.NotNull(welcomeBob);
        var bobGroup = MlsGroup.ProcessWelcome(_cs, welcomeBob!, bobKp, bobInitPriv, bobHpkePriv, bobSigPriv);
        DumpState("Bob (epoch 1, from Welcome)", bobGroup);

        // Epoch 1 exporter secrets
        var aliceExp1 = aliceGroup.ExportSecret("marmot", "group-event"u8.ToArray(), 32);
        var bobExp1 = bobGroup.ExportSecret("marmot", "group-event"u8.ToArray(), 32);
        _output.WriteLine($"  Alice exporter: {Hex(aliceExp1)}");
        _output.WriteLine($"  Bob   exporter: {Hex(bobExp1)}");
        Assert.Equal(aliceExp1, bobExp1);
        _output.WriteLine("  MATCH at epoch 1 ✓\n");

        // Charlie's KeyPackage
        var (charlieSigPriv, charlieSigPub) = _cs.GenerateSignatureKeyPair();
        var charlieKp = MlsGroup.CreateKeyPackage(_cs, "charlie"u8.ToArray(), charlieSigPriv, charlieSigPub,
            out var charlieInitPriv, out var charlieHpkePriv);

        // Alice adds Charlie → epoch 2
        var addCharlie = aliceGroup.ProposeAdd(new[] { charlieKp });
        var (commitCharlie, welcomeCharlie) = aliceGroup.Commit(addCharlie);
        aliceGroup.MergePendingCommit();
        DumpState("Alice (epoch 2, after adding Charlie)", aliceGroup);

        // Bob processes the commit
        var commitBytes = TlsCodec.Serialize(w => commitCharlie.WriteTo(w));
        var parsed = PrivateMessage.ReadFrom(new TlsReader(commitBytes));
        bobGroup.ProcessCommit(parsed);
        DumpState("Bob (epoch 2, after processing commit)", bobGroup);

        // Charlie joins via Welcome
        Assert.NotNull(welcomeCharlie);
        var charlieGroup = MlsGroup.ProcessWelcome(_cs, welcomeCharlie!, charlieKp,
            charlieInitPriv, charlieHpkePriv, charlieSigPriv);
        DumpState("Charlie (epoch 2, from Welcome)", charlieGroup);

        // Epoch 2 exporter secrets
        var aliceExp2 = aliceGroup.ExportSecret("marmot", "group-event"u8.ToArray(), 32);
        var bobExp2 = bobGroup.ExportSecret("marmot", "group-event"u8.ToArray(), 32);
        var charlieExp2 = charlieGroup.ExportSecret("marmot", "group-event"u8.ToArray(), 32);

        _output.WriteLine($"  Alice   exporter: {Hex(aliceExp2)}");
        _output.WriteLine($"  Bob     exporter: {Hex(bobExp2)}");
        _output.WriteLine($"  Charlie exporter: {Hex(charlieExp2)}");

        bool ab = aliceExp2.SequenceEqual(bobExp2);
        bool ac = aliceExp2.SequenceEqual(charlieExp2);
        bool bc = bobExp2.SequenceEqual(charlieExp2);
        _output.WriteLine($"  Alice == Bob:     {(ab ? "MATCH ✓" : "MISMATCH ✗")}");
        _output.WriteLine($"  Alice == Charlie: {(ac ? "MATCH ✓" : "MISMATCH ✗")}");
        _output.WriteLine($"  Bob   == Charlie: {(bc ? "MATCH ✓" : "MISMATCH ✗")}");

        // Tree hashes
        _output.WriteLine($"\n  Alice   tree_hash: {Hex(aliceGroup.GroupContext.TreeHash)}");
        _output.WriteLine($"  Bob     tree_hash: {Hex(bobGroup.GroupContext.TreeHash)}");
        _output.WriteLine($"  Charlie tree_hash: {Hex(charlieGroup.GroupContext.TreeHash)}");

        // Transcript hashes
        _output.WriteLine($"\n  Alice   transcript: {Hex(aliceGroup.GroupContext.ConfirmedTranscriptHash)}");
        _output.WriteLine($"  Bob     transcript: {Hex(bobGroup.GroupContext.ConfirmedTranscriptHash)}");
        _output.WriteLine($"  Charlie transcript: {Hex(charlieGroup.GroupContext.ConfirmedTranscriptHash)}");

        Assert.True(ab, "Alice and Bob exporter secrets must match at epoch 2");
        Assert.True(ac, "Alice and Charlie exporter secrets must match at epoch 2");
        Assert.True(bc, "Bob and Charlie exporter secrets must match at epoch 2");

        // Round-trip test: Alice encrypts, Charlie decrypts
        _output.WriteLine("\n=== Round-trip: Alice encrypts at epoch 2, all decrypt ===");
        var plaintext = System.Text.Encoding.UTF8.GetBytes("Hello from Alice!");
        var aliceEncrypted = aliceGroup.EncryptApplicationMessage(plaintext);
        var encBytes = TlsCodec.Serialize(w => aliceEncrypted.WriteTo(w));

        var bobDecrypted = bobGroup.DecryptApplicationMessage(
            PrivateMessage.ReadFrom(new TlsReader(encBytes)));
        var charlieDecrypted = charlieGroup.DecryptApplicationMessage(
            PrivateMessage.ReadFrom(new TlsReader(encBytes)));

        _output.WriteLine($"  Bob decrypted:     \"{System.Text.Encoding.UTF8.GetString(bobDecrypted.plaintext)}\"");
        _output.WriteLine($"  Charlie decrypted: \"{System.Text.Encoding.UTF8.GetString(charlieDecrypted.plaintext)}\"");

        Assert.Equal(plaintext, bobDecrypted.plaintext);
        Assert.Equal(plaintext, charlieDecrypted.plaintext);
        _output.WriteLine("  All round-trips OK ✓");
    }

    private void DumpState(string label, MlsGroup group)
    {
        _output.WriteLine($"[{label}]");
        _output.WriteLine($"  Epoch: {group.Epoch}");
        _output.WriteLine($"  TreeHash: {Hex(group.GroupContext.TreeHash)}");
        _output.WriteLine($"  Transcript: {Hex(group.GroupContext.ConfirmedTranscriptHash)}");
        _output.WriteLine($"  Tree ({group.Tree.LeafCount} leaves, {group.Tree.NodeCount} nodes):");
        for (int i = 0; i < group.Tree.NodeCount; i++)
        {
            var node = group.Tree.GetNode((uint)i);
            if (node is DotnetMls.Tree.TreeNode.Leaf leaf)
            {
                if (leaf.Value != null)
                    _output.WriteLine($"    [{i}] Leaf: sig={Hex(leaf.Value.SignatureKey)[..16]}..., src={leaf.Value.Source}");
                else
                    _output.WriteLine($"    [{i}] Leaf: (blank)");
            }
            else if (node is DotnetMls.Tree.TreeNode.Parent parent)
            {
                if (parent.Value != null)
                    _output.WriteLine($"    [{i}] Parent: enc={Hex(parent.Value.EncryptionKey)[..16]}..., unmerged=[{string.Join(",", parent.Value.UnmergedLeaves)}], parentHash={Hex(parent.Value.ParentHash)[..Math.Min(16, Hex(parent.Value.ParentHash).Length)]}");
                else
                    _output.WriteLine($"    [{i}] Parent: (blank)");
            }
            else
            {
                _output.WriteLine($"    [{i}] null");
            }
        }
        _output.WriteLine("");
    }

    private static string Hex(byte[] data) => Convert.ToHexString(data).ToLowerInvariant();
}
