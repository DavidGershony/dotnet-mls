using System.Security.Cryptography;
using System.Text.Json;
using System.Text.Json.Serialization;
using DotnetMls.Codec;
using DotnetMls.Crypto;
using DotnetMls.Group;
using DotnetMls.KeySchedule;
using DotnetMls.Message;
using DotnetMls.Tree;
using DotnetMls.Types;
using Xunit;

namespace DotnetMls.Tests;

/// <summary>
/// Tests against the official RFC 9420 test vectors from
/// https://github.com/mlswg/mls-implementations/tree/main/test-vectors
/// </summary>
public class Rfc9420TestVectorTests
{
    private static readonly JsonSerializerOptions JsonOpts = new()
    {
        PropertyNamingPolicy = JsonNamingPolicy.SnakeCaseLower,
    };

    private static string VectorPath(string fileName) =>
        Path.Combine(AppContext.BaseDirectory, "TestVectors", fileName);

    private static byte[] Hex(string hex)
    {
        if (string.IsNullOrEmpty(hex)) return Array.Empty<byte>();
        return Convert.FromHexString(hex);
    }

    // ================================================================
    // Tree Math Test Vectors
    // ================================================================

    public class TreeMathVector
    {
        [JsonPropertyName("n_leaves")]
        public uint NLeaves { get; set; }

        [JsonPropertyName("n_nodes")]
        public uint NNodes { get; set; }

        [JsonPropertyName("root")]
        public uint Root { get; set; }

        [JsonPropertyName("left")]
        public uint?[] Left { get; set; } = Array.Empty<uint?>();

        [JsonPropertyName("right")]
        public uint?[] Right { get; set; } = Array.Empty<uint?>();

        [JsonPropertyName("parent")]
        public uint?[] Parent { get; set; } = Array.Empty<uint?>();

        [JsonPropertyName("sibling")]
        public uint?[] Sibling { get; set; } = Array.Empty<uint?>();

        public override string ToString() => $"n_leaves={NLeaves}";
    }

    public static IEnumerable<object[]> TreeMathVectors()
    {
        var vectors = JsonSerializer.Deserialize<TreeMathVector[]>(
            File.ReadAllText(VectorPath("tree-math.json")), JsonOpts)!;
        foreach (var v in vectors)
            yield return new object[] { v };
    }

    [Theory]
    [MemberData(nameof(TreeMathVectors))]
    public void TreeMath_MatchesOfficialVectors(TreeMathVector v)
    {
        // n_nodes
        Assert.Equal(v.NNodes, TreeMath.NodeCount(v.NLeaves));

        // root
        if (v.NLeaves > 0)
            Assert.Equal(v.Root, TreeMath.Root(v.NLeaves));

        uint nodeCount = v.NNodes;

        for (uint i = 0; i < v.NNodes; i++)
        {
            // left
            if (i < (uint)v.Left.Length)
            {
                if (v.Left[i].HasValue)
                {
                    Assert.False(TreeMath.IsLeaf(i),
                        $"n_leaves={v.NLeaves}: node {i} has left child but IsLeaf=true");
                    Assert.Equal(v.Left[i].Value, TreeMath.Left(i));
                }
            }

            // right
            if (i < (uint)v.Right.Length)
            {
                if (v.Right[i].HasValue)
                {
                    Assert.False(TreeMath.IsLeaf(i),
                        $"n_leaves={v.NLeaves}: node {i} has right child but IsLeaf=true");
                    Assert.Equal(v.Right[i].Value, TreeMath.Right(i));
                }
            }

            // parent
            if (i < (uint)v.Parent.Length)
            {
                if (v.Parent[i].HasValue)
                {
                    Assert.Equal(v.Parent[i].Value, TreeMath.Parent(i, nodeCount));
                }
                // null parent means root node — calling Parent would throw
            }

            // sibling
            if (i < (uint)v.Sibling.Length)
            {
                if (v.Sibling[i].HasValue)
                {
                    Assert.Equal(v.Sibling[i].Value, TreeMath.Sibling(i, nodeCount));
                }
            }
        }
    }

    // ================================================================
    // Crypto Basics Test Vectors
    // ================================================================

    public class CryptoBasicsVector
    {
        [JsonPropertyName("cipher_suite")]
        public ushort CipherSuite { get; set; }

        [JsonPropertyName("ref_hash")]
        public RefHashCase RefHash { get; set; } = new();

        [JsonPropertyName("expand_with_label")]
        public ExpandWithLabelCase ExpandWithLabel { get; set; } = new();

        [JsonPropertyName("derive_secret")]
        public DeriveSecretCase DeriveSecret { get; set; } = new();

        [JsonPropertyName("sign_with_label")]
        public SignWithLabelCase SignWithLabel { get; set; } = new();

        [JsonPropertyName("encrypt_with_label")]
        public EncryptWithLabelCase EncryptWithLabel { get; set; } = new();

        [JsonPropertyName("derive_tree_secret")]
        public DeriveTreeSecretCase DeriveTreeSecret { get; set; } = new();
    }

    public class RefHashCase
    {
        [JsonPropertyName("label")]
        public string Label { get; set; } = "";
        [JsonPropertyName("value")]
        public string Value { get; set; } = "";
        [JsonPropertyName("out")]
        public string Out { get; set; } = "";
    }

    public class ExpandWithLabelCase
    {
        [JsonPropertyName("secret")]
        public string Secret { get; set; } = "";
        [JsonPropertyName("label")]
        public string Label { get; set; } = "";
        [JsonPropertyName("context")]
        public string Context { get; set; } = "";
        [JsonPropertyName("length")]
        public int Length { get; set; }
        [JsonPropertyName("out")]
        public string Out { get; set; } = "";
    }

    public class DeriveSecretCase
    {
        [JsonPropertyName("secret")]
        public string Secret { get; set; } = "";
        [JsonPropertyName("label")]
        public string Label { get; set; } = "";
        [JsonPropertyName("out")]
        public string Out { get; set; } = "";
    }

    public class SignWithLabelCase
    {
        [JsonPropertyName("priv")]
        public string Priv { get; set; } = "";
        [JsonPropertyName("pub")]
        public string Pub { get; set; } = "";
        [JsonPropertyName("content")]
        public string Content { get; set; } = "";
        [JsonPropertyName("label")]
        public string Label { get; set; } = "";
        [JsonPropertyName("signature")]
        public string Signature { get; set; } = "";
    }

    public class EncryptWithLabelCase
    {
        [JsonPropertyName("priv")]
        public string Priv { get; set; } = "";
        [JsonPropertyName("pub")]
        public string Pub { get; set; } = "";
        [JsonPropertyName("label")]
        public string Label { get; set; } = "";
        [JsonPropertyName("context")]
        public string Context { get; set; } = "";
        [JsonPropertyName("plaintext")]
        public string Plaintext { get; set; } = "";
        [JsonPropertyName("kem_output")]
        public string KemOutput { get; set; } = "";
        [JsonPropertyName("ciphertext")]
        public string Ciphertext { get; set; } = "";
    }

    public class DeriveTreeSecretCase
    {
        [JsonPropertyName("secret")]
        public string Secret { get; set; } = "";
        [JsonPropertyName("label")]
        public string Label { get; set; } = "";
        [JsonPropertyName("generation")]
        public uint Generation { get; set; }
        [JsonPropertyName("length")]
        public int Length { get; set; }
        [JsonPropertyName("out")]
        public string Out { get; set; } = "";
    }

    [Fact]
    public void CryptoBasics_ExpandWithLabel_MatchesOfficialVectors()
    {
        var vectors = JsonSerializer.Deserialize<CryptoBasicsVector[]>(
            File.ReadAllText(VectorPath("crypto-basics.json")), JsonOpts)!;

        // We only support cipher suite 1 (MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519)
        var v = vectors.First(x => x.CipherSuite == 1);
        var cs = new CipherSuite0x0001();

        var result = cs.ExpandWithLabel(
            Hex(v.ExpandWithLabel.Secret),
            v.ExpandWithLabel.Label,
            Hex(v.ExpandWithLabel.Context),
            v.ExpandWithLabel.Length);

        Assert.Equal(Hex(v.ExpandWithLabel.Out), result);
    }

    [Fact]
    public void CryptoBasics_DeriveSecret_MatchesOfficialVectors()
    {
        var vectors = JsonSerializer.Deserialize<CryptoBasicsVector[]>(
            File.ReadAllText(VectorPath("crypto-basics.json")), JsonOpts)!;

        var v = vectors.First(x => x.CipherSuite == 1);
        var cs = new CipherSuite0x0001();

        var result = cs.DeriveSecret(
            Hex(v.DeriveSecret.Secret),
            v.DeriveSecret.Label);

        Assert.Equal(Hex(v.DeriveSecret.Out), result);
    }

    [Fact]
    public void CryptoBasics_RefHash_MatchesOfficialVectors()
    {
        var vectors = JsonSerializer.Deserialize<CryptoBasicsVector[]>(
            File.ReadAllText(VectorPath("crypto-basics.json")), JsonOpts)!;

        var v = vectors.First(x => x.CipherSuite == 1);
        var cs = new CipherSuite0x0001();

        var result = cs.RefHash(v.RefHash.Label, Hex(v.RefHash.Value));
        Assert.Equal(Hex(v.RefHash.Out), result);
    }

    [Fact]
    public void CryptoBasics_SignWithLabel_VerifiesOfficialVectors()
    {
        var vectors = JsonSerializer.Deserialize<CryptoBasicsVector[]>(
            File.ReadAllText(VectorPath("crypto-basics.json")), JsonOpts)!;

        var v = vectors.First(x => x.CipherSuite == 1);
        var cs = new CipherSuite0x0001();

        // Verify the test vector signature
        bool valid = cs.VerifyWithLabel(
            Hex(v.SignWithLabel.Pub),
            v.SignWithLabel.Label,
            Hex(v.SignWithLabel.Content),
            Hex(v.SignWithLabel.Signature));

        Assert.True(valid, "Test vector signature should verify");

        // Ed25519 is deterministic — our signature must match the test vector exactly
        var ourSig = cs.SignWithLabel(
            Hex(v.SignWithLabel.Priv),
            v.SignWithLabel.Label,
            Hex(v.SignWithLabel.Content));

        Assert.Equal(Hex(v.SignWithLabel.Signature), ourSig);
    }

    [Fact]
    public void CryptoBasics_DeriveTreeSecret_MatchesOfficialVectors()
    {
        var vectors = JsonSerializer.Deserialize<CryptoBasicsVector[]>(
            File.ReadAllText(VectorPath("crypto-basics.json")), JsonOpts)!;

        var v = vectors.First(x => x.CipherSuite == 1);
        var cs = new CipherSuite0x0001();

        // DeriveTreeSecret(Secret, Label, Generation, Length) =
        //   ExpandWithLabel(Secret, Label, uint32(Generation), Length)
        var genBytes = new byte[4];
        genBytes[0] = (byte)(v.DeriveTreeSecret.Generation >> 24);
        genBytes[1] = (byte)(v.DeriveTreeSecret.Generation >> 16);
        genBytes[2] = (byte)(v.DeriveTreeSecret.Generation >> 8);
        genBytes[3] = (byte)(v.DeriveTreeSecret.Generation & 0xFF);

        var result = cs.ExpandWithLabel(
            Hex(v.DeriveTreeSecret.Secret),
            v.DeriveTreeSecret.Label,
            genBytes,
            v.DeriveTreeSecret.Length);

        Assert.Equal(Hex(v.DeriveTreeSecret.Out), result);
    }

    [Fact]
    public void CryptoBasics_EncryptWithLabel_DecryptsOfficialVectors()
    {
        var vectors = JsonSerializer.Deserialize<CryptoBasicsVector[]>(
            File.ReadAllText(VectorPath("crypto-basics.json")), JsonOpts)!;

        var v = vectors.First(x => x.CipherSuite == 1);
        var cs = new CipherSuite0x0001();

        // Build EncryptContext info = struct { opaque label<V>; opaque content<V>; }
        byte[] info = TlsCodec.Serialize(w =>
        {
            byte[] fullLabel = System.Text.Encoding.ASCII.GetBytes("MLS 1.0 " + v.EncryptWithLabel.Label);
            w.WriteOpaqueV(fullLabel);
            w.WriteOpaqueV(Hex(v.EncryptWithLabel.Context));
        });

        // Decrypt the test vector ciphertext
        byte[] plaintext = cs.HpkeOpen(
            Hex(v.EncryptWithLabel.Priv),
            Hex(v.EncryptWithLabel.KemOutput),
            info,
            Array.Empty<byte>(),
            Hex(v.EncryptWithLabel.Ciphertext));

        Assert.Equal(Hex(v.EncryptWithLabel.Plaintext), plaintext);
    }

    [Fact]
    public void CryptoBasics_EncryptWithLabel_RoundTrips()
    {
        var vectors = JsonSerializer.Deserialize<CryptoBasicsVector[]>(
            File.ReadAllText(VectorPath("crypto-basics.json")), JsonOpts)!;

        var v = vectors.First(x => x.CipherSuite == 1);
        var cs = new CipherSuite0x0001();

        byte[] info = TlsCodec.Serialize(w =>
        {
            byte[] fullLabel = System.Text.Encoding.ASCII.GetBytes("MLS 1.0 " + v.EncryptWithLabel.Label);
            w.WriteOpaqueV(fullLabel);
            w.WriteOpaqueV(Hex(v.EncryptWithLabel.Context));
        });

        // Encrypt with the test vector's public key (randomized — won't match test vector ciphertext)
        byte[] sealed_ = cs.HpkeSeal(
            Hex(v.EncryptWithLabel.Pub), info, Array.Empty<byte>(), Hex(v.EncryptWithLabel.Plaintext));

        // Decrypt with the test vector's private key
        byte[] kemOutput = sealed_[..32];
        byte[] ciphertext = sealed_[32..];
        byte[] decrypted = cs.HpkeOpen(
            Hex(v.EncryptWithLabel.Priv), kemOutput, info, Array.Empty<byte>(), ciphertext);

        Assert.Equal(Hex(v.EncryptWithLabel.Plaintext), decrypted);
    }

    // ================================================================
    // Key Schedule Test Vectors
    // ================================================================

    public class KeyScheduleVector
    {
        [JsonPropertyName("cipher_suite")]
        public ushort CipherSuite { get; set; }

        [JsonPropertyName("group_id")]
        public string GroupId { get; set; } = "";

        [JsonPropertyName("initial_init_secret")]
        public string InitialInitSecret { get; set; } = "";

        [JsonPropertyName("epochs")]
        public KeyScheduleEpochVector[] Epochs { get; set; } = Array.Empty<KeyScheduleEpochVector>();
    }

    public class KeyScheduleEpochVector
    {
        [JsonPropertyName("tree_hash")]
        public string TreeHash { get; set; } = "";

        [JsonPropertyName("commit_secret")]
        public string CommitSecret { get; set; } = "";

        [JsonPropertyName("psk_secret")]
        public string PskSecret { get; set; } = "";

        [JsonPropertyName("confirmed_transcript_hash")]
        public string ConfirmedTranscriptHash { get; set; } = "";

        [JsonPropertyName("group_context")]
        public string GroupContext { get; set; } = "";

        [JsonPropertyName("joiner_secret")]
        public string JoinerSecret { get; set; } = "";

        [JsonPropertyName("welcome_secret")]
        public string WelcomeSecret { get; set; } = "";

        [JsonPropertyName("init_secret")]
        public string InitSecret { get; set; } = "";

        [JsonPropertyName("sender_data_secret")]
        public string SenderDataSecret { get; set; } = "";

        [JsonPropertyName("encryption_secret")]
        public string EncryptionSecret { get; set; } = "";

        [JsonPropertyName("exporter_secret")]
        public string ExporterSecret { get; set; } = "";

        [JsonPropertyName("epoch_authenticator")]
        public string EpochAuthenticator { get; set; } = "";

        [JsonPropertyName("external_secret")]
        public string ExternalSecret { get; set; } = "";

        [JsonPropertyName("confirmation_key")]
        public string ConfirmationKey { get; set; } = "";

        [JsonPropertyName("membership_key")]
        public string MembershipKey { get; set; } = "";

        [JsonPropertyName("resumption_psk")]
        public string ResumptionPsk { get; set; } = "";

        [JsonPropertyName("external_pub")]
        public string ExternalPub { get; set; } = "";

        [JsonPropertyName("exporter")]
        public ExporterCase Exporter { get; set; } = new();
    }

    public class ExporterCase
    {
        [JsonPropertyName("label")]
        public string Label { get; set; } = "";
        [JsonPropertyName("context")]
        public string Context { get; set; } = "";
        [JsonPropertyName("length")]
        public int Length { get; set; }
        [JsonPropertyName("secret")]
        public string Secret { get; set; } = "";
    }

    [Fact]
    public void KeySchedule_JoinerSecret_MatchesOfficialVectors()
    {
        var vectors = JsonSerializer.Deserialize<KeyScheduleVector[]>(
            File.ReadAllText(VectorPath("key-schedule.json")), JsonOpts)!;

        var v = vectors.First(x => x.CipherSuite == 1);
        var cs = new CipherSuite0x0001();

        byte[] initSecret = Hex(v.InitialInitSecret);
        var epochVec = v.Epochs[0];
        byte[] commitSecret = Hex(epochVec.CommitSecret);
        byte[] groupContext = Hex(epochVec.GroupContext);

        // Per RFC 9420 §8:
        //   extracted = KDF.Extract(salt=init_secret, ikm=commit_secret)
        //   joiner_secret = ExpandWithLabel(extracted, "joiner", GroupContext, Nh)
        var extracted = cs.Extract(initSecret, commitSecret);
        var joinerSecret = cs.ExpandWithLabel(extracted, "joiner", groupContext, cs.SecretSize);

        Assert.Equal(Hex(epochVec.JoinerSecret), joinerSecret);
    }

    [Fact]
    public void KeySchedule_MatchesOfficialVectors()
    {
        // Epochs are sequential (each uses previous epoch's init_secret),
        // so this test must remain a single [Fact] with a loop.
        var vectors = JsonSerializer.Deserialize<KeyScheduleVector[]>(
            File.ReadAllText(VectorPath("key-schedule.json")), JsonOpts)!;

        var v = vectors.First(x => x.CipherSuite == 1);
        var cs = new CipherSuite0x0001();

        byte[] initSecret = Hex(v.InitialInitSecret);

        foreach (var epochVec in v.Epochs)
        {
            byte[] commitSecret = Hex(epochVec.CommitSecret);
            byte[] pskSecret = Hex(epochVec.PskSecret);
            byte[] groupContext = Hex(epochVec.GroupContext);

            var epoch = KeyScheduleEpoch.Create(cs, initSecret, commitSecret, groupContext, pskSecret);

            Assert.Equal(Hex(epochVec.JoinerSecret), epoch.JoinerSecret);
            Assert.Equal(Hex(epochVec.WelcomeSecret), epoch.WelcomeSecret);
            Assert.Equal(Hex(epochVec.SenderDataSecret), epoch.SenderDataSecret);
            Assert.Equal(Hex(epochVec.EncryptionSecret), epoch.EncryptionSecret);
            Assert.Equal(Hex(epochVec.ExporterSecret), epoch.ExporterSecret);
            Assert.Equal(Hex(epochVec.EpochAuthenticator), epoch.EpochAuthenticator);
            Assert.Equal(Hex(epochVec.ExternalSecret), epoch.ExternalSecret);
            Assert.Equal(Hex(epochVec.ConfirmationKey), epoch.ConfirmationKey);
            Assert.Equal(Hex(epochVec.MembershipKey), epoch.MembershipKey);
            Assert.Equal(Hex(epochVec.ResumptionPsk), epoch.ResumptionPsk);
            Assert.Equal(Hex(epochVec.InitSecret), epoch.InitSecret);
            Assert.Equal(Hex(epochVec.ExternalPub), epoch.ExternalPub);

            // Test MLS-Exporter
            var exported = epoch.DeriveExporterSecret(cs,
                epochVec.Exporter.Label,
                Hex(epochVec.Exporter.Context),
                epochVec.Exporter.Length);
            Assert.Equal(Hex(epochVec.Exporter.Secret), exported);

            // Use this epoch's init_secret for the next epoch
            initSecret = epoch.InitSecret;
        }
    }

    // ================================================================
    // Deserialization (VarInt) Test Vectors
    // ================================================================

    public class DeserializationVector
    {
        [JsonPropertyName("vlbytes_header")]
        public string VlbytesHeader { get; set; } = "";

        [JsonPropertyName("length")]
        public ulong Length { get; set; }

        public override string ToString() => $"length={Length}";
    }

    public static IEnumerable<object[]> DeserializationVectors()
    {
        var vectors = JsonSerializer.Deserialize<DeserializationVector[]>(
            File.ReadAllText(VectorPath("deserialization.json")), JsonOpts)!;
        foreach (var v in vectors)
            yield return new object[] { v };
    }

    [Theory]
    [MemberData(nameof(DeserializationVectors))]
    public void Deserialization_VarInt_MatchesOfficialVectors(DeserializationVector v)
    {
        byte[] header = Hex(v.VlbytesHeader);

        // Decode
        var reader = new TlsReader(header);
        ulong decoded = QuicVarint.Read(reader);
        Assert.Equal(v.Length, decoded);

        // Encode
        byte[] encoded = TlsCodec.Serialize(w => QuicVarint.Write(w, v.Length));
        Assert.Equal(header, encoded);
    }

    // ================================================================
    // Transcript Hash Test Vectors
    // ================================================================

    public class TranscriptHashVector
    {
        [JsonPropertyName("cipher_suite")]
        public ushort CipherSuite { get; set; }

        [JsonPropertyName("confirmation_key")]
        public string ConfirmationKey { get; set; } = "";

        [JsonPropertyName("authenticated_content")]
        public string AuthenticatedContent { get; set; } = "";

        [JsonPropertyName("interim_transcript_hash_before")]
        public string InterimTranscriptHashBefore { get; set; } = "";

        [JsonPropertyName("confirmed_transcript_hash_after")]
        public string ConfirmedTranscriptHashAfter { get; set; } = "";

        [JsonPropertyName("interim_transcript_hash_after")]
        public string InterimTranscriptHashAfter { get; set; } = "";
    }

    [Fact]
    public void TranscriptHash_ConfirmedHash_MatchesOfficialVectors()
    {
        var vectors = JsonSerializer.Deserialize<TranscriptHashVector[]>(
            File.ReadAllText(VectorPath("transcript-hashes.json")), JsonOpts)!;

        var v = vectors.First(x => x.CipherSuite == 1);
        var cs = new CipherSuite0x0001();

        byte[] interimBefore = Hex(v.InterimTranscriptHashBefore);
        byte[] authenticatedContent = Hex(v.AuthenticatedContent);
        byte[] confirmationKey = Hex(v.ConfirmationKey);

        byte[] expectedConfirmedHash = Hex(v.ConfirmedTranscriptHashAfter);
        byte[] expectedInterimAfter = Hex(v.InterimTranscriptHashAfter);

        // Per RFC 9420 §8.2:
        // ConfirmedTranscriptHashInput = wire_format || content || signature (no confirmation_tag)
        // The AuthenticatedContent ends with VarInt(32) || 32-byte confirmation_tag.
        // Strip the last 33 bytes to get ConfirmedTranscriptHashInput.
        int tagPrefixLen = 1; // VarInt(32) = 0x20 = 1 byte
        int tagLen = cs.HashSize; // MAC output size = 32 for SHA-256
        byte[] confirmedInput = authenticatedContent[..(authenticatedContent.Length - tagPrefixLen - tagLen)];
        byte[] confirmationTagFromVector = authenticatedContent[(authenticatedContent.Length - tagLen)..];

        // Use the production TranscriptHash class
        var transcriptHash = new TranscriptHash(interimBefore, interimBefore);

        // Compute confirmation_tag to pass to Update
        // (The test vector provides confirmation_key, so we derive the tag from the expected confirmed hash)
        // However, Update needs the tag AFTER computing confirmed hash, so we verify step by step.

        // Step 1: Verify confirmed hash via production code
        // TranscriptHash.Update computes both, so we need the correct confirmation_tag.
        // From the vector: confirmation_tag = MAC(confirmation_key, confirmed_transcript_hash)
        // But we can't call Update without the tag... Use direct verification instead:
        // Actually, the test vector gives us the authenticated_content which contains the tag.
        // Let's extract it and use Update.
        byte[] confirmationTag = cs.Mac(confirmationKey, expectedConfirmedHash);

        // Verify Update produces correct results
        transcriptHash.Update(cs, confirmedInput, confirmationTag);

        Assert.Equal(expectedConfirmedHash, transcriptHash.ConfirmedTranscriptHash);
        Assert.Equal(expectedInterimAfter, transcriptHash.InterimTranscriptHash);
    }

    private static byte[] Concat(byte[] a, byte[] b)
    {
        var result = new byte[a.Length + b.Length];
        Buffer.BlockCopy(a, 0, result, 0, a.Length);
        Buffer.BlockCopy(b, 0, result, a.Length, b.Length);
        return result;
    }

    // ================================================================
    // Secret Tree Test Vectors
    // ================================================================

    public class SecretTreeVector
    {
        [JsonPropertyName("cipher_suite")]
        public ushort CipherSuite { get; set; }

        [JsonPropertyName("encryption_secret")]
        public string EncryptionSecret { get; set; } = "";

        [JsonPropertyName("sender_data")]
        public SenderDataCase SenderData { get; set; } = new();

        [JsonPropertyName("leaves")]
        public LeafGeneration[][] Leaves { get; set; } = Array.Empty<LeafGeneration[]>();

        public override string ToString() => $"cs={CipherSuite},leaves={Leaves.Length}";
    }

    public class SenderDataCase
    {
        [JsonPropertyName("sender_data_secret")]
        public string SenderDataSecret { get; set; } = "";
        [JsonPropertyName("ciphertext")]
        public string Ciphertext { get; set; } = "";
        [JsonPropertyName("key")]
        public string Key { get; set; } = "";
        [JsonPropertyName("nonce")]
        public string Nonce { get; set; } = "";
    }

    public class LeafGeneration
    {
        [JsonPropertyName("generation")]
        public uint Generation { get; set; }
        [JsonPropertyName("application_key")]
        public string ApplicationKey { get; set; } = "";
        [JsonPropertyName("application_nonce")]
        public string ApplicationNonce { get; set; } = "";
        [JsonPropertyName("handshake_key")]
        public string HandshakeKey { get; set; } = "";
        [JsonPropertyName("handshake_nonce")]
        public string HandshakeNonce { get; set; } = "";
    }

    public static IEnumerable<object[]> SecretTreeVectors()
    {
        var vectors = JsonSerializer.Deserialize<SecretTreeVector[]>(
            File.ReadAllText(VectorPath("secret-tree.json")), JsonOpts)!;
        foreach (var v in vectors.Where(x => x.CipherSuite == 1))
            yield return new object[] { v };
    }

    [Theory]
    [MemberData(nameof(SecretTreeVectors))]
    public void SecretTree_MatchesOfficialVectors(SecretTreeVector v)
    {
        var cs = new CipherSuite0x0001();
        uint leafCount = (uint)v.Leaves.Length;
        var tree = new SecretTree(cs, Hex(v.EncryptionSecret), leafCount);

        for (uint leafIdx = 0; leafIdx < leafCount; leafIdx++)
        {
            foreach (var gen in v.Leaves[leafIdx])
            {
                // Use generation-specific lookup to handle non-consecutive generations
                var (hKey, hNonce) = tree.GetHandshakeKeyAndNonceForGeneration(leafIdx, gen.Generation);
                Assert.Equal(Hex(gen.HandshakeKey), hKey);
                Assert.Equal(Hex(gen.HandshakeNonce), hNonce);

                var (aKey, aNonce) = tree.GetApplicationKeyAndNonceForGeneration(leafIdx, gen.Generation);
                Assert.Equal(Hex(gen.ApplicationKey), aKey);
                Assert.Equal(Hex(gen.ApplicationNonce), aNonce);
            }
        }
    }

    [Fact]
    public void SecretTree_SenderDataKey_MatchesOfficialVectors()
    {
        var vectors = JsonSerializer.Deserialize<SecretTreeVector[]>(
            File.ReadAllText(VectorPath("secret-tree.json")), JsonOpts)!;

        var v = vectors.First(x => x.CipherSuite == 1);
        var cs = new CipherSuite0x0001();

        // Per RFC 9420 §9.2:
        // sender_data_key = ExpandWithLabel(sender_data_secret, "key", ciphertext_sample, Nk)
        // sender_data_nonce = ExpandWithLabel(sender_data_secret, "nonce", ciphertext_sample, Nn)
        // ciphertext_sample = first KDF.Nh bytes of ciphertext
        byte[] senderDataSecret = Hex(v.SenderData.SenderDataSecret);
        byte[] ciphertext = Hex(v.SenderData.Ciphertext);
        byte[] sample = ciphertext[..cs.HashSize]; // first Nh bytes

        byte[] key = cs.ExpandWithLabel(senderDataSecret, "key", sample, cs.AeadKeySize);
        byte[] nonce = cs.ExpandWithLabel(senderDataSecret, "nonce", sample, cs.AeadNonceSize);

        Assert.Equal(Hex(v.SenderData.Key), key);
        Assert.Equal(Hex(v.SenderData.Nonce), nonce);
    }

    // ================================================================
    // PSK Secret Test Vectors (RFC 9420 Section 8.4)
    // ================================================================

    public class PskSecretVector
    {
        [JsonPropertyName("cipher_suite")]
        public int CipherSuite { get; set; }

        [JsonPropertyName("psks")]
        public PskEntry[] Psks { get; set; } = Array.Empty<PskEntry>();

        [JsonPropertyName("psk_secret")]
        public string PskSecret { get; set; } = "";

        public override string ToString() => $"cs={CipherSuite},psk_count={Psks.Length}";
    }

    public class PskEntry
    {
        [JsonPropertyName("psk_id")]
        public string PskId { get; set; } = "";

        [JsonPropertyName("psk")]
        public string Psk { get; set; } = "";

        [JsonPropertyName("psk_nonce")]
        public string PskNonce { get; set; } = "";
    }

    [Fact]
    public void PskSecret_ZeroPsks_ReturnsAllZeros()
    {
        // RFC 9420 §8.4: When there are no PSKs, psk_secret is zeros(KDF.Nh)
        var cs = new CipherSuite0x0001();
        var result = PskSecretDerivation.ComputePskSecret(cs, Array.Empty<PskSecretDerivation.PskInput>());
        Assert.Equal(new byte[cs.SecretSize], result);
    }

    public static IEnumerable<object[]> PskSecretVectors()
    {
        var vectors = JsonSerializer.Deserialize<PskSecretVector[]>(
            File.ReadAllText(VectorPath("psk_secret.json")), JsonOpts)!;
        foreach (var v in vectors.Where(x => x.CipherSuite == 1))
            yield return new object[] { v };
    }

    [Theory]
    [MemberData(nameof(PskSecretVectors))]
    public void PskSecret_MatchesOfficialVectors(PskSecretVector v)
    {
        var cs = new CipherSuite0x0001();

        // Build PSK inputs from the test vector
        var pskInputs = v.Psks.Select(p => new PskSecretDerivation.PskInput
        {
            Id = new PreSharedKeyId
            {
                PskType = PskType.External,
                PskId = Hex(p.PskId),
                PskNonce = Hex(p.PskNonce),
            },
            PskValue = Hex(p.Psk),
        }).ToArray();

        var expected = Hex(v.PskSecret);
        var actual = PskSecretDerivation.ComputePskSecret(cs, pskInputs);

        Assert.Equal(expected, actual);
    }

    // ================================================================
    // Sender Data Key Derivation — Production Code Path (Bug Regression)
    // ================================================================

    /// <summary>
    /// Validates that the production MessageFraming.DeriveSenderDataKey/Nonce
    /// (which call GetCiphertextSample internally) produce the same results as
    /// the test vector. This catches Bug 1 where GetCiphertextSample used
    /// AeadKeySize (Nk=16) instead of HashSize (Nh=32).
    /// </summary>
    [Fact]
    public void SenderDataKey_ProductionCodePath_MatchesOfficialVectors()
    {
        var vectors = JsonSerializer.Deserialize<SecretTreeVector[]>(
            File.ReadAllText(VectorPath("secret-tree.json")), JsonOpts)!;

        var v = vectors.First(x => x.CipherSuite == 1);
        var cs = new CipherSuite0x0001();

        byte[] senderDataSecret = Hex(v.SenderData.SenderDataSecret);
        byte[] ciphertext = Hex(v.SenderData.Ciphertext);

        // Call the PRODUCTION code path (not manual inline computation)
        byte[] key = MessageFraming.DeriveSenderDataKey(cs, senderDataSecret, ciphertext);
        byte[] nonce = MessageFraming.DeriveSenderDataNonce(cs, senderDataSecret, ciphertext);

        Assert.Equal(Hex(v.SenderData.Key), key);
        Assert.Equal(Hex(v.SenderData.Nonce), nonce);
    }

    /// <summary>
    /// Validates that GetCiphertextSample takes min(Nh, len(ciphertext)) bytes,
    /// not min(Nk, len(ciphertext)). For CipherSuite 1 (AES-128-GCM + SHA-256):
    /// Nh=32, Nk=16. With ciphertext longer than 32 bytes, the sample must be 32 bytes.
    /// </summary>
    [Fact]
    public void GetCiphertextSample_UsesHashSize_NotAeadKeySize()
    {
        var cs = new CipherSuite0x0001();
        // Nh=32, Nk=16 for CipherSuite 1
        Assert.Equal(32, cs.HashSize);
        Assert.Equal(16, cs.AeadKeySize);

        // Ciphertext longer than both Nh and Nk
        var ciphertext = new byte[64];
        for (int i = 0; i < ciphertext.Length; i++) ciphertext[i] = (byte)i;

        byte[] sample = MessageFraming.GetCiphertextSample(cs, ciphertext);

        // Must be Nh=32 bytes, not Nk=16
        Assert.Equal(cs.HashSize, sample.Length);
        Assert.Equal(ciphertext[..32], sample);
    }

    // ================================================================
    // Message Protection Test Vectors (RFC 9420 Section 13.3)
    // ================================================================

    public class MessageProtectionVector
    {
        [JsonPropertyName("cipher_suite")]
        public int CipherSuite { get; set; }

        [JsonPropertyName("group_id")]
        public string GroupId { get; set; } = "";

        [JsonPropertyName("epoch")]
        public ulong Epoch { get; set; }

        [JsonPropertyName("tree_hash")]
        public string TreeHash { get; set; } = "";

        [JsonPropertyName("confirmed_transcript_hash")]
        public string ConfirmedTranscriptHash { get; set; } = "";

        [JsonPropertyName("signature_priv")]
        public string SignaturePriv { get; set; } = "";

        [JsonPropertyName("signature_pub")]
        public string SignaturePub { get; set; } = "";

        [JsonPropertyName("encryption_secret")]
        public string EncryptionSecret { get; set; } = "";

        [JsonPropertyName("sender_data_secret")]
        public string SenderDataSecret { get; set; } = "";

        [JsonPropertyName("membership_key")]
        public string MembershipKey { get; set; } = "";

        [JsonPropertyName("proposal")]
        public string Proposal { get; set; } = "";

        [JsonPropertyName("proposal_priv")]
        public string ProposalPriv { get; set; } = "";

        [JsonPropertyName("proposal_pub")]
        public string ProposalPub { get; set; } = "";

        [JsonPropertyName("commit")]
        public string Commit { get; set; } = "";

        [JsonPropertyName("commit_priv")]
        public string CommitPriv { get; set; } = "";

        [JsonPropertyName("commit_pub")]
        public string CommitPub { get; set; } = "";

        [JsonPropertyName("application")]
        public string Application { get; set; } = "";

        [JsonPropertyName("application_priv")]
        public string ApplicationPriv { get; set; } = "";
    }

    private static readonly Lazy<MessageProtectionVector> MsgProtVec = new(() =>
    {
        var vectors = JsonSerializer.Deserialize<MessageProtectionVector[]>(
            File.ReadAllText(VectorPath("message-protection.json")), JsonOpts)!;
        return vectors.First(x => x.CipherSuite == 1);
    });

    private static byte[] MsgProtGroupContext(MessageProtectionVector v)
    {
        var groupContext = new GroupContext
        {
            Version = ProtocolVersion.Mls10,
            CipherSuite = (ushort)v.CipherSuite,
            GroupId = Hex(v.GroupId),
            Epoch = v.Epoch,
            TreeHash = Hex(v.TreeHash),
            ConfirmedTranscriptHash = Hex(v.ConfirmedTranscriptHash),
            Extensions = Array.Empty<Extension>()
        };
        return TlsCodec.Serialize(w => groupContext.WriteTo(w));
    }

    public static IEnumerable<object[]> PrivateMessageCases()
    {
        yield return new object[] { "Application", ContentType.Application };
        yield return new object[] { "Proposal", ContentType.Proposal };
        yield return new object[] { "Commit", ContentType.Commit };
    }

    [Theory]
    [MemberData(nameof(PrivateMessageCases))]
    public void MessageProtection_DecryptPrivateMessage_MatchesOfficialVectors(
        string label, ContentType expectedType)
    {
        var v = MsgProtVec.Value;
        var cs = new CipherSuite0x0001();

        string privHex = label switch
        {
            "Application" => v.ApplicationPriv,
            "Proposal" => v.ProposalPriv,
            "Commit" => v.CommitPriv,
            _ => throw new ArgumentException(label)
        };
        byte[] expectedPlaintext = Hex(label switch
        {
            "Application" => v.Application,
            "Proposal" => v.Proposal,
            "Commit" => v.Commit,
            _ => throw new ArgumentException(label)
        });

        var mlsMsg = MlsMessage.ReadFrom(new TlsReader(Hex(privHex)));
        Assert.Equal(WireFormat.MlsPrivateMessage, mlsMsg.WireFormat);
        var privateMsg = (PrivateMessage)mlsMsg.Body;
        Assert.Equal(expectedType, privateMsg.ContentType);

        var secretTree = new SecretTree(cs, Hex(v.EncryptionSecret), 2);
        var (content, auth) = MessageFraming.DecryptPrivateMessage(
            privateMsg, cs, secretTree, Hex(v.SenderDataSecret));

        Assert.Equal(expectedPlaintext, content.Content);
        Assert.Equal(expectedType, content.ContentType);
        Assert.Equal(Hex(v.GroupId), content.GroupId);
        Assert.Equal(v.Epoch, content.Epoch);

        byte[] serializedGroupContext = MsgProtGroupContext(v);
        bool sigValid = MessageFraming.VerifyPrivateMessageSignature(
            content, auth, Hex(v.SignaturePub), serializedGroupContext, cs);
        Assert.True(sigValid, $"Signature verification failed on {label} PrivateMessage");
    }

    public static IEnumerable<object[]> PublicMessageCases()
    {
        yield return new object[] { "Proposal", ContentType.Proposal };
        yield return new object[] { "Commit", ContentType.Commit };
    }

    [Theory]
    [MemberData(nameof(PublicMessageCases))]
    public void MessageProtection_VerifyPublicMessage_MatchesOfficialVectors(
        string label, ContentType expectedType)
    {
        var v = MsgProtVec.Value;
        var cs = new CipherSuite0x0001();

        string pubHex = label switch
        {
            "Proposal" => v.ProposalPub,
            "Commit" => v.CommitPub,
            _ => throw new ArgumentException(label)
        };
        byte[] expectedPlaintext = Hex(label switch
        {
            "Proposal" => v.Proposal,
            "Commit" => v.Commit,
            _ => throw new ArgumentException(label)
        });

        var mlsMsg = MlsMessage.ReadFrom(new TlsReader(Hex(pubHex)));
        Assert.Equal(WireFormat.MlsPublicMessage, mlsMsg.WireFormat);
        var publicMsg = (PublicMessage)mlsMsg.Body;

        Assert.Equal(expectedType, publicMsg.Content.ContentType);
        Assert.Equal(Hex(v.GroupId), publicMsg.Content.GroupId);
        Assert.Equal(v.Epoch, publicMsg.Content.Epoch);
        Assert.Equal(expectedPlaintext, publicMsg.Content.Content);

        byte[] serializedGroupContext = MsgProtGroupContext(v);
        bool valid = MessageFraming.VerifyPublicMessage(
            publicMsg, Hex(v.SignaturePub), serializedGroupContext, cs, Hex(v.MembershipKey));
        Assert.True(valid, $"PublicMessage {label} signature + membership tag verification failed");
    }

    // ================================================================
    // Welcome Test Vectors (RFC 9420 Section 13.7)
    // ================================================================

    public class WelcomeVector
    {
        [JsonPropertyName("cipher_suite")]
        public int CipherSuite { get; set; }

        [JsonPropertyName("init_priv")]
        public string InitPriv { get; set; } = "";

        [JsonPropertyName("key_package")]
        public string KeyPackage { get; set; } = "";

        [JsonPropertyName("signer_pub")]
        public string SignerPub { get; set; } = "";

        [JsonPropertyName("welcome")]
        public string Welcome { get; set; } = "";
    }

    /// <summary>
    /// Processes a Welcome message from official test vectors:
    /// parses KeyPackage, finds matching EncryptedGroupSecrets,
    /// HPKE-decrypts GroupSecrets, derives welcome key/nonce,
    /// decrypts GroupInfo, and verifies the GroupInfo signature.
    /// </summary>
    [Fact]
    public void Welcome_ProcessWelcome_MatchesOfficialVectors()
    {
        var vectors = JsonSerializer.Deserialize<WelcomeVector[]>(
            File.ReadAllText(VectorPath("welcome.json")), JsonOpts)!;

        var v = vectors.First(x => x.CipherSuite == 1);
        var cs = new CipherSuite0x0001();

        // Parse the MLSMessage-wrapped KeyPackage
        var kpMsg = MlsMessage.ReadFrom(new TlsReader(Hex(v.KeyPackage)));
        Assert.Equal(WireFormat.MlsKeyPackage, kpMsg.WireFormat);
        var keyPackage = (KeyPackage)kpMsg.Body;

        // Parse the MLSMessage-wrapped Welcome
        var welcomeMsg = MlsMessage.ReadFrom(new TlsReader(Hex(v.Welcome)));
        Assert.Equal(WireFormat.MlsWelcome, welcomeMsg.WireFormat);
        var welcome = (Welcome)welcomeMsg.Body;

        Assert.Equal(1, welcome.CipherSuite);

        // Compute KeyPackageRef and find our EncryptedGroupSecrets
        byte[] kpBytes = TlsCodec.Serialize(w => keyPackage.WriteTo(w));
        var kpRef = KeyPackageRef.Compute(cs, kpBytes);

        EncryptedGroupSecrets? mySecrets = null;
        foreach (var egs in welcome.Secrets)
        {
            if (egs.NewMember.AsSpan().SequenceEqual(kpRef.Value))
            {
                mySecrets = egs;
                break;
            }
        }
        Assert.NotNull(mySecrets);

        // HPKE decrypt GroupSecrets using init private key
        byte[] hpkeInfo = TlsCodec.Serialize(w =>
        {
            byte[] fullLabel = System.Text.Encoding.ASCII.GetBytes("MLS 1.0 Welcome");
            w.WriteOpaqueV(fullLabel);
            w.WriteOpaqueV(welcome.EncryptedGroupInfo);
        });

        byte[] groupSecretsBytes = cs.HpkeOpen(
            Hex(v.InitPriv),
            mySecrets.EncryptedGroupSecretsValue.KemOutput,
            hpkeInfo,
            Array.Empty<byte>(),
            mySecrets.EncryptedGroupSecretsValue.Ciphertext);

        var groupSecrets = GroupSecrets.ReadFrom(new TlsReader(groupSecretsBytes));
        Assert.NotNull(groupSecrets.JoinerSecret);
        Assert.True(groupSecrets.JoinerSecret.Length > 0);

        // Derive welcome_secret and decrypt GroupInfo
        byte[] pskSecret = new byte[cs.SecretSize]; // zeros when no PSKs
        byte[] intermediateSecret = cs.Extract(groupSecrets.JoinerSecret, pskSecret);
        byte[] welcomeSecret = cs.DeriveSecret(intermediateSecret, "welcome");
        byte[] welcomeKey = cs.ExpandWithLabel(
            welcomeSecret, "key", Array.Empty<byte>(), cs.AeadKeySize);
        byte[] welcomeNonce = cs.ExpandWithLabel(
            welcomeSecret, "nonce", Array.Empty<byte>(), cs.AeadNonceSize);

        byte[] groupInfoBytes = cs.AeadDecrypt(
            welcomeKey, welcomeNonce, Array.Empty<byte>(), welcome.EncryptedGroupInfo);

        var groupInfo = GroupInfo.ReadFrom(new TlsReader(groupInfoBytes));

        // Verify GroupInfo fields
        Assert.Equal(ProtocolVersion.Mls10, groupInfo.GroupContext.Version);
        Assert.Equal((ushort)1, groupInfo.GroupContext.CipherSuite);

        // Verify the GroupInfo signature using the signer's public key
        byte[] groupInfoTbs = TlsCodec.Serialize(w =>
        {
            // GroupInfoTBS = GroupContext || extensions || confirmation_tag
            groupInfo.GroupContext.WriteTo(w);
            w.WriteVectorV(inner =>
            {
                foreach (var ext in groupInfo.Extensions)
                    ext.WriteTo(inner);
            });
            w.WriteOpaqueV(groupInfo.ConfirmationTag);
            w.WriteUint32(groupInfo.Signer);
        });

        bool sigValid = cs.VerifyWithLabel(
            Hex(v.SignerPub), "GroupInfoTBS", groupInfoTbs, groupInfo.Signature);
        Assert.True(sigValid, "GroupInfo signature verification failed");
    }

    // ================================================================
    // Messages Test Vectors (RFC 9420 Section 13.10)
    // ================================================================

    public class MessagesVector
    {
        [JsonPropertyName("mls_welcome")]
        public string MlsWelcome { get; set; } = "";

        [JsonPropertyName("mls_group_info")]
        public string MlsGroupInfo { get; set; } = "";

        [JsonPropertyName("mls_key_package")]
        public string MlsKeyPackage { get; set; } = "";

        [JsonPropertyName("ratchet_tree")]
        public string RatchetTree { get; set; } = "";

        [JsonPropertyName("group_secrets")]
        public string GroupSecrets { get; set; } = "";

        [JsonPropertyName("add_proposal")]
        public string AddProposal { get; set; } = "";

        [JsonPropertyName("update_proposal")]
        public string UpdateProposal { get; set; } = "";

        [JsonPropertyName("remove_proposal")]
        public string RemoveProposal { get; set; } = "";

        [JsonPropertyName("pre_shared_key_proposal")]
        public string PreSharedKeyProposal { get; set; } = "";

        [JsonPropertyName("re_init_proposal")]
        public string ReInitProposal { get; set; } = "";

        [JsonPropertyName("external_init_proposal")]
        public string ExternalInitProposal { get; set; } = "";

        [JsonPropertyName("group_context_extensions_proposal")]
        public string GroupContextExtensionsProposal { get; set; } = "";

        [JsonPropertyName("commit")]
        public string CommitMsg { get; set; } = "";

        [JsonPropertyName("public_message_application")]
        public string PublicMessageApplication { get; set; } = "";

        [JsonPropertyName("public_message_proposal")]
        public string PublicMessageProposal { get; set; } = "";

        [JsonPropertyName("public_message_commit")]
        public string PublicMessageCommit { get; set; } = "";

        [JsonPropertyName("private_message")]
        public string PrivateMessage { get; set; } = "";
    }

    /// <summary>
    /// Round-trip test for MLSMessage-wrapped types: deserialize then re-serialize
    /// and verify the bytes match exactly.
    /// </summary>
    [Fact]
    public void Messages_MlsMessageRoundTrip_MatchesOfficialVectors()
    {
        var vectors = JsonSerializer.Deserialize<MessagesVector[]>(
            File.ReadAllText(VectorPath("messages.json")), JsonOpts)!;

        // Test the first entry
        var v = vectors[0];

        // MLSMessage-wrapped Welcome
        AssertMlsMessageRoundTrip(v.MlsWelcome, "mls_welcome");

        // MLSMessage-wrapped GroupInfo
        AssertMlsMessageRoundTrip(v.MlsGroupInfo, "mls_group_info");

        // MLSMessage-wrapped KeyPackage
        AssertMlsMessageRoundTrip(v.MlsKeyPackage, "mls_key_package");

        // MLSMessage-wrapped PublicMessage (application)
        AssertMlsMessageRoundTrip(v.PublicMessageApplication, "public_message_application");

        // MLSMessage-wrapped PublicMessage (proposal)
        AssertMlsMessageRoundTrip(v.PublicMessageProposal, "public_message_proposal");

        // MLSMessage-wrapped PublicMessage (commit)
        AssertMlsMessageRoundTrip(v.PublicMessageCommit, "public_message_commit");

        // MLSMessage-wrapped PrivateMessage
        AssertMlsMessageRoundTrip(v.PrivateMessage, "private_message");
    }

    private static void AssertMlsMessageRoundTrip(string hex, string label)
    {
        byte[] original = Hex(hex);
        var msg = MlsMessage.ReadFrom(new TlsReader(original));
        byte[] reserialized = TlsCodec.Serialize(w => msg.WriteTo(w));
        Assert.True(original.SequenceEqual(reserialized),
            $"Round-trip mismatch for {label}: " +
            $"expected {original.Length} bytes, got {reserialized.Length} bytes");
    }

    /// <summary>
    /// Round-trip test for raw (non-MLSMessage-wrapped) types:
    /// GroupSecrets, RatchetTree, Proposals, Commit.
    /// Proposals in messages.json are body-only (no type tag).
    /// </summary>
    [Fact]
    public void Messages_RawTypeRoundTrip_MatchesOfficialVectors()
    {
        var vectors = JsonSerializer.Deserialize<MessagesVector[]>(
            File.ReadAllText(VectorPath("messages.json")), JsonOpts)!;

        var v = vectors[0];

        // GroupSecrets
        {
            byte[] original = Hex(v.GroupSecrets);
            var gs = Types.GroupSecrets.ReadFrom(new TlsReader(original));
            byte[] reserialized = TlsCodec.Serialize(w => gs.WriteTo(w));
            Assert.Equal(original, reserialized);
        }

        // RatchetTree (VarInt-prefixed opaque vector)
        {
            byte[] original = Hex(v.RatchetTree);
            var tree = Tree.RatchetTree.ReadFrom(new TlsReader(original));
            byte[] reserialized = TlsCodec.Serialize(w => tree.WriteTo(w));
            Assert.True(original.SequenceEqual(reserialized),
                $"Round-trip mismatch for ratchet_tree");
        }

        // Proposals — body only (no type tag), so we prepend the type tag
        // for ReadFrom, then compare the full output including type tag
        AssertProposalBodyRoundTrip(v.AddProposal, ProposalType.Add, "add_proposal");
        AssertProposalBodyRoundTrip(v.UpdateProposal, ProposalType.Update, "update_proposal");
        AssertProposalBodyRoundTrip(v.RemoveProposal, ProposalType.Remove, "remove_proposal");
        AssertProposalBodyRoundTrip(v.PreSharedKeyProposal, ProposalType.PreSharedKey, "pre_shared_key_proposal");
        AssertProposalBodyRoundTrip(v.ReInitProposal, ProposalType.ReInit, "re_init_proposal");
        AssertProposalBodyRoundTrip(v.ExternalInitProposal, ProposalType.ExternalInit, "external_init_proposal");
        AssertProposalBodyRoundTrip(v.GroupContextExtensionsProposal, ProposalType.GroupContextExtensions, "group_context_extensions_proposal");

        // Commit
        {
            byte[] original = Hex(v.CommitMsg);
            var commit = Types.Commit.ReadFrom(new TlsReader(original));
            byte[] reserialized = TlsCodec.Serialize(w => commit.WriteTo(w));
            Assert.Equal(original, reserialized);
        }
    }

    /// <summary>


    private static byte[] Concat(byte[] a, byte[] b, byte[] c)
    {
        var result = new byte[a.Length + b.Length + c.Length];
        Buffer.BlockCopy(a, 0, result, 0, a.Length);
        Buffer.BlockCopy(b, 0, result, a.Length, b.Length);
        Buffer.BlockCopy(c, 0, result, a.Length + b.Length, c.Length);
        return result;
    }

    private static void AssertProposalBodyRoundTrip(string bodyHex, ProposalType type, string label)
    {
        byte[] bodyOriginal = Hex(bodyHex);

        // Prepend the 2-byte type tag so Proposal.ReadFrom can parse it
        byte[] withTag = new byte[2 + bodyOriginal.Length];
        withTag[0] = (byte)((ushort)type >> 8);
        withTag[1] = (byte)((ushort)type & 0xFF);
        Buffer.BlockCopy(bodyOriginal, 0, withTag, 2, bodyOriginal.Length);

        var proposal = Types.Proposal.ReadFrom(new TlsReader(withTag));
        byte[] reserialized = TlsCodec.Serialize(w => proposal.WriteTo(w));

        Assert.True(withTag.SequenceEqual(reserialized),
            $"Round-trip mismatch for {label}: " +
            $"expected {Convert.ToHexString(withTag)}, got {Convert.ToHexString(reserialized)}");
    }

    // ================================================================
    // Tree Validation Test Vectors (RFC 9420 Section 13.6)
    // ================================================================

    public class TreeValidationVector
    {
        [JsonPropertyName("cipher_suite")]
        public int CipherSuite { get; set; }

        [JsonPropertyName("tree")]
        public string TreeData { get; set; } = "";

        [JsonPropertyName("group_id")]
        public string GroupId { get; set; } = "";

        [JsonPropertyName("tree_hashes")]
        public string[] TreeHashes { get; set; } = Array.Empty<string>();

        [JsonPropertyName("resolutions")]
        public uint[][] Resolutions { get; set; } = Array.Empty<uint[]>();
    }

    /// <summary>
    /// Original combined tree-validation test. Kept for backward compatibility
    /// while the individual Theory tests above provide better isolation.
    /// TODO: Remove once Theory tests are confirmed stable.
    /// </summary>
    [Fact]
    public void TreeValidation_TreeHash_MatchesOfficialVectors()
    {
        var vectors = JsonSerializer.Deserialize<TreeValidationVector[]>(
            File.ReadAllText(VectorPath("tree-validation.json")), JsonOpts)!;

        var v = vectors.First(x => x.CipherSuite == 1);
        var cs = new CipherSuite0x0001();

        var tree = Tree.RatchetTree.ReadFrom(new TlsReader(Hex(v.TreeData)));

        byte[] reserialized = TlsCodec.Serialize(w => tree.WriteTo(w));
        Assert.Equal(Hex(v.TreeData), reserialized);

        for (int i = 0; i < v.TreeHashes.Length; i++)
        {
            byte[] expected = Hex(v.TreeHashes[i]);
            byte[] actual = tree.ComputeTreeHash(cs, (uint)i);
            Assert.True(expected.SequenceEqual(actual),
                $"Tree hash mismatch at node {i}");
        }

        for (int i = 0; i < v.Resolutions.Length; i++)
        {
            var expected = v.Resolutions[i];
            var actual = tree.Resolution((uint)i);
            Assert.Equal(expected, actual.ToArray());
        }
    }

    public static IEnumerable<object[]> TreeValidationVectors()
    {
        var vectors = JsonSerializer.Deserialize<TreeValidationVector[]>(
            File.ReadAllText(VectorPath("tree-validation.json")), JsonOpts)!;
        foreach (var v in vectors.Where(x => x.CipherSuite == 1))
            yield return new object[] { v };
    }

    private static (Tree.RatchetTree tree, ICipherSuite cs) ParseTreeVector(TreeValidationVector v)
    {
        var cs = new CipherSuite0x0001();
        var tree = Tree.RatchetTree.ReadFrom(new TlsReader(Hex(v.TreeData)));
        return (tree, cs);
    }

    /// <summary>
    /// RFC 9420 §13.6 Check 1: Tree serialization round-trips exactly.
    /// </summary>
    [Theory]
    [MemberData(nameof(TreeValidationVectors))]
    public void TreeValidation_Serialization_RoundTrips(TreeValidationVector v)
    {
        var (tree, _) = ParseTreeVector(v);
        byte[] reserialized = TlsCodec.Serialize(w => tree.WriteTo(w));
        Assert.Equal(Hex(v.TreeData), reserialized);
    }

    /// <summary>
    /// RFC 9420 §13.6 Check 2: Tree hash at each node matches the expected value.
    /// </summary>
    [Theory]
    [MemberData(nameof(TreeValidationVectors))]
    public void TreeValidation_TreeHashes_MatchExpected(TreeValidationVector v)
    {
        var (tree, cs) = ParseTreeVector(v);
        for (int i = 0; i < v.TreeHashes.Length; i++)
        {
            byte[] expected = Hex(v.TreeHashes[i]);
            byte[] actual = tree.ComputeTreeHash(cs, (uint)i);
            Assert.True(expected.SequenceEqual(actual),
                $"Tree hash mismatch at node {i}: " +
                $"expected {v.TreeHashes[i][..16]}..., got {Convert.ToHexString(actual)[..16]}...");
        }
    }

    /// <summary>
    /// RFC 9420 §13.6 Check 3: Resolution of each node matches the expected value.
    /// </summary>
    [Theory]
    [MemberData(nameof(TreeValidationVectors))]
    public void TreeValidation_Resolutions_MatchExpected(TreeValidationVector v)
    {
        var (tree, _) = ParseTreeVector(v);
        for (int i = 0; i < v.Resolutions.Length; i++)
        {
            var expected = v.Resolutions[i];
            var actual = tree.Resolution((uint)i);
            Assert.Equal(expected, actual.ToArray());
        }
    }

    /// <summary>
    /// RFC 9420 §13.6 Check 4: Leaf node signatures verify using group_id as context.
    /// LeafNodeTBS for Update/Commit sources includes group_id + leaf_index (RFC 9420 §7.2).
    /// </summary>
    [Theory]
    [MemberData(nameof(TreeValidationVectors))]
    public void TreeValidation_LeafSignatures_Verify(TreeValidationVector v)
    {
        var (tree, cs) = ParseTreeVector(v);
        var groupId = Hex(v.GroupId);

        int leafCount = (int)tree.LeafCount;
        int verifiedCount = 0;
        for (uint leafIdx = 0; leafIdx < leafCount; leafIdx++)
        {
            var leaf = tree.GetLeaf(leafIdx);
            if (leaf == null) continue;

            byte[] tbs = BuildLeafNodeTbs(leaf, groupId, leafIdx);
            bool valid = cs.VerifyWithLabel(leaf.SignatureKey, "LeafNodeTBS", tbs, leaf.Signature);
            Assert.True(valid,
                $"Leaf signature failed at leaf {leafIdx} " +
                $"(source={leaf.Source}, sigKey={Convert.ToHexString(leaf.SignatureKey)[..16]}...)");

            verifiedCount++;
        }

        Assert.True(verifiedCount > 0, "No leaf nodes found to verify");
    }

    /// <summary>
    /// Builds the LeafNodeTBS per RFC 9420 §7.2. Shared by tree-validation and
    /// leaf-signature tests.
    /// </summary>
    private static byte[] BuildLeafNodeTbs(LeafNode leaf, byte[] groupId, uint leafIndex)
    {
        return TlsCodec.Serialize(writer =>
        {
            writer.WriteOpaqueV(leaf.EncryptionKey);
            writer.WriteOpaqueV(leaf.SignatureKey);
            leaf.Credential.WriteTo(writer);
            leaf.Capabilities.WriteTo(writer);
            writer.WriteUint8((byte)leaf.Source);

            switch (leaf.Source)
            {
                case LeafNodeSource.KeyPackage:
                    if (leaf.Lifetime != null)
                        leaf.Lifetime.WriteTo(writer);
                    break;
                case LeafNodeSource.Commit:
                    writer.WriteOpaqueV(leaf.ParentHash);
                    break;
            }

            writer.WriteVectorV(inner =>
            {
                foreach (var ext in leaf.Extensions)
                    ext.WriteTo(inner);
            });

            if (leaf.Source == LeafNodeSource.Update ||
                leaf.Source == LeafNodeSource.Commit)
            {
                writer.WriteOpaqueV(groupId);
                writer.WriteUint32(leafIndex);
            }
        });
    }

    // ================================================================
    // Tree Operations Test Vectors (RFC 9420 Section 13.8)
    // ================================================================

    public class TreeOperationsVector
    {
        [JsonPropertyName("cipher_suite")]
        public int CipherSuite { get; set; }

        [JsonPropertyName("proposal")]
        public string Proposal { get; set; } = "";

        [JsonPropertyName("proposal_sender")]
        public uint ProposalSender { get; set; }

        [JsonPropertyName("tree_before")]
        public string TreeBefore { get; set; } = "";

        [JsonPropertyName("tree_after")]
        public string TreeAfter { get; set; } = "";

        [JsonPropertyName("tree_hash_before")]
        public string TreeHashBefore { get; set; } = "";

        [JsonPropertyName("tree_hash_after")]
        public string TreeHashAfter { get; set; } = "";
    }

    public static IEnumerable<object[]> TreeOperationsVectors()
    {
        var vectors = JsonSerializer.Deserialize<TreeOperationsVector[]>(
            File.ReadAllText(VectorPath("tree-operations.json")), JsonOpts)!;
        foreach (var v in vectors.Where(x => x.CipherSuite == 1))
            yield return new object[] { v };
    }

    /// <summary>
    /// Validates tree operations: parse tree, verify tree hash, apply proposal,
    /// verify resulting tree hash matches expected value.
    /// </summary>
    [Theory]
    [MemberData(nameof(TreeOperationsVectors))]
    public void TreeOperations_MatchesOfficialVectors(TreeOperationsVector v)
    {
        var cs = new CipherSuite0x0001();

        // Parse and verify tree_before
        var treeBefore = Tree.RatchetTree.ReadFrom(new TlsReader(Hex(v.TreeBefore)));
        uint rootBefore = TreeMath.Root(treeBefore.LeafCount);
        byte[] hashBefore = treeBefore.ComputeTreeHash(cs, rootBefore);
        Assert.Equal(Hex(v.TreeHashBefore), hashBefore);

        // Parse the proposal (includes type tag)
        var proposal = Types.Proposal.ReadFrom(new TlsReader(Hex(v.Proposal)));

        // Apply the proposal to the tree
        switch (proposal)
        {
            case AddProposal addProposal:
                treeBefore.AddLeaf(addProposal.KeyPackage.LeafNode);
                break;
            case UpdateProposal updateProposal:
                treeBefore.SetLeaf(v.ProposalSender, updateProposal.LeafNode);
                // RFC 9420 §12.4.2: blank the direct path after an Update
                var directPath = TreeMath.DirectPath(v.ProposalSender, treeBefore.LeafCount);
                foreach (uint dp in directPath)
                    treeBefore.SetParent(dp, null);
                break;
            case RemoveProposal removeProposal:
                treeBefore.BlankLeaf(removeProposal.LeafIndex);
                break;
            default:
                Assert.Fail($"Unexpected proposal type: {proposal.ProposalType}");
                break;
        }

        // Verify tree_after hash
        uint rootAfter = TreeMath.Root(treeBefore.LeafCount);
        byte[] hashAfter = treeBefore.ComputeTreeHash(cs, rootAfter);
        Assert.Equal(Hex(v.TreeHashAfter), hashAfter);

        // Also verify the expected tree_after deserializes to the same hash
        var treeAfter = Tree.RatchetTree.ReadFrom(new TlsReader(Hex(v.TreeAfter)));
        uint rootExpected = TreeMath.Root(treeAfter.LeafCount);
        byte[] hashExpected = treeAfter.ComputeTreeHash(cs, rootExpected);
        Assert.Equal(Hex(v.TreeHashAfter), hashExpected);
    }

    // ================================================================
    // TreeKEM Test Vectors (RFC 9420 Section 13.9)
    // ================================================================

    public class TreeKemVector
    {
        [JsonPropertyName("cipher_suite")]
        public int CipherSuite { get; set; }

        [JsonPropertyName("group_id")]
        public string GroupId { get; set; } = "";

        [JsonPropertyName("epoch")]
        public ulong Epoch { get; set; }

        [JsonPropertyName("confirmed_transcript_hash")]
        public string ConfirmedTranscriptHash { get; set; } = "";

        [JsonPropertyName("ratchet_tree")]
        public string RatchetTree { get; set; } = "";

        [JsonPropertyName("leaves_private")]
        public TreeKemLeafPrivate[] LeavesPrivate { get; set; } = Array.Empty<TreeKemLeafPrivate>();

        [JsonPropertyName("update_paths")]
        public TreeKemUpdatePath[] UpdatePaths { get; set; } = Array.Empty<TreeKemUpdatePath>();
    }

    public class TreeKemLeafPrivate
    {
        [JsonPropertyName("index")]
        public uint Index { get; set; }

        [JsonPropertyName("encryption_priv")]
        public string EncryptionPriv { get; set; } = "";

        [JsonPropertyName("signature_priv")]
        public string SignaturePriv { get; set; } = "";

        [JsonPropertyName("path_secrets")]
        public TreeKemPathSecret[] PathSecrets { get; set; } = Array.Empty<TreeKemPathSecret>();
    }

    public class TreeKemPathSecret
    {
        [JsonPropertyName("node")]
        public uint Node { get; set; }

        [JsonPropertyName("path_secret")]
        public string PathSecret { get; set; } = "";
    }

    public class TreeKemUpdatePath
    {
        [JsonPropertyName("sender")]
        public uint Sender { get; set; }

        [JsonPropertyName("update_path")]
        public string UpdatePathData { get; set; } = "";

        [JsonPropertyName("path_secrets")]
        public string?[] PathSecrets { get; set; } = Array.Empty<string?>();

        [JsonPropertyName("commit_secret")]
        public string CommitSecret { get; set; } = "";

        [JsonPropertyName("tree_hash_after")]
        public string TreeHashAfter { get; set; } = "";
    }

    public static IEnumerable<object[]> TreeKemVectors()
    {
        var vectors = JsonSerializer.Deserialize<TreeKemVector[]>(
            File.ReadAllText(VectorPath("treekem.json")), JsonOpts)!;
        foreach (var v in vectors.Where(x => x.CipherSuite == 1))
            yield return new object[] { v };
    }

    [Theory]
    [MemberData(nameof(TreeKemVectors))]
    public void TreeKem_MatchesOfficialVectors(TreeKemVector v)
    {
        var cs = new CipherSuite0x0001();
        var tree = Tree.RatchetTree.ReadFrom(new TlsReader(Hex(v.RatchetTree)));

        foreach (var up in v.UpdatePaths)
        {
            // Parse UpdatePath
            var updatePath = Types.UpdatePath.ReadFrom(new TlsReader(Hex(up.UpdatePathData)));

            // Verify UpdatePath round-trip
            byte[] reser = TlsCodec.Serialize(w => updatePath.WriteTo(w));
            Assert.Equal(Hex(up.UpdatePathData), reser);

            // Build provisional tree: apply UpdatePath public keys to get tree_hash_after
            // RFC 9420 §12.4.2: the GroupContext for HPKE uses the provisional tree hash
            var provisionalTree = tree.Clone();
            provisionalTree.SetLeaf(up.Sender, updatePath.LeafNode);
            var senderDp = TreeMath.DirectPath(up.Sender, provisionalTree.LeafCount);
            var senderCopath = TreeMath.Copath(up.Sender, provisionalTree.LeafCount);
            foreach (uint n in senderDp)
                provisionalTree.SetParent(n, null);

            // Build filtered direct path: exclude nodes whose copath child has empty resolution
            // RFC 9420 §7.6: filtered direct path skips nodes with no members in copath subtree
            var filteredDp = new List<uint>();
            var filteredCopath = new List<uint>();
            for (int i = 0; i < senderDp.Length; i++)
            {
                if (tree.Resolution(senderCopath[i]).Count > 0)
                {
                    filteredDp.Add(senderDp[i]);
                    filteredCopath.Add(senderCopath[i]);
                }
            }

            for (int i = 0; i < filteredDp.Count; i++)
            {
                provisionalTree.SetParent(filteredDp[i], new ParentNode
                {
                    EncryptionKey = updatePath.Nodes[i].EncryptionKey,
                    UnmergedLeaves = new List<uint>(),
                });
            }

            // Compute parent_hash for each filtered direct path node (RFC 9420 §7.9)
            // parent_hash references the next node on the filtered DP, not the tree parent.
            // Sibling is the child of the filtered DP parent on the opposite side.
            for (int i = filteredDp.Count - 2; i >= 0; i--)
            {
                uint nodeIdx = filteredDp[i];
                uint parentIdx = filteredDp[i + 1];
                // Sibling relative to filtered DP parent (child of parentIdx on opposite side)
                uint siblingIdx = nodeIdx < parentIdx
                    ? TreeMath.Right(parentIdx)
                    : TreeMath.Left(parentIdx);
                byte[] siblingTreeHash = tree.ComputeTreeHash(cs, siblingIdx);
                byte[] parentHash = provisionalTree.ComputeParentHash(cs, parentIdx, siblingTreeHash);
                var pn = provisionalTree.GetParent(nodeIdx)!;
                pn.ParentHash = parentHash;
            }

            uint root = TreeMath.Root(provisionalTree.LeafCount);
            byte[] provisionalTreeHash = provisionalTree.ComputeTreeHash(cs, root);

            // Build GroupContext with provisional tree hash
            var groupCtx = new GroupContext
            {
                Version = ProtocolVersion.Mls10,
                CipherSuite = (ushort)v.CipherSuite,
                GroupId = Hex(v.GroupId),
                Epoch = v.Epoch,
                TreeHash = provisionalTreeHash,
                ConfirmedTranscriptHash = Hex(v.ConfirmedTranscriptHash),
            };
            byte[] groupCtxBytes = TlsCodec.Serialize(w => groupCtx.WriteTo(w));

            // Verify provisional tree hash matches expected
            Assert.Equal(Hex(up.TreeHashAfter), provisionalTreeHash);

            // Build EncryptWithLabel context for HPKE (RFC 9420 §5.1.3)
            byte[] encryptContext = TlsCodec.Serialize(w =>
            {
                w.WriteOpaqueV(System.Text.Encoding.UTF8.GetBytes("MLS 1.0 UpdatePathNode"));
                w.WriteOpaqueV(groupCtxBytes);
            });

            foreach (var leafPriv in v.LeavesPrivate)
            {
                if (leafPriv.Index == up.Sender)
                    continue;
                if (leafPriv.Index >= (uint)up.PathSecrets.Length)
                    continue;
                if (up.PathSecrets[leafPriv.Index] == null)
                    continue;

                byte[] expectedPathSecret = Hex(up.PathSecrets[leafPriv.Index]!);

                // Build the receiver's private key map: leaf key + parent keys from path_secrets
                var privateKeys = new Dictionary<uint, byte[]>();
                uint leafNodeIdx = TreeMath.LeafToNode(leafPriv.Index);
                privateKeys[leafNodeIdx] = Hex(leafPriv.EncryptionPriv);

                foreach (var ps in leafPriv.PathSecrets)
                {
                    byte[] nodeSecret = cs.DeriveSecret(Hex(ps.PathSecret), "node");
                    byte[] nodePriv = TreeKem.DeriveKeyPair(cs, nodeSecret).privateKey;
                    privateKeys[ps.Node] = nodePriv;
                }

                // Find which filtered copath resolution entry matches one of our keys
                int copathPos = -1;
                int resPos = -1;
                for (int i = 0; i < filteredCopath.Count; i++)
                {
                    var resolution = tree.Resolution(filteredCopath[i]);
                    for (int j = 0; j < resolution.Count; j++)
                    {
                        if (privateKeys.ContainsKey(resolution[j]))
                        {
                            copathPos = i;
                            resPos = j;
                            break;
                        }
                    }
                    if (copathPos >= 0) break;
                }

                Assert.True(copathPos >= 0,
                    $"Leaf {leafPriv.Index} not found in any filtered copath resolution for sender {up.Sender}");

                // Decrypt the path secret using HPKE
                var ct = updatePath.Nodes[copathPos].EncryptedPathSecret[resPos];
                uint resNodeIdx = tree.Resolution(filteredCopath[copathPos])[resPos];
                byte[] decrypted = cs.HpkeOpen(
                    privateKeys[resNodeIdx],
                    ct.KemOutput,
                    encryptContext,
                    Array.Empty<byte>(),
                    ct.Ciphertext);

                Assert.Equal(expectedPathSecret, decrypted);

                // Verify commit_secret by chaining DeriveSecret("path") forward
                // Chain through remaining filtered DP nodes (not full DP)
                byte[] pathSecret = decrypted;
                for (int i = copathPos + 1; i < filteredDp.Count; i++)
                    pathSecret = cs.DeriveSecret(pathSecret, "path");
                byte[] commitSecret = cs.DeriveSecret(pathSecret, "path");
                Assert.Equal(Hex(up.CommitSecret), commitSecret);
            }
        }

        // Verify signature_priv: derive Ed25519 public key and compare to leaf's SignatureKey
        foreach (var leafPriv in v.LeavesPrivate)
        {
            var leafNode = tree.GetLeaf(leafPriv.Index);
            if (leafNode == null) continue;

            var privParams = new Org.BouncyCastle.Crypto.Parameters.Ed25519PrivateKeyParameters(
                Hex(leafPriv.SignaturePriv), 0);
            byte[] derivedPub = new byte[32];
            privParams.GeneratePublicKey().Encode(derivedPub, 0);

            Assert.Equal(leafNode.SignatureKey, derivedPub);
        }
    }

    // ================================================================
    // Passive Client Test Vectors (RFC 9420 Section 13.14)
    // ================================================================

    public class PassiveClientVector
    {
        [JsonPropertyName("cipher_suite")]
        public int CipherSuite { get; set; }

        [JsonPropertyName("external_psks")]
        public PassiveClientPsk[] ExternalPsks { get; set; } = Array.Empty<PassiveClientPsk>();

        [JsonPropertyName("key_package")]
        public string KeyPackage { get; set; } = "";

        [JsonPropertyName("signature_priv")]
        public string SignaturePriv { get; set; } = "";

        [JsonPropertyName("encryption_priv")]
        public string EncryptionPriv { get; set; } = "";

        [JsonPropertyName("init_priv")]
        public string InitPriv { get; set; } = "";

        [JsonPropertyName("welcome")]
        public string Welcome { get; set; } = "";

        [JsonPropertyName("ratchet_tree")]
        public string? RatchetTree { get; set; }

        [JsonPropertyName("initial_epoch_authenticator")]
        public string InitialEpochAuthenticator { get; set; } = "";

        [JsonPropertyName("epochs")]
        public PassiveClientEpoch[] Epochs { get; set; } = Array.Empty<PassiveClientEpoch>();
    }

    public class PassiveClientPsk
    {
        [JsonPropertyName("psk_id")]
        public string PskId { get; set; } = "";

        [JsonPropertyName("psk")]
        public string Psk { get; set; } = "";
    }

    public class PassiveClientEpoch
    {
        [JsonPropertyName("proposals")]
        public string[] Proposals { get; set; } = Array.Empty<string>();

        [JsonPropertyName("commit")]
        public string Commit { get; set; } = "";

        [JsonPropertyName("epoch_authenticator")]
        public string EpochAuthenticator { get; set; } = "";
    }

    /// <summary>
    /// Processes a Welcome message using production MlsGroup.ProcessWelcome.
    /// </summary>
    private MlsGroup ProcessWelcomeForPassiveClient(
        PassiveClientVector v, ICipherSuite cs)
    {
        // Parse MLSMessage-wrapped KeyPackage
        var kpMsg = MlsMessage.ReadFrom(new TlsReader(Hex(v.KeyPackage)));
        var keyPackage = (KeyPackage)kpMsg.Body;

        // Parse MLSMessage-wrapped Welcome
        var welcomeMsg = MlsMessage.ReadFrom(new TlsReader(Hex(v.Welcome)));
        var welcome = (Welcome)welcomeMsg.Body;

        // Verify signature_priv matches the KeyPackage's public SignatureKey
        var sigPrivParams = new Org.BouncyCastle.Crypto.Parameters.Ed25519PrivateKeyParameters(
            Hex(v.SignaturePriv), 0);
        byte[] derivedSigPub = new byte[32];
        sigPrivParams.GeneratePublicKey().Encode(derivedSigPub, 0);
        Assert.Equal(keyPackage.LeafNode.SignatureKey, derivedSigPub);

        // Build external PSK map if needed
        Dictionary<string, byte[]>? externalPsks = null;
        if (v.ExternalPsks.Length > 0)
        {
            externalPsks = new Dictionary<string, byte[]>();
            foreach (var psk in v.ExternalPsks)
                externalPsks[psk.PskId.ToLowerInvariant()] = Hex(psk.Psk);
        }

        // Use production code
        return MlsGroup.ProcessWelcome(
            cs,
            welcome,
            keyPackage,
            Hex(v.InitPriv),
            Hex(v.EncryptionPriv),
            Hex(v.SignaturePriv),
            externalTree: v.RatchetTree != null ? Hex(v.RatchetTree) : null,
            externalPsks: externalPsks);
    }

    /// <summary>
    /// Processes a single epoch using production MlsGroup.CacheProposal + ProcessCommit.
    /// </summary>
    private void ProcessEpochForPassiveClient(
        MlsGroup group, PassiveClientEpoch epoch,
        PassiveClientVector v, ICipherSuite cs)
    {
        // Cache standalone proposals via production code
        foreach (var propHex in epoch.Proposals)
        {
            var propMsg = MlsMessage.ReadFrom(new TlsReader(Hex(propHex)));
            var propPub = (PublicMessage)propMsg.Body;
            group.CacheProposal(propPub);
        }

        // Parse commit PublicMessage
        var commitMsg = MlsMessage.ReadFrom(new TlsReader(Hex(epoch.Commit)));
        var commitPub = (PublicMessage)commitMsg.Body;

        // Process commit via production code
        group.ProcessCommit(commitPub);
    }


    // ---- Passive Client: Welcome Test Vectors ----

    public static IEnumerable<object[]> PassiveClientWelcomeVectors()
    {
        var vectors = JsonSerializer.Deserialize<PassiveClientVector[]>(
            File.ReadAllText(VectorPath("passive-client-welcome.json")), JsonOpts)!;
        foreach (var v in vectors.Where(x => x.CipherSuite == 1))
            yield return new object[] { v };
    }

    [Theory]
    [MemberData(nameof(PassiveClientWelcomeVectors))]
    public void PassiveClient_Welcome_MatchesOfficialVectors(PassiveClientVector v)
    {
        var cs = new CipherSuite0x0001();
        var group = ProcessWelcomeForPassiveClient(v, cs);
        Assert.Equal(Hex(v.InitialEpochAuthenticator), group.KeySchedule.EpochAuthenticator);

        foreach (var epoch in v.Epochs)
        {
            ProcessEpochForPassiveClient(group, epoch, v, cs);
            Assert.Equal(Hex(epoch.EpochAuthenticator), group.KeySchedule.EpochAuthenticator);
        }
    }

    // ---- Passive Client: Handling Commit Test Vectors ----

    public static IEnumerable<object[]> PassiveClientHandlingCommitVectors()
    {
        var vectors = JsonSerializer.Deserialize<PassiveClientVector[]>(
            File.ReadAllText(VectorPath("passive-client-handling-commit.json")), JsonOpts)!;
        foreach (var v in vectors.Where(x => x.CipherSuite == 1))
            yield return new object[] { v };
    }

    [Theory]
    [MemberData(nameof(PassiveClientHandlingCommitVectors))]
    public void PassiveClient_HandlingCommit_MatchesOfficialVectors(PassiveClientVector v)
    {
        var cs = new CipherSuite0x0001();
        var group = ProcessWelcomeForPassiveClient(v, cs);
        Assert.Equal(Hex(v.InitialEpochAuthenticator), group.KeySchedule.EpochAuthenticator);

        for (int i = 0; i < v.Epochs.Length; i++)
        {
            try
            {
                ProcessEpochForPassiveClient(group, v.Epochs[i], v, cs);
            }
            catch (Exception ex)
            {
                throw new Exception($"Epoch {i} (epoch={group.Epoch}) failed: {ex.Message}", ex);
            }
            Assert.Equal(Hex(v.Epochs[i].EpochAuthenticator), group.KeySchedule.EpochAuthenticator);
        }
    }

    // ---- Passive Client: Random Test Vectors ----

    public static IEnumerable<object[]> PassiveClientRandomVectors()
    {
        var vectors = JsonSerializer.Deserialize<PassiveClientVector[]>(
            File.ReadAllText(VectorPath("passive-client-random.json")), JsonOpts)!;
        foreach (var v in vectors.Where(x => x.CipherSuite == 1))
            yield return new object[] { v };
    }

    [Theory]
    [MemberData(nameof(PassiveClientRandomVectors))]
    public void PassiveClient_Random_MatchesOfficialVectors(PassiveClientVector v)
    {
        var cs = new CipherSuite0x0001();
        var group = ProcessWelcomeForPassiveClient(v, cs);
        Assert.Equal(Hex(v.InitialEpochAuthenticator), group.KeySchedule.EpochAuthenticator);

        for (int i = 0; i < v.Epochs.Length; i++)
        {
            ProcessEpochForPassiveClient(group, v.Epochs[i], v, cs);
            Assert.Equal(Hex(v.Epochs[i].EpochAuthenticator), group.KeySchedule.EpochAuthenticator);
        }
    }

}
