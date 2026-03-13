using System.Text.Json;
using System.Text.Json.Serialization;
using DotnetMls.Codec;
using DotnetMls.Crypto;
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

        // Also verify our own signatures verify
        var ourSig = cs.SignWithLabel(
            Hex(v.SignWithLabel.Priv),
            v.SignWithLabel.Label,
            Hex(v.SignWithLabel.Content));

        bool ourValid = cs.VerifyWithLabel(
            Hex(v.SignWithLabel.Pub),
            v.SignWithLabel.Label,
            Hex(v.SignWithLabel.Content),
            ourSig);

        Assert.True(ourValid, "Our own signature should verify");
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

        // confirmed_transcript_hash = Hash(interim_before || ConfirmedTranscriptHashInput)
        byte[] computedConfirmedHash = cs.Hash(Concat(interimBefore, confirmedInput));
        Assert.Equal(expectedConfirmedHash, computedConfirmedHash);

        // confirmation_tag = MAC(confirmation_key, confirmed_transcript_hash)
        byte[] confirmationTag = cs.Mac(confirmationKey, computedConfirmedHash);

        // interim_transcript_hash_after = Hash(confirmed_transcript_hash || InterimTranscriptHashInput)
        // InterimTranscriptHashInput = struct { MAC confirmation_tag; }
        // MAC is opaque<V>, so serialized with VarInt length prefix
        byte[] interimInput = TlsCodec.Serialize(w => w.WriteOpaqueV(confirmationTag));
        byte[] computedInterimAfter = cs.Hash(Concat(computedConfirmedHash, interimInput));
        Assert.Equal(expectedInterimAfter, computedInterimAfter);
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
}
