using System.Security.Cryptography;
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

    /// <summary>
    /// Decrypts PrivateMessage test vectors from the official RFC 9420 message-protection
    /// test vectors. This validates the full production code path including:
    /// - GetCiphertextSample (must use Nh, not Nk)
    /// - DeriveSenderDataKey/Nonce
    /// - reuse_guard XOR with content nonce
    /// - AEAD decrypt of content
    /// </summary>
    [Fact]
    public void MessageProtection_DecryptPrivateMessage_Application_MatchesOfficialVectors()
    {
        var vectors = JsonSerializer.Deserialize<MessageProtectionVector[]>(
            File.ReadAllText(VectorPath("message-protection.json")), JsonOpts)!;

        var v = vectors.First(x => x.CipherSuite == 1);
        var cs = new CipherSuite0x0001();

        // Parse the PrivateMessage from the MLSMessage envelope
        var mlsMsg = MlsMessage.ReadFrom(new TlsReader(Hex(v.ApplicationPriv)));
        Assert.Equal(WireFormat.MlsPrivateMessage, mlsMsg.WireFormat);
        var privateMsg = (PrivateMessage)mlsMsg.Body;

        // Verify the parsed message matches expected group context
        Assert.Equal(Hex(v.GroupId), privateMsg.GroupId);
        Assert.Equal(v.Epoch, privateMsg.Epoch);
        Assert.Equal(ContentType.Application, privateMsg.ContentType);

        // Build the SecretTree from the encryption secret (2-member group per RFC 13.3)
        var secretTree = new SecretTree(cs, Hex(v.EncryptionSecret), 2);

        // Decrypt using the production code path
        var (content, auth) = MessageFraming.DecryptPrivateMessage(
            privateMsg, cs, secretTree, Hex(v.SenderDataSecret));

        // The decrypted content bytes should match the application plaintext
        Assert.Equal(Hex(v.Application), content.Content);
        Assert.Equal(ContentType.Application, content.ContentType);
        Assert.Equal(Hex(v.GroupId), content.GroupId);
        Assert.Equal(v.Epoch, content.Epoch);

        // Verify the signature using the test vector's signing public key
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
        byte[] serializedGroupContext = TlsCodec.Serialize(w => groupContext.WriteTo(w));

        bool sigValid = MessageFraming.VerifyPrivateMessageSignature(
            content, auth, Hex(v.SignaturePub), serializedGroupContext, cs);
        Assert.True(sigValid, "Signature verification failed on decrypted PrivateMessage");
    }

    /// <summary>
    /// Decrypts the proposal PrivateMessage test vector.
    /// </summary>
    [Fact]
    public void MessageProtection_DecryptPrivateMessage_Proposal_MatchesOfficialVectors()
    {
        var vectors = JsonSerializer.Deserialize<MessageProtectionVector[]>(
            File.ReadAllText(VectorPath("message-protection.json")), JsonOpts)!;

        var v = vectors.First(x => x.CipherSuite == 1);
        var cs = new CipherSuite0x0001();

        var mlsMsg = MlsMessage.ReadFrom(new TlsReader(Hex(v.ProposalPriv)));
        Assert.Equal(WireFormat.MlsPrivateMessage, mlsMsg.WireFormat);
        var privateMsg = (PrivateMessage)mlsMsg.Body;

        Assert.Equal(ContentType.Proposal, privateMsg.ContentType);

        var secretTree = new SecretTree(cs, Hex(v.EncryptionSecret), 2);

        var (content, auth) = MessageFraming.DecryptPrivateMessage(
            privateMsg, cs, secretTree, Hex(v.SenderDataSecret));

        Assert.Equal(Hex(v.Proposal), content.Content);
        Assert.Equal(ContentType.Proposal, content.ContentType);
    }

    /// <summary>
    /// Decrypts the commit PrivateMessage test vector.
    /// </summary>
    [Fact]
    public void MessageProtection_DecryptPrivateMessage_Commit_MatchesOfficialVectors()
    {
        var vectors = JsonSerializer.Deserialize<MessageProtectionVector[]>(
            File.ReadAllText(VectorPath("message-protection.json")), JsonOpts)!;

        var v = vectors.First(x => x.CipherSuite == 1);
        var cs = new CipherSuite0x0001();

        var mlsMsg = MlsMessage.ReadFrom(new TlsReader(Hex(v.CommitPriv)));
        Assert.Equal(WireFormat.MlsPrivateMessage, mlsMsg.WireFormat);
        var privateMsg = (PrivateMessage)mlsMsg.Body;

        Assert.Equal(ContentType.Commit, privateMsg.ContentType);

        var secretTree = new SecretTree(cs, Hex(v.EncryptionSecret), 2);

        var (content, auth) = MessageFraming.DecryptPrivateMessage(
            privateMsg, cs, secretTree, Hex(v.SenderDataSecret));

        Assert.Equal(Hex(v.Commit), content.Content);
        Assert.Equal(ContentType.Commit, content.ContentType);
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
    /// Derives the HPKE private key from a node secret using RFC 9180 §7.1.3 DeriveKeyPair.
    /// For DHKEM(X25519): dkp_prk = LabeledExtract("", "dkp_prk", ikm),
    /// sk = LabeledExpand(dkp_prk, "sk", "", 32)
    /// </summary>
    private static byte[] DeriveHpkePrivateKey(ICipherSuite cs, byte[] nodeSecret)
    {
        // KEM suite_id = "KEM" || I2OSP(0x0020, 2)
        byte[] kemSuiteId = { 0x4B, 0x45, 0x4D, 0x00, 0x20 };
        byte[] hpkeV1 = System.Text.Encoding.ASCII.GetBytes("HPKE-v1");

        // LabeledExtract(salt="", label="dkp_prk", ikm=nodeSecret)
        // labeled_ikm = "HPKE-v1" || suite_id || "dkp_prk" || ikm
        byte[] dkpPrkLabel = System.Text.Encoding.ASCII.GetBytes("dkp_prk");
        byte[] labeledIkm = Concat(Concat(Concat(hpkeV1, kemSuiteId), dkpPrkLabel), nodeSecret);
        byte[] dkpPrk = cs.Extract(Array.Empty<byte>(), labeledIkm);

        // LabeledExpand(dkp_prk, label="sk", info="", L=32)
        // labeled_info = I2OSP(32, 2) || "HPKE-v1" || suite_id || "sk" || ""
        byte[] skLabel = System.Text.Encoding.ASCII.GetBytes("sk");
        byte[] labeledInfo = Concat(Concat(Concat(new byte[] { 0x00, 0x20 }, hpkeV1), kemSuiteId), skLabel);
        return cs.Expand(dkpPrk, labeledInfo, 32);
    }

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

    [Fact]
    public void TreeValidation_TreeHash_MatchesOfficialVectors()
    {
        var vectors = JsonSerializer.Deserialize<TreeValidationVector[]>(
            File.ReadAllText(VectorPath("tree-validation.json")), JsonOpts)!;

        var v = vectors.First(x => x.CipherSuite == 1);
        var cs = new CipherSuite0x0001();

        var tree = Tree.RatchetTree.ReadFrom(new TlsReader(Hex(v.TreeData)));

        // Verify tree round-trip
        byte[] reserialized = TlsCodec.Serialize(w => tree.WriteTo(w));
        Assert.Equal(Hex(v.TreeData), reserialized);

        // Verify tree hash for each node
        for (int i = 0; i < v.TreeHashes.Length; i++)
        {
            byte[] expected = Hex(v.TreeHashes[i]);
            byte[] actual = tree.ComputeTreeHash(cs, (uint)i);
            Assert.True(expected.SequenceEqual(actual),
                $"Tree hash mismatch at node {i}: " +
                $"expected {v.TreeHashes[i][..16]}..., got {Convert.ToHexString(actual)[..16]}...");
        }

        // Verify resolutions for each node
        for (int i = 0; i < v.Resolutions.Length; i++)
        {
            var expected = v.Resolutions[i];
            var actual = tree.Resolution((uint)i);
            Assert.Equal(expected, actual.ToArray());
        }
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
                    byte[] nodePriv = DeriveHpkePrivateKey(cs, nodeSecret);
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
    /// Holds the passive client's state between epochs.
    /// </summary>
    private sealed class PassiveClientState
    {
        public required Tree.RatchetTree Tree { get; set; }
        public required uint MyLeafIndex { get; set; }
        public required byte[] MyEncryptionPriv { get; set; }
        public required KeySchedule.KeyScheduleEpoch KeySchedule { get; set; }
        public required GroupContext GroupContext { get; set; }
        public required byte[] InterimTranscriptHash { get; set; }
        public required Extension[] Extensions { get; set; }
        public required ulong Epoch { get; set; }
        // Map from node index to HPKE private key (leaf + parent nodes)
        public Dictionary<uint, byte[]> PrivateKeys { get; set; } = new();
    }

    /// <summary>
    /// Processes a Welcome message manually (not using MlsGroup) to establish passive client state.
    /// </summary>
    private PassiveClientState ProcessWelcomeForPassiveClient(
        PassiveClientVector v, ICipherSuite cs)
    {
        // Parse MLSMessage-wrapped KeyPackage
        var kpMsg = MlsMessage.ReadFrom(new TlsReader(Hex(v.KeyPackage)));
        var keyPackage = (KeyPackage)kpMsg.Body;

        // Parse MLSMessage-wrapped Welcome
        var welcomeMsg = MlsMessage.ReadFrom(new TlsReader(Hex(v.Welcome)));
        var welcome = (Welcome)welcomeMsg.Body;

        // Find matching EncryptedGroupSecrets
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

        // HPKE decrypt GroupSecrets (EncryptWithLabel per RFC 9420 §5.1.3)
        byte[] hpkeInfo = TlsCodec.Serialize(w =>
        {
            w.WriteOpaqueV(System.Text.Encoding.ASCII.GetBytes("MLS 1.0 Welcome"));
            w.WriteOpaqueV(welcome.EncryptedGroupInfo);
        });
        byte[] gsBytes = cs.HpkeOpen(
            Hex(v.InitPriv),
            mySecrets.EncryptedGroupSecretsValue.KemOutput,
            hpkeInfo,
            Array.Empty<byte>(),
            mySecrets.EncryptedGroupSecretsValue.Ciphertext);
        var groupSecrets = GroupSecrets.ReadFrom(new TlsReader(gsBytes));

        // Compute PSK secret
        byte[] pskSecret;
        if (v.ExternalPsks.Length > 0)
        {
            var pskInputs = new List<PskSecretDerivation.PskInput>();
            foreach (var psk in groupSecrets.Psks)
            {
                byte[] pskValue = Array.Empty<byte>();
                if (psk.PskType == PskType.External)
                {
                    // Match by psk_id
                    foreach (var extPsk in v.ExternalPsks)
                    {
                        if (Hex(extPsk.PskId).AsSpan().SequenceEqual(psk.PskId))
                        {
                            pskValue = Hex(extPsk.Psk);
                            break;
                        }
                    }
                }
                pskInputs.Add(new PskSecretDerivation.PskInput { Id = psk, PskValue = pskValue });
            }
            pskSecret = PskSecretDerivation.ComputePskSecret(cs, pskInputs.ToArray());
        }
        else
        {
            pskSecret = new byte[cs.SecretSize];
        }

        // Derive welcome_secret and decrypt GroupInfo
        byte[] intermediateSecret = cs.Extract(groupSecrets.JoinerSecret, pskSecret);
        byte[] welcomeSecret = cs.DeriveSecret(intermediateSecret, "welcome");
        byte[] welcomeKey = cs.ExpandWithLabel(
            welcomeSecret, "key", Array.Empty<byte>(), cs.AeadKeySize);
        byte[] welcomeNonce = cs.ExpandWithLabel(
            welcomeSecret, "nonce", Array.Empty<byte>(), cs.AeadNonceSize);
        byte[] groupInfoBytes = cs.AeadDecrypt(
            welcomeKey, welcomeNonce, Array.Empty<byte>(), welcome.EncryptedGroupInfo);
        var groupInfo = GroupInfo.ReadFrom(new TlsReader(groupInfoBytes));

        // Get ratchet tree (from GroupInfo extensions or test vector)
        Tree.RatchetTree tree;
        if (v.RatchetTree != null)
        {
            tree = Tree.RatchetTree.ReadFrom(new TlsReader(Hex(v.RatchetTree)));
        }
        else
        {
            byte[]? treeData = null;
            foreach (var ext in groupInfo.Extensions)
            {
                if (ext.ExtensionType == 0x0002)
                {
                    treeData = ext.ExtensionData;
                    break;
                }
            }
            Assert.NotNull(treeData);
            tree = Tree.RatchetTree.ReadFrom(new TlsReader(treeData));
        }

        // Find our leaf index
        uint myLeafIndex = uint.MaxValue;
        for (uint i = 0; i < tree.LeafCount; i++)
        {
            var leaf = tree.GetLeaf(i);
            if (leaf != null &&
                leaf.SignatureKey.AsSpan().SequenceEqual(keyPackage.LeafNode.SignatureKey))
            {
                myLeafIndex = i;
                break;
            }
        }
        Assert.NotEqual(uint.MaxValue, myLeafIndex);

        // Derive key schedule from joiner_secret
        var groupContext = groupInfo.GroupContext;
        byte[] contextBytes = TlsCodec.Serialize(w => groupContext.WriteTo(w));
        var keySchedule = KeyScheduleEpoch.FromJoinerSecret(
            cs, groupSecrets.JoinerSecret, contextBytes, pskSecret);

        // Verify confirmation tag
        byte[] expectedTag = keySchedule.ComputeConfirmationTag(
            cs, groupContext.ConfirmedTranscriptHash);
        Assert.True(
            CryptographicOperations.FixedTimeEquals(expectedTag, groupInfo.ConfirmationTag),
            "Confirmation tag mismatch in Welcome");

        // Compute interim transcript hash per RFC 9420 §8.2:
        // InterimTranscriptHashInput = { MAC confirmation_tag } where MAC = opaque<V>
        byte[] interimInput = TlsCodec.Serialize(w => w.WriteOpaqueV(groupInfo.ConfirmationTag));
        byte[] interimHash = cs.Hash(
            Concat(groupContext.ConfirmedTranscriptHash, interimInput));

        // Build private key map
        var privateKeys = new Dictionary<uint, byte[]>();
        uint myNodeIdx = TreeMath.LeafToNode(myLeafIndex);
        privateKeys[myNodeIdx] = Hex(v.EncryptionPriv);

        // Derive parent node private keys from path_secret (if provided in GroupSecrets)
        // RFC 9420 §12.4.3.1: path_secret is at the common ancestor of the
        // committer and the joiner. Derive forward up the joiner's direct path.
        if (groupSecrets.PathSecret != null)
        {
            uint committerLeaf = groupInfo.Signer;
            var myDp = TreeMath.DirectPath(myLeafIndex, tree.LeafCount);

            // Find the common ancestor node of committer and joiner
            // CommonAncestor takes LEAF indices (it calls LeafToNode internally)
            uint commonAncestor = TreeMath.CommonAncestor(committerLeaf, myLeafIndex);

            // Find the position of the common ancestor in the joiner's direct path
            int startIdx = -1;
            for (int i = 0; i < myDp.Length; i++)
            {
                if (myDp[i] == commonAncestor)
                {
                    startIdx = i;
                    break;
                }
            }
            Assert.True(startIdx >= 0, "Common ancestor not found in joiner's direct path");

            byte[] pathSecret = groupSecrets.PathSecret;
            for (int i = startIdx; i < myDp.Length; i++)
            {
                byte[] nodeSecret = cs.DeriveSecret(pathSecret, "node");
                byte[] nodePriv = DeriveHpkePrivateKey(cs, nodeSecret);
                privateKeys[myDp[i]] = nodePriv;
                // Store private key in tree node if it exists
                var parentNode = tree.GetParent(myDp[i]);
                if (parentNode != null)
                    parentNode.PrivateKey = nodePriv;
                if (i < myDp.Length - 1)
                    pathSecret = cs.DeriveSecret(pathSecret, "path");
            }
        }

        return new PassiveClientState
        {
            Tree = tree,
            MyLeafIndex = myLeafIndex,
            MyEncryptionPriv = Hex(v.EncryptionPriv),
            KeySchedule = keySchedule,
            GroupContext = groupContext,
            InterimTranscriptHash = interimHash,
            Extensions = groupContext.Extensions,
            Epoch = groupContext.Epoch,
            PrivateKeys = privateKeys,
        };
    }

    /// <summary>
    /// Processes a single epoch (proposals + commit) for a passive client.
    /// </summary>
    private void ProcessEpochForPassiveClient(
        PassiveClientState state, PassiveClientEpoch epoch,
        PassiveClientVector v, ICipherSuite cs)
    {
        // Parse standalone proposals and build proposal cache
        var proposalCache = new Dictionary<string, Proposal>();
        foreach (var propHex in epoch.Proposals)
        {
            var propMsg = MlsMessage.ReadFrom(new TlsReader(Hex(propHex)));
            var propPub = (PublicMessage)propMsg.Body;

            // Compute ProposalRef = RefHash("MLS 1.0 Proposal Reference", AuthenticatedContent)
            byte[] authContent = TlsCodec.Serialize(w =>
            {
                w.WriteUint16((ushort)WireFormat.MlsPublicMessage);
                propPub.Content.WriteTo(w);
                propPub.Auth.WriteTo(w, propPub.Content.ContentType);
            });
            byte[] propRef = cs.RefHash("MLS 1.0 Proposal Reference", authContent);
            var proposal = Proposal.ReadFrom(new TlsReader(propPub.Content.Content));
            proposalCache[Convert.ToHexString(propRef).ToLowerInvariant()] = proposal;
        }

        // Parse commit PublicMessage
        var commitMsg = MlsMessage.ReadFrom(new TlsReader(Hex(epoch.Commit)));
        var commitPub = (PublicMessage)commitMsg.Body;
        var content = commitPub.Content;
        Assert.Equal(ContentType.Commit, content.ContentType);

        uint senderLeaf = content.Sender.LeafIndex;

        // Verify signature using the CURRENT group context
        byte[] currentCtxBytes = TlsCodec.Serialize(w => state.GroupContext.WriteTo(w));
        byte[] senderSigKey = state.Tree.GetLeaf(senderLeaf)!.SignatureKey;
        byte[] tbs = MessageFraming.BuildFramedContentTbs(
            WireFormat.MlsPublicMessage, content, currentCtxBytes);
        Assert.True(
            cs.VerifyWithLabel(senderSigKey, "FramedContentTBS", tbs, commitPub.Auth.Signature),
            $"Commit signature verification failed for sender {senderLeaf}");

        // Parse the Commit struct
        var commit = Types.Commit.ReadFrom(new TlsReader(content.Content));

        // Clone tree and extensions
        var tentativeTree = state.Tree.Clone();
        var tentativeExtensions = (Extension[])state.Extensions.Clone();

        // Resolve and apply proposals, collecting PSK references and tracking added leaves
        var pskIds = new List<PreSharedKeyId>();
        var addedLeaves = new List<uint>();
        foreach (var por in commit.Proposals)
        {
            Proposal proposal;
            if (por is InlineProposal inline)
            {
                proposal = inline.Proposal;
            }
            else if (por is ProposalReference pref)
            {
                string refKey = Convert.ToHexString(pref.Reference).ToLowerInvariant();
                Assert.True(proposalCache.ContainsKey(refKey),
                    $"Unknown proposal reference: {refKey}");
                proposal = proposalCache[refKey];
            }
            else
            {
                throw new InvalidOperationException("Unknown ProposalOrRef type");
            }

            // Apply proposal to tentative tree
            if (proposal is AddProposal add)
            {
                uint newLeafIdx = tentativeTree.AddLeaf(add.KeyPackage.LeafNode);
                addedLeaves.Add(newLeafIdx);
            }
            else if (proposal is RemoveProposal remove)
                tentativeTree.BlankLeaf(remove.LeafIndex);
            else if (proposal is UpdateProposal update)
            {
                // Update proposal: sender updates their own leaf
                tentativeTree.SetLeaf(senderLeaf, update.LeafNode);
            }
            else if (proposal is PreSharedKeyProposal pskProp)
                pskIds.Add(pskProp.Psk);
            else if (proposal is GroupContextExtensionsProposal gce)
                tentativeExtensions = gce.Extensions;
        }

        // Process UpdatePath if present
        byte[] commitSecret;
        if (commit.Path != null)
        {
            // Save tree state AFTER proposals but BEFORE UpdatePath
            // for sibling tree hash and resolution computation
            var originalTree = tentativeTree.Clone();

            // Apply UpdatePath public state
            tentativeTree.SetLeaf(senderLeaf, commit.Path.LeafNode);
            var senderDp = TreeMath.DirectPath(senderLeaf, tentativeTree.LeafCount);
            var senderCopath = TreeMath.Copath(senderLeaf, tentativeTree.LeafCount);
            foreach (uint n in senderDp)
                tentativeTree.SetParent(n, null);

            // Filtered direct path
            var filteredDp = new List<uint>();
            var filteredCopath = new List<uint>();
            for (int i = 0; i < senderDp.Length; i++)
            {
                if (tentativeTree.Resolution(senderCopath[i]).Count > 0)
                {
                    filteredDp.Add(senderDp[i]);
                    filteredCopath.Add(senderCopath[i]);
                }
            }

            for (int i = 0; i < filteredDp.Count; i++)
            {
                tentativeTree.SetParent(filteredDp[i], new ParentNode
                {
                    EncryptionKey = commit.Path.Nodes[i].EncryptionKey,
                    UnmergedLeaves = new List<uint>(),
                });
            }

            // Compute parent hashes (from root down)
            for (int i = filteredDp.Count - 2; i >= 0; i--)
            {
                uint nodeIdx = filteredDp[i];
                uint parentIdx = filteredDp[i + 1];
                uint siblingIdx = nodeIdx < parentIdx
                    ? TreeMath.Right(parentIdx)
                    : TreeMath.Left(parentIdx);
                byte[] siblingTreeHash = originalTree.ComputeTreeHash(cs, siblingIdx);
                byte[] parentHash = tentativeTree.ComputeParentHash(cs, parentIdx, siblingTreeHash);
                tentativeTree.GetParent(nodeIdx)!.ParentHash = parentHash;
            }

            // RFC 9420 §7.7: Update unmerged leaves
            // Step 1: Already done - all parent nodes on committer's DP have empty unmerged-leaves
            //         (we created them with empty lists above).
            // Step 2: For each added leaf, add to unmerged-leaves of applicable parent nodes.
            foreach (uint addedLeaf in addedLeaves)
            {
                var addedDp = TreeMath.DirectPath(addedLeaf, tentativeTree.LeafCount);
                var addedDpSet = new HashSet<uint>(addedDp);

                // Step 2a: If commit has a path, add to committer's filtered DP nodes
                // that are NOT in the added leaf's direct path
                foreach (uint fdpNode in filteredDp)
                {
                    if (!addedDpSet.Contains(fdpNode))
                    {
                        var pn = tentativeTree.GetParent(fdpNode);
                        if (pn != null)
                            pn.UnmergedLeaves.Add(addedLeaf);
                    }
                }

                // Step 2b: Add to non-blank parent nodes between the added leaf and
                // the common ancestor of the added leaf and the committer
                uint commonAnc = TreeMath.CommonAncestor(addedLeaf, senderLeaf);
                foreach (uint dpNode in addedDp)
                {
                    if (dpNode == commonAnc)
                        break;
                    var pn = tentativeTree.GetParent(dpNode);
                    if (pn != null)
                        pn.UnmergedLeaves.Add(addedLeaf);
                }
            }

            // Compute provisional tree hash
            uint root = TreeMath.Root(tentativeTree.LeafCount);
            byte[] provisionalTreeHash = tentativeTree.ComputeTreeHash(cs, root);

            // Compute confirmed transcript hash per RFC 9420 §8.2:
            // ConfirmedTranscriptHashInput = { wire_format, FramedContent, signature }
            // NOT FramedContentTBS (which includes version + group_context instead of signature)
            byte[] confirmedInput = TlsCodec.Serialize(w =>
            {
                w.WriteUint16((ushort)WireFormat.MlsPublicMessage);
                content.WriteTo(w);
                w.WriteOpaqueV(commitPub.Auth.Signature);
            });
            byte[] newConfirmedTranscriptHash = cs.Hash(
                Concat(state.InterimTranscriptHash, confirmedInput));

            // Build new GroupContext
            var newGroupContext = new GroupContext
            {
                Version = ProtocolVersion.Mls10,
                CipherSuite = cs.Id,
                GroupId = state.GroupContext.GroupId,
                Epoch = state.Epoch + 1,
                TreeHash = provisionalTreeHash,
                ConfirmedTranscriptHash = newConfirmedTranscriptHash,
                Extensions = tentativeExtensions,
            };
            byte[] newCtxBytes = TlsCodec.Serialize(w => newGroupContext.WriteTo(w));

            // HPKE context for EncryptWithLabel
            byte[] encryptContext = TlsCodec.Serialize(w =>
            {
                w.WriteOpaqueV(System.Text.Encoding.UTF8.GetBytes("MLS 1.0 UpdatePathNode"));
                w.WriteOpaqueV(newCtxBytes);
            });

            // Find our decryption position in filtered copath
            int copathPos = -1;
            int resPos = -1;
            for (int i = 0; i < filteredCopath.Count; i++)
            {
                // Use tentativeTree for resolution (after proposals, before UpdatePath was
                // the original tree, but copath subtrees aren't affected by UpdatePath)
                var resolution = originalTree.Resolution(filteredCopath[i]);
                for (int j = 0; j < resolution.Count; j++)
                {
                    if (state.PrivateKeys.ContainsKey(resolution[j]))
                    {
                        copathPos = i;
                        resPos = j;
                        break;
                    }
                }
                if (copathPos >= 0) break;
            }

            Assert.True(copathPos >= 0,
                $"Passive client (leaf {state.MyLeafIndex}) not found in any filtered copath resolution for sender {senderLeaf}");

            // Decrypt path secret
            var ct = commit.Path.Nodes[copathPos].EncryptedPathSecret[resPos];
            uint resNodeIdx = originalTree.Resolution(filteredCopath[copathPos])[resPos];

            byte[] pathSecret = cs.HpkeOpen(
                state.PrivateKeys[resNodeIdx],
                ct.KemOutput,
                encryptContext,
                Array.Empty<byte>(),
                ct.Ciphertext);

            // Derive forward: compute private keys for all filtered DP nodes from copathPos onward
            byte[] currentPathSecret = pathSecret;
            var newPrivateKeys = new Dictionary<uint, byte[]>(state.PrivateKeys);
            for (int i = copathPos; i < filteredDp.Count; i++)
            {
                byte[] nodeSecret = cs.DeriveSecret(currentPathSecret, "node");
                byte[] nodePriv = DeriveHpkePrivateKey(cs, nodeSecret);
                newPrivateKeys[filteredDp[i]] = nodePriv;
                tentativeTree.GetParent(filteredDp[i])!.PrivateKey = nodePriv;
                if (i < filteredDp.Count - 1)
                    currentPathSecret = cs.DeriveSecret(currentPathSecret, "path");
            }
            commitSecret = cs.DeriveSecret(currentPathSecret, "path");

            // Update private keys
            state.PrivateKeys = newPrivateKeys;

            // Compute PSK secret for key schedule
            byte[]? pskSecretParam = null;
            if (pskIds.Count > 0)
            {
                var pskInputs = pskIds.Select(id =>
                {
                    byte[] pskValue = Array.Empty<byte>();
                    if (id.PskType == PskType.External)
                    {
                        foreach (var extPsk in v.ExternalPsks)
                        {
                            if (Hex(extPsk.PskId).AsSpan().SequenceEqual(id.PskId))
                            {
                                pskValue = Hex(extPsk.Psk);
                                break;
                            }
                        }
                    }
                    return new PskSecretDerivation.PskInput { Id = id, PskValue = pskValue };
                }).ToArray();
                pskSecretParam = PskSecretDerivation.ComputePskSecret(cs, pskInputs);
            }

            // Derive new key schedule
            var newKeySchedule = KeyScheduleEpoch.Create(
                cs, state.KeySchedule.InitSecret, commitSecret, newCtxBytes, pskSecretParam);

            // Verify confirmation tag
            byte[] expectedTag = newKeySchedule.ComputeConfirmationTag(cs, newConfirmedTranscriptHash);
            Assert.True(
                commitPub.Auth.ConfirmationTag != null &&
                CryptographicOperations.FixedTimeEquals(expectedTag, commitPub.Auth.ConfirmationTag),
                $"Confirmation tag mismatch at epoch {state.Epoch + 1}");

            // Compute interim transcript hash per RFC 9420 §8.2
            byte[] newInterimInput = TlsCodec.Serialize(w => w.WriteOpaqueV(commitPub.Auth.ConfirmationTag!));
            byte[] newInterimHash = cs.Hash(
                Concat(newConfirmedTranscriptHash, newInterimInput));

            // Update state
            state.Tree = tentativeTree;
            state.KeySchedule = newKeySchedule;
            state.GroupContext = newGroupContext;
            state.InterimTranscriptHash = newInterimHash;
            state.Extensions = tentativeExtensions;
            state.Epoch = state.Epoch + 1;
        }
        else
        {
            // No UpdatePath: commit_secret = zeros
            commitSecret = new byte[cs.SecretSize];

            // Compute tree hash
            uint root = TreeMath.Root(tentativeTree.LeafCount);
            byte[] treeHash = tentativeTree.ComputeTreeHash(cs, root);

            // ConfirmedTranscriptHashInput per RFC 9420 §8.2
            byte[] confirmedInput2 = TlsCodec.Serialize(w =>
            {
                w.WriteUint16((ushort)WireFormat.MlsPublicMessage);
                content.WriteTo(w);
                w.WriteOpaqueV(commitPub.Auth.Signature);
            });
            byte[] newConfirmedTranscriptHash = cs.Hash(
                Concat(state.InterimTranscriptHash, confirmedInput2));

            var newGroupContext = new GroupContext
            {
                Version = ProtocolVersion.Mls10,
                CipherSuite = cs.Id,
                GroupId = state.GroupContext.GroupId,
                Epoch = state.Epoch + 1,
                TreeHash = treeHash,
                ConfirmedTranscriptHash = newConfirmedTranscriptHash,
                Extensions = tentativeExtensions,
            };
            byte[] newCtxBytes = TlsCodec.Serialize(w => newGroupContext.WriteTo(w));

            // PSK secret
            byte[]? pskSecretParam = null;
            if (pskIds.Count > 0)
            {
                var pskInputs = pskIds.Select(id =>
                {
                    byte[] pskValue = Array.Empty<byte>();
                    if (id.PskType == PskType.External)
                    {
                        foreach (var extPsk in v.ExternalPsks)
                        {
                            if (Hex(extPsk.PskId).AsSpan().SequenceEqual(id.PskId))
                            {
                                pskValue = Hex(extPsk.Psk);
                                break;
                            }
                        }
                    }
                    return new PskSecretDerivation.PskInput { Id = id, PskValue = pskValue };
                }).ToArray();
                pskSecretParam = PskSecretDerivation.ComputePskSecret(cs, pskInputs);
            }

            var newKeySchedule = KeyScheduleEpoch.Create(
                cs, state.KeySchedule.InitSecret, commitSecret, newCtxBytes, pskSecretParam);

            byte[] expectedTag = newKeySchedule.ComputeConfirmationTag(cs, newConfirmedTranscriptHash);
            Assert.True(
                commitPub.Auth.ConfirmationTag != null &&
                CryptographicOperations.FixedTimeEquals(expectedTag, commitPub.Auth.ConfirmationTag),
                $"Confirmation tag mismatch at epoch {state.Epoch + 1}");

            byte[] newInterimInput = TlsCodec.Serialize(w => w.WriteOpaqueV(commitPub.Auth.ConfirmationTag!));
            byte[] newInterimHash = cs.Hash(
                Concat(newConfirmedTranscriptHash, newInterimInput));

            state.Tree = tentativeTree;
            state.KeySchedule = newKeySchedule;
            state.GroupContext = newGroupContext;
            state.InterimTranscriptHash = newInterimHash;
            state.Extensions = tentativeExtensions;
            state.Epoch = state.Epoch + 1;
        }
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
        var state = ProcessWelcomeForPassiveClient(v, cs);
        Assert.Equal(Hex(v.InitialEpochAuthenticator), state.KeySchedule.EpochAuthenticator);

        foreach (var epoch in v.Epochs)
        {
            ProcessEpochForPassiveClient(state, epoch, v, cs);
            Assert.Equal(Hex(epoch.EpochAuthenticator), state.KeySchedule.EpochAuthenticator);
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
        var state = ProcessWelcomeForPassiveClient(v, cs);
        Assert.Equal(Hex(v.InitialEpochAuthenticator), state.KeySchedule.EpochAuthenticator);

        for (int i = 0; i < v.Epochs.Length; i++)
        {
            try
            {
                ProcessEpochForPassiveClient(state, v.Epochs[i], v, cs);
            }
            catch (Exception ex)
            {
                throw new Exception($"Epoch {i} (epoch={state.Epoch}) failed: {ex.Message}", ex);
            }
            Assert.Equal(Hex(v.Epochs[i].EpochAuthenticator), state.KeySchedule.EpochAuthenticator);
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
        var state = ProcessWelcomeForPassiveClient(v, cs);
        Assert.Equal(Hex(v.InitialEpochAuthenticator), state.KeySchedule.EpochAuthenticator);

        for (int i = 0; i < v.Epochs.Length; i++)
        {
            ProcessEpochForPassiveClient(state, v.Epochs[i], v, cs);
            Assert.Equal(Hex(v.Epochs[i].EpochAuthenticator), state.KeySchedule.EpochAuthenticator);
        }
    }

}
