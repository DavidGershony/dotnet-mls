using System.Text;

namespace DotnetMls.Crypto;

/// <summary>
/// Full HPKE implementation per RFC 9180:
///   DHKEM(X25519, HKDF-SHA256) + HKDF-SHA256 + ChaCha20-Poly1305
///   (KEM ID = 0x0020, KDF ID = 0x0001, AEAD ID = 0x0003)
///
/// Operates in Base mode (mode = 0x00) only.
/// Identical to HpkeX25519Aes128 except for AEAD (ChaCha20-Poly1305 with 32-byte keys).
/// </summary>
public sealed class HpkeX25519ChaCha20 : IHpke
{
    // RFC 9180 constants
    private const ushort KemId = 0x0020;   // DHKEM(X25519, HKDF-SHA256)
    private const ushort KdfId = 0x0001;   // HKDF-SHA256
    private const ushort AeadId = 0x0003;  // ChaCha20-Poly1305
    private const byte ModeBase = 0x00;

    private const int Nk = 32;   // ChaCha20-Poly1305 key size
    private const int Nn = 12;   // ChaCha20-Poly1305 nonce size
    private const int Nh = 32;   // SHA-256 hash output size
    private const int Nsecret = 32; // KEM shared secret size
    private const int Nenc = 32; // X25519 public key / enc size

    // suite_id for KEM: "KEM" || I2OSP(kem_id, 2)
    private static readonly byte[] KemSuiteId = BuildKemSuiteId();
    // suite_id for HPKE: "HPKE" || I2OSP(kem_id, 2) || I2OSP(kdf_id, 2) || I2OSP(aead_id, 2)
    private static readonly byte[] HpkeSuiteId = BuildHpkeSuiteId();

    private static readonly byte[] PskIdHashLabel = Encoding.ASCII.GetBytes("psk_id_hash");
    private static readonly byte[] InfoHashLabel = Encoding.ASCII.GetBytes("info_hash");
    private static readonly byte[] SecretLabel = Encoding.ASCII.GetBytes("secret");
    private static readonly byte[] KeyLabel = Encoding.ASCII.GetBytes("key");
    private static readonly byte[] BaseNonceLabel = Encoding.ASCII.GetBytes("base_nonce");
    private static readonly byte[] SharedSecretLabel = Encoding.ASCII.GetBytes("shared_secret");
    private static readonly byte[] EaePrkLabel = Encoding.ASCII.GetBytes("eae_prk");
    private static readonly byte[] EmptyBytes = Array.Empty<byte>();

    private readonly X25519Provider _x25519;
    private readonly HkdfProvider _hkdf;
    private readonly ChaCha20Poly1305Provider _aead;

    public HpkeX25519ChaCha20(X25519Provider x25519, HkdfProvider hkdf, ChaCha20Poly1305Provider aead)
    {
        _x25519 = x25519;
        _hkdf = hkdf;
        _aead = aead;
    }

    public HpkeX25519ChaCha20()
        : this(new X25519Provider(), new HkdfProvider(), new ChaCha20Poly1305Provider())
    {
    }

    /// <inheritdoc />
    public (byte[] privateKey, byte[] publicKey) GenerateKeyPair() => _x25519.GenerateKeyPair();

    /// <inheritdoc />
    public (byte[] kemOutput, byte[] sharedSecret) Encap(byte[] recipientPublicKey)
    {
        var (skE, pkE) = _x25519.GenerateKeyPair();
        var dh = _x25519.DeriveSharedSecret(skE, recipientPublicKey);
        var kemContext = Concat(pkE, recipientPublicKey);
        var sharedSecret = ExtractAndExpand(dh, kemContext);
        return (pkE, sharedSecret);
    }

    /// <inheritdoc />
    public byte[] Decap(byte[] kemOutput, byte[] recipientPrivateKey)
    {
        var dh = _x25519.DeriveSharedSecret(recipientPrivateKey, kemOutput);
        var pkR = _x25519.GetPublicKey(recipientPrivateKey);
        var kemContext = Concat(kemOutput, pkR);
        return ExtractAndExpand(dh, kemContext);
    }

    /// <inheritdoc />
    public byte[] Seal(byte[] recipientPublicKey, byte[] info, byte[] aad, byte[] plaintext)
    {
        var (enc, sharedSecret) = Encap(recipientPublicKey);
        var (key, baseNonce) = KeyScheduleS(sharedSecret, info);
        var ct = _aead.Encrypt(key, baseNonce, aad, plaintext);
        return Concat(enc, ct);
    }

    /// <inheritdoc />
    public byte[] Open(byte[] recipientPrivateKey, byte[] kemOutput, byte[] info, byte[] aad, byte[] ciphertext)
    {
        var sharedSecret = Decap(kemOutput, recipientPrivateKey);
        var (key, baseNonce) = KeyScheduleS(sharedSecret, info);
        return _aead.Decrypt(key, baseNonce, aad, ciphertext);
    }

    private byte[] ExtractAndExpand(byte[] dh, byte[] kemContext)
    {
        var eaePrk = LabeledExtractKem(EmptyBytes, EaePrkLabel, dh);
        return LabeledExpandKem(eaePrk, SharedSecretLabel, kemContext, Nsecret);
    }

    private byte[] LabeledExtractKem(byte[] salt, byte[] label, byte[] ikm) =>
        _hkdf.Extract(salt, BuildLabeledIkm(KemSuiteId, label, ikm));

    private byte[] LabeledExpandKem(byte[] prk, byte[] label, byte[] info, int length) =>
        _hkdf.Expand(prk, BuildLabeledInfo(KemSuiteId, label, info, length), length);

    private (byte[] key, byte[] baseNonce) KeyScheduleS(byte[] sharedSecret, byte[] info)
    {
        var mode = new byte[] { ModeBase };
        var pskIdHash = LabeledExtractHpke(EmptyBytes, PskIdHashLabel, EmptyBytes);
        var infoHash = LabeledExtractHpke(EmptyBytes, InfoHashLabel, info);
        var ksContext = Concat(mode, pskIdHash, infoHash);
        var secret = LabeledExtractHpke(sharedSecret, SecretLabel, EmptyBytes);
        var key = LabeledExpandHpke(secret, KeyLabel, ksContext, Nk);
        var baseNonce = LabeledExpandHpke(secret, BaseNonceLabel, ksContext, Nn);
        return (key, baseNonce);
    }

    private byte[] LabeledExtractHpke(byte[] salt, byte[] label, byte[] ikm) =>
        _hkdf.Extract(salt, BuildLabeledIkm(HpkeSuiteId, label, ikm));

    private byte[] LabeledExpandHpke(byte[] prk, byte[] label, byte[] info, int length) =>
        _hkdf.Expand(prk, BuildLabeledInfo(HpkeSuiteId, label, info, length), length);

    private static readonly byte[] HpkeV1Prefix = Encoding.ASCII.GetBytes("HPKE-v1");

    private static byte[] BuildLabeledIkm(byte[] suiteId, byte[] label, byte[] ikm)
    {
        var result = new byte[HpkeV1Prefix.Length + suiteId.Length + label.Length + ikm.Length];
        var offset = 0;
        Buffer.BlockCopy(HpkeV1Prefix, 0, result, offset, HpkeV1Prefix.Length); offset += HpkeV1Prefix.Length;
        Buffer.BlockCopy(suiteId, 0, result, offset, suiteId.Length); offset += suiteId.Length;
        Buffer.BlockCopy(label, 0, result, offset, label.Length); offset += label.Length;
        Buffer.BlockCopy(ikm, 0, result, offset, ikm.Length);
        return result;
    }

    private static byte[] BuildLabeledInfo(byte[] suiteId, byte[] label, byte[] info, int length)
    {
        var result = new byte[2 + HpkeV1Prefix.Length + suiteId.Length + label.Length + info.Length];
        var offset = 0;
        result[offset++] = (byte)(length >> 8);
        result[offset++] = (byte)(length & 0xFF);
        Buffer.BlockCopy(HpkeV1Prefix, 0, result, offset, HpkeV1Prefix.Length); offset += HpkeV1Prefix.Length;
        Buffer.BlockCopy(suiteId, 0, result, offset, suiteId.Length); offset += suiteId.Length;
        Buffer.BlockCopy(label, 0, result, offset, label.Length); offset += label.Length;
        Buffer.BlockCopy(info, 0, result, offset, info.Length);
        return result;
    }

    private static byte[] BuildKemSuiteId()
    {
        var prefix = Encoding.ASCII.GetBytes("KEM");
        var result = new byte[prefix.Length + 2];
        Buffer.BlockCopy(prefix, 0, result, 0, prefix.Length);
        result[prefix.Length] = (byte)(KemId >> 8);
        result[prefix.Length + 1] = (byte)(KemId & 0xFF);
        return result;
    }

    private static byte[] BuildHpkeSuiteId()
    {
        var prefix = Encoding.ASCII.GetBytes("HPKE");
        var result = new byte[prefix.Length + 6];
        var offset = prefix.Length;
        Buffer.BlockCopy(prefix, 0, result, 0, prefix.Length);
        result[offset++] = (byte)(KemId >> 8);  result[offset++] = (byte)(KemId & 0xFF);
        result[offset++] = (byte)(KdfId >> 8);  result[offset++] = (byte)(KdfId & 0xFF);
        result[offset++] = (byte)(AeadId >> 8); result[offset] = (byte)(AeadId & 0xFF);
        return result;
    }

    private static byte[] Concat(byte[] a, byte[] b)
    {
        var result = new byte[a.Length + b.Length];
        Buffer.BlockCopy(a, 0, result, 0, a.Length);
        Buffer.BlockCopy(b, 0, result, a.Length, b.Length);
        return result;
    }

    private static byte[] Concat(byte[] a, byte[] b, byte[] c)
    {
        var result = new byte[a.Length + b.Length + c.Length];
        var offset = 0;
        Buffer.BlockCopy(a, 0, result, offset, a.Length); offset += a.Length;
        Buffer.BlockCopy(b, 0, result, offset, b.Length); offset += b.Length;
        Buffer.BlockCopy(c, 0, result, offset, c.Length);
        return result;
    }
}
