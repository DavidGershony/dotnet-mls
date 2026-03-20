using System.Security.Cryptography;
using System.Text;

namespace DotnetMls.Crypto;

/// <summary>
/// MLS cipher suite 0x0003: MLS_128_DHKEMX25519_CHACHA20POLY1305_SHA256_Ed25519
///   - KEM: DHKEM(X25519, HKDF-SHA256)
///   - AEAD: ChaCha20-Poly1305
///   - Hash: SHA-256
///   - Signature: Ed25519
///
/// Identical to CipherSuite0x0001 except AEAD uses ChaCha20-Poly1305 (32-byte keys)
/// instead of AES-128-GCM (16-byte keys).
/// </summary>
public sealed class CipherSuite0x0003 : ICipherSuite
{
    private static readonly byte[] MlsLabelPrefix = Encoding.UTF8.GetBytes("MLS 1.0 ");

    private readonly HkdfProvider _hkdf;
    private readonly ChaCha20Poly1305Provider _aead;
    private readonly Ed25519Provider _signer;
    private readonly HpkeX25519ChaCha20 _hpke;

    public CipherSuite0x0003()
    {
        _hkdf = new HkdfProvider(HashAlgorithmName.SHA256);
        _aead = new ChaCha20Poly1305Provider();
        _signer = new Ed25519Provider();
        _hpke = new HpkeX25519ChaCha20(new X25519Provider(), _hkdf, _aead);
    }

    /// <inheritdoc />
    public ushort Id => 0x0003;

    /// <inheritdoc />
    public int HashSize => 32;

    /// <inheritdoc />
    public int AeadKeySize => 32; // ChaCha20-Poly1305 uses 256-bit keys

    /// <inheritdoc />
    public int AeadNonceSize => 12;

    /// <inheritdoc />
    public int SecretSize => 32;

    // ---- Hash ----

    /// <inheritdoc />
    public byte[] Hash(byte[] data) => SHA256.HashData(data);

    // ---- MAC ----

    /// <inheritdoc />
    public byte[] Mac(byte[] key, byte[] data) => HMACSHA256.HashData(key, data);

    /// <inheritdoc />
    public bool VerifyMac(byte[] key, byte[] data, byte[] mac)
    {
        var computed = Mac(key, data);
        return CryptographicOperations.FixedTimeEquals(computed, mac);
    }

    // ---- KDF (HKDF) ----

    /// <inheritdoc />
    public byte[] Extract(byte[] salt, byte[] ikm) => _hkdf.Extract(salt, ikm);

    /// <inheritdoc />
    public byte[] Expand(byte[] secret, byte[] info, int length) => _hkdf.Expand(secret, info, length);

    /// <inheritdoc />
    public byte[] ExpandWithLabel(byte[] secret, string label, byte[] context, int length)
    {
        var labelBytes = Encoding.UTF8.GetBytes(label);
        var fullLabel = new byte[MlsLabelPrefix.Length + labelBytes.Length];
        Buffer.BlockCopy(MlsLabelPrefix, 0, fullLabel, 0, MlsLabelPrefix.Length);
        Buffer.BlockCopy(labelBytes, 0, fullLabel, MlsLabelPrefix.Length, labelBytes.Length);

        var labelLenBytes = EncodeVarInt(fullLabel.Length);
        var contextLenBytes = EncodeVarInt(context.Length);

        var kdfLabel = new byte[2 + labelLenBytes.Length + fullLabel.Length + contextLenBytes.Length + context.Length];
        var offset = 0;

        kdfLabel[offset++] = (byte)(length >> 8);
        kdfLabel[offset++] = (byte)(length & 0xFF);

        Buffer.BlockCopy(labelLenBytes, 0, kdfLabel, offset, labelLenBytes.Length);
        offset += labelLenBytes.Length;
        Buffer.BlockCopy(fullLabel, 0, kdfLabel, offset, fullLabel.Length);
        offset += fullLabel.Length;

        Buffer.BlockCopy(contextLenBytes, 0, kdfLabel, offset, contextLenBytes.Length);
        offset += contextLenBytes.Length;
        Buffer.BlockCopy(context, 0, kdfLabel, offset, context.Length);

        return _hkdf.Expand(secret, kdfLabel, length);
    }

    /// <inheritdoc />
    public byte[] DeriveSecret(byte[] secret, string label) =>
        ExpandWithLabel(secret, label, Array.Empty<byte>(), HashSize);

    // ---- Ref Hash ----

    /// <inheritdoc />
    public byte[] RefHash(string label, byte[] content)
    {
        var labelBytes = Encoding.UTF8.GetBytes(label);
        var labelLenBytes = EncodeVarInt(labelBytes.Length);
        var contentLenBytes = EncodeVarInt(content.Length);

        var input = new byte[labelLenBytes.Length + labelBytes.Length + contentLenBytes.Length + content.Length];
        var offset = 0;

        Buffer.BlockCopy(labelLenBytes, 0, input, offset, labelLenBytes.Length); offset += labelLenBytes.Length;
        Buffer.BlockCopy(labelBytes, 0, input, offset, labelBytes.Length); offset += labelBytes.Length;
        Buffer.BlockCopy(contentLenBytes, 0, input, offset, contentLenBytes.Length); offset += contentLenBytes.Length;
        Buffer.BlockCopy(content, 0, input, offset, content.Length);

        return Hash(input);
    }

    // ---- AEAD ----

    /// <inheritdoc />
    public byte[] AeadEncrypt(byte[] key, byte[] nonce, byte[] aad, byte[] plaintext) =>
        _aead.Encrypt(key, nonce, aad, plaintext);

    /// <inheritdoc />
    public byte[] AeadDecrypt(byte[] key, byte[] nonce, byte[] aad, byte[] ciphertext) =>
        _aead.Decrypt(key, nonce, aad, ciphertext);

    // ---- Signatures ----

    /// <inheritdoc />
    public byte[] SignWithLabel(byte[] privateKey, string label, byte[] content)
    {
        var signContent = BuildSignContent(label, content);
        return _signer.Sign(privateKey, signContent);
    }

    /// <inheritdoc />
    public bool VerifyWithLabel(byte[] publicKey, string label, byte[] content, byte[] signature)
    {
        var signContent = BuildSignContent(label, content);
        return _signer.Verify(publicKey, signContent, signature);
    }

    /// <inheritdoc />
    public (byte[] privateKey, byte[] publicKey) GenerateSignatureKeyPair() => _signer.GenerateKeyPair();

    // ---- HPKE ----

    /// <inheritdoc />
    public (byte[] privateKey, byte[] publicKey) GenerateHpkeKeyPair() => _hpke.GenerateKeyPair();

    /// <inheritdoc />
    public (byte[] kem_output, byte[] shared_secret) HpkeEncap(byte[] publicKey) => _hpke.Encap(publicKey);

    /// <inheritdoc />
    public byte[] HpkeDecap(byte[] kem_output, byte[] privateKey) => _hpke.Decap(kem_output, privateKey);

    /// <inheritdoc />
    public byte[] HpkeSeal(byte[] publicKey, byte[] info, byte[] aad, byte[] plaintext) =>
        _hpke.Seal(publicKey, info, aad, plaintext);

    /// <inheritdoc />
    public byte[] HpkeOpen(byte[] privateKey, byte[] kem_output, byte[] info, byte[] aad, byte[] ciphertext) =>
        _hpke.Open(privateKey, kem_output, info, aad, ciphertext);

    // ---- Random ----

    /// <inheritdoc />
    public byte[] RandomBytes(int length)
    {
        var bytes = new byte[length];
        RandomNumberGenerator.Fill(bytes);
        return bytes;
    }

    // ---- Private helpers ----

    private static byte[] BuildSignContent(string label, byte[] content)
    {
        var labelBytes = Encoding.UTF8.GetBytes(label);
        var fullLabel = new byte[MlsLabelPrefix.Length + labelBytes.Length];
        Buffer.BlockCopy(MlsLabelPrefix, 0, fullLabel, 0, MlsLabelPrefix.Length);
        Buffer.BlockCopy(labelBytes, 0, fullLabel, MlsLabelPrefix.Length, labelBytes.Length);

        var fullLabelLen = EncodeVarInt(fullLabel.Length);
        var contentLen = EncodeVarInt(content.Length);

        var result = new byte[fullLabelLen.Length + fullLabel.Length + contentLen.Length + content.Length];
        var offset = 0;

        Buffer.BlockCopy(fullLabelLen, 0, result, offset, fullLabelLen.Length); offset += fullLabelLen.Length;
        Buffer.BlockCopy(fullLabel, 0, result, offset, fullLabel.Length); offset += fullLabel.Length;
        Buffer.BlockCopy(contentLen, 0, result, offset, contentLen.Length); offset += contentLen.Length;
        Buffer.BlockCopy(content, 0, result, offset, content.Length);

        return result;
    }

    private static byte[] EncodeVarInt(int length)
    {
        if (length <= 63)
            return new byte[] { (byte)length };
        if (length <= 16383)
            return new byte[] { (byte)(0x40 | (length >> 8)), (byte)(length & 0xFF) };
        if (length <= 1073741823)
            return new byte[]
            {
                (byte)(0x80 | (length >> 24)),
                (byte)((length >> 16) & 0xFF),
                (byte)((length >> 8) & 0xFF),
                (byte)(length & 0xFF)
            };
        throw new ArgumentOutOfRangeException(nameof(length), length, "VarInt length exceeds maximum (2^30 - 1).");
    }
}
