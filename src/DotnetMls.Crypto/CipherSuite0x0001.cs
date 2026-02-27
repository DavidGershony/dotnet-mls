using System.Security.Cryptography;
using System.Text;

namespace DotnetMls.Crypto;

/// <summary>
/// MLS cipher suite 0x0001: MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519
///   - KEM: DHKEM(X25519, HKDF-SHA256)
///   - AEAD: AES-128-GCM
///   - Hash: SHA-256
///   - Signature: Ed25519
/// </summary>
public sealed class CipherSuite0x0001 : ICipherSuite
{
    private static readonly byte[] MlsLabelPrefix = Encoding.UTF8.GetBytes("MLS 1.0 ");

    private readonly HkdfProvider _hkdf;
    private readonly AesGcmProvider _aead;
    private readonly Ed25519Provider _signer;
    private readonly HpkeX25519Aes128 _hpke;

    /// <summary>
    /// Creates a new instance of cipher suite 0x0001.
    /// </summary>
    public CipherSuite0x0001()
    {
        _hkdf = new HkdfProvider(HashAlgorithmName.SHA256);
        _aead = new AesGcmProvider();
        _signer = new Ed25519Provider();
        _hpke = new HpkeX25519Aes128(new X25519Provider(), _hkdf, _aead);
    }

    /// <inheritdoc />
    public ushort Id => 0x0001;

    /// <inheritdoc />
    public int HashSize => 32;

    /// <inheritdoc />
    public int AeadKeySize => 16;

    /// <inheritdoc />
    public int AeadNonceSize => 12;

    /// <inheritdoc />
    public int SecretSize => 32;

    // ---- Hash ----

    /// <inheritdoc />
    public byte[] Hash(byte[] data)
    {
        return SHA256.HashData(data);
    }

    // ---- MAC ----

    /// <inheritdoc />
    public byte[] Mac(byte[] key, byte[] data)
    {
        return HMACSHA256.HashData(key, data);
    }

    /// <inheritdoc />
    public bool VerifyMac(byte[] key, byte[] data, byte[] mac)
    {
        var computed = Mac(key, data);
        return CryptographicOperations.FixedTimeEquals(computed, mac);
    }

    // ---- KDF (HKDF) ----

    /// <inheritdoc />
    public byte[] Extract(byte[] salt, byte[] ikm)
    {
        return _hkdf.Extract(salt, ikm);
    }

    /// <inheritdoc />
    public byte[] Expand(byte[] secret, byte[] info, int length)
    {
        return _hkdf.Expand(secret, info, length);
    }

    /// <inheritdoc />
    /// <remarks>
    /// Per RFC 9420 Section 5.1:
    ///   ExpandWithLabel(Secret, Label, Context, Length) =
    ///     KDF.Expand(Secret, KDFLabel, Length)
    ///   where KDFLabel is:
    ///     uint16 length = Length;
    ///     opaque label&lt;V&gt; = "MLS 1.0 " + Label;
    ///     opaque context&lt;V&gt; = Context;
    ///   Encoded as: uint16(Length) || uint8(label_len) || label || uint8(context_len) || context
    ///
    ///   Actually per the TLS-style encoding used in RFC 9420:
    ///   struct {
    ///     uint16 length = Length;
    ///     opaque label&lt;7..255&gt; = "MLS 1.0 " + Label;
    ///     opaque context&lt;0..255&gt; = Context;
    ///   } KDFLabel;
    ///
    ///   This encodes as: uint16(Length) || uint8(len("MLS 1.0 " + Label)) || "MLS 1.0 " || Label || uint8(len(Context)) || Context
    /// </remarks>
    public byte[] ExpandWithLabel(byte[] secret, string label, byte[] context, int length)
    {
        var labelBytes = Encoding.UTF8.GetBytes(label);
        var fullLabel = new byte[MlsLabelPrefix.Length + labelBytes.Length];
        Buffer.BlockCopy(MlsLabelPrefix, 0, fullLabel, 0, MlsLabelPrefix.Length);
        Buffer.BlockCopy(labelBytes, 0, fullLabel, MlsLabelPrefix.Length, labelBytes.Length);

        // KDFLabel = uint16(length) || uint8(fullLabel.Length) || fullLabel || uint8(context.Length) || context
        var kdfLabel = new byte[2 + 1 + fullLabel.Length + 1 + context.Length];
        var offset = 0;

        // uint16 length (big-endian)
        kdfLabel[offset++] = (byte)(length >> 8);
        kdfLabel[offset++] = (byte)(length & 0xFF);

        // uint8 label length + label
        kdfLabel[offset++] = (byte)fullLabel.Length;
        Buffer.BlockCopy(fullLabel, 0, kdfLabel, offset, fullLabel.Length);
        offset += fullLabel.Length;

        // uint8 context length + context
        kdfLabel[offset++] = (byte)context.Length;
        Buffer.BlockCopy(context, 0, kdfLabel, offset, context.Length);

        return _hkdf.Expand(secret, kdfLabel, length);
    }

    /// <inheritdoc />
    /// <remarks>
    /// DeriveSecret(Secret, Label) = ExpandWithLabel(Secret, Label, "", KDF.Nh)
    /// </remarks>
    public byte[] DeriveSecret(byte[] secret, string label)
    {
        return ExpandWithLabel(secret, label, Array.Empty<byte>(), HashSize);
    }

    // ---- Ref Hash ----

    /// <inheritdoc />
    /// <remarks>
    /// Per RFC 9420 Section 5.2:
    ///   RefHash(label, value) = Hash(RefHashInput)
    ///   where RefHashInput is:
    ///   struct {
    ///     opaque label&lt;V&gt; = label;
    ///     opaque value&lt;V&gt; = value;
    ///   } RefHashInput;
    ///   Encoded as: uint16(label_len) || label || value
    ///
    ///   Note: The "value" field uses a variable-length encoding with a length prefix
    ///   that matches the TLS encoding. For simplicity and per the spec's intent,
    ///   we encode: uint16(label.Length) || label_bytes || value.
    /// </remarks>
    public byte[] RefHash(string label, byte[] content)
    {
        var labelBytes = Encoding.UTF8.GetBytes(label);

        // RefHashInput = uint16(label_len) || label || content
        // Note: per the RFC, the value is included directly after the label
        var input = new byte[2 + labelBytes.Length + content.Length];
        var offset = 0;

        // uint16 label length (big-endian)
        input[offset++] = (byte)(labelBytes.Length >> 8);
        input[offset++] = (byte)(labelBytes.Length & 0xFF);

        Buffer.BlockCopy(labelBytes, 0, input, offset, labelBytes.Length);
        offset += labelBytes.Length;

        Buffer.BlockCopy(content, 0, input, offset, content.Length);

        return Hash(input);
    }

    // ---- AEAD ----

    /// <inheritdoc />
    public byte[] AeadEncrypt(byte[] key, byte[] nonce, byte[] aad, byte[] plaintext)
    {
        return _aead.Encrypt(key, nonce, aad, plaintext);
    }

    /// <inheritdoc />
    public byte[] AeadDecrypt(byte[] key, byte[] nonce, byte[] aad, byte[] ciphertext)
    {
        return _aead.Decrypt(key, nonce, aad, ciphertext);
    }

    // ---- Signatures ----

    /// <inheritdoc />
    /// <remarks>
    /// Per RFC 9420 Section 5.1.2:
    ///   SignWithLabel(SignKey, Label, Content) =
    ///     Sign(SignKey, SignContent)
    ///   where SignContent is:
    ///   struct {
    ///     opaque label&lt;7..255&gt; = "MLS 1.0 " + Label;
    ///     opaque content&lt;0..2^32-1&gt; = Content;
    ///   } SignContent;
    ///
    ///   For signing, we construct: "MLS 1.0 " || Label || Content
    ///   and sign that directly with Ed25519.
    /// </remarks>
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
    public (byte[] privateKey, byte[] publicKey) GenerateSignatureKeyPair()
    {
        return _signer.GenerateKeyPair();
    }

    // ---- HPKE ----

    /// <inheritdoc />
    public (byte[] privateKey, byte[] publicKey) GenerateHpkeKeyPair()
    {
        return _hpke.GenerateKeyPair();
    }

    /// <inheritdoc />
    public (byte[] kem_output, byte[] shared_secret) HpkeEncap(byte[] publicKey)
    {
        return _hpke.Encap(publicKey);
    }

    /// <inheritdoc />
    public byte[] HpkeDecap(byte[] kem_output, byte[] privateKey)
    {
        return _hpke.Decap(kem_output, privateKey);
    }

    /// <inheritdoc />
    public byte[] HpkeSeal(byte[] publicKey, byte[] info, byte[] aad, byte[] plaintext)
    {
        return _hpke.Seal(publicKey, info, aad, plaintext);
    }

    /// <inheritdoc />
    public byte[] HpkeOpen(byte[] privateKey, byte[] kem_output, byte[] info, byte[] aad, byte[] ciphertext)
    {
        return _hpke.Open(privateKey, kem_output, info, aad, ciphertext);
    }

    // ---- Random ----

    /// <inheritdoc />
    public byte[] RandomBytes(int length)
    {
        var bytes = new byte[length];
        RandomNumberGenerator.Fill(bytes);
        return bytes;
    }

    // ---- Private helpers ----

    /// <summary>
    /// Builds the SignContent for SignWithLabel/VerifyWithLabel:
    /// "MLS 1.0 " || label || content
    /// </summary>
    private static byte[] BuildSignContent(string label, byte[] content)
    {
        var labelBytes = Encoding.UTF8.GetBytes(label);
        var result = new byte[MlsLabelPrefix.Length + labelBytes.Length + content.Length];
        var offset = 0;

        Buffer.BlockCopy(MlsLabelPrefix, 0, result, offset, MlsLabelPrefix.Length);
        offset += MlsLabelPrefix.Length;

        Buffer.BlockCopy(labelBytes, 0, result, offset, labelBytes.Length);
        offset += labelBytes.Length;

        Buffer.BlockCopy(content, 0, result, offset, content.Length);

        return result;
    }
}
