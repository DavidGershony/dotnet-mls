namespace DotnetMls.Crypto;

/// <summary>
/// Defines the cryptographic operations for an MLS cipher suite (RFC 9420).
/// </summary>
public interface ICipherSuite
{
    /// <summary>
    /// The IANA-registered cipher suite identifier.
    /// </summary>
    ushort Id { get; }

    /// <summary>
    /// The output size of the hash function in bytes.
    /// </summary>
    int HashSize { get; }

    /// <summary>
    /// The AEAD key size in bytes.
    /// </summary>
    int AeadKeySize { get; }

    /// <summary>
    /// The AEAD nonce size in bytes.
    /// </summary>
    int AeadNonceSize { get; }

    /// <summary>
    /// The secret size in bytes (typically equal to HashSize).
    /// </summary>
    int SecretSize { get; }

    // ---- Hash ----

    /// <summary>
    /// Computes the hash of the given data.
    /// </summary>
    byte[] Hash(byte[] data);

    // ---- MAC ----

    /// <summary>
    /// Computes an HMAC over the given data with the specified key.
    /// </summary>
    byte[] Mac(byte[] key, byte[] data);

    /// <summary>
    /// Verifies an HMAC over the given data with the specified key.
    /// </summary>
    bool VerifyMac(byte[] key, byte[] data, byte[] mac);

    // ---- KDF (HKDF) ----

    /// <summary>
    /// HKDF-Extract: derives a pseudorandom key from salt and input keying material.
    /// </summary>
    byte[] Extract(byte[] salt, byte[] ikm);

    /// <summary>
    /// HKDF-Expand: expands a pseudorandom key to the desired length using info.
    /// </summary>
    byte[] Expand(byte[] secret, byte[] info, int length);

    /// <summary>
    /// MLS ExpandWithLabel (RFC 9420 Section 5.1):
    /// HKDF-Expand with MLS-formatted info = uint16(length) || "MLS 1.0 " || label || uint8(context.Length) || context.
    /// </summary>
    byte[] ExpandWithLabel(byte[] secret, string label, byte[] context, int length);

    /// <summary>
    /// MLS DeriveSecret: ExpandWithLabel with empty context and output length = HashSize.
    /// </summary>
    byte[] DeriveSecret(byte[] secret, string label);

    // ---- Ref Hash ----

    /// <summary>
    /// MLS RefHash (RFC 9420 Section 5.2):
    /// Hash(VarInt(label_len) || label || VarInt(value_len) || value).
    /// </summary>
    byte[] RefHash(string label, byte[] content);

    // ---- AEAD ----

    /// <summary>
    /// AEAD encryption. Returns ciphertext with appended authentication tag.
    /// </summary>
    byte[] AeadEncrypt(byte[] key, byte[] nonce, byte[] aad, byte[] plaintext);

    /// <summary>
    /// AEAD decryption. Input ciphertext includes the appended authentication tag.
    /// </summary>
    byte[] AeadDecrypt(byte[] key, byte[] nonce, byte[] aad, byte[] ciphertext);

    // ---- Signatures ----

    /// <summary>
    /// Signs content per RFC 9420 §5.1.2:
    /// Sign(VarInt(label_len) || "MLS 1.0 " + label || VarInt(content_len) || content).
    /// </summary>
    byte[] SignWithLabel(byte[] privateKey, string label, byte[] content);

    /// <summary>
    /// Verifies a signature per RFC 9420 §5.1.2:
    /// Verify(VarInt(label_len) || "MLS 1.0 " + label || VarInt(content_len) || content, sig).
    /// </summary>
    bool VerifyWithLabel(byte[] publicKey, string label, byte[] content, byte[] signature);

    /// <summary>
    /// Generates a signature key pair.
    /// </summary>
    (byte[] privateKey, byte[] publicKey) GenerateSignatureKeyPair();

    // ---- HPKE ----

    /// <summary>
    /// Generates an HPKE key pair (KEM key pair).
    /// </summary>
    (byte[] privateKey, byte[] publicKey) GenerateHpkeKeyPair();

    /// <summary>
    /// HPKE KEM Encap: generates a shared secret and KEM output for the given public key.
    /// </summary>
    (byte[] kem_output, byte[] shared_secret) HpkeEncap(byte[] publicKey);

    /// <summary>
    /// HPKE KEM Decap: recovers the shared secret from KEM output and private key.
    /// </summary>
    byte[] HpkeDecap(byte[] kem_output, byte[] privateKey);

    /// <summary>
    /// HPKE single-shot Seal: encrypts plaintext for the given public key.
    /// Returns kem_output prepended to the AEAD ciphertext.
    /// </summary>
    byte[] HpkeSeal(byte[] publicKey, byte[] info, byte[] aad, byte[] plaintext);

    /// <summary>
    /// HPKE single-shot Open: decrypts ciphertext using the private key and KEM output.
    /// </summary>
    byte[] HpkeOpen(byte[] privateKey, byte[] kem_output, byte[] info, byte[] aad, byte[] ciphertext);

    // ---- Random ----

    /// <summary>
    /// Generates cryptographically secure random bytes.
    /// </summary>
    byte[] RandomBytes(int length);
}
