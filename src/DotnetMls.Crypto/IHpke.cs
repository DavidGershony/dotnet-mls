namespace DotnetMls.Crypto;

/// <summary>
/// HPKE (Hybrid Public Key Encryption) interface per RFC 9180.
/// Provides KEM operations and single-shot AEAD seal/open.
/// </summary>
public interface IHpke
{
    /// <summary>
    /// Generates a KEM key pair.
    /// </summary>
    (byte[] privateKey, byte[] publicKey) GenerateKeyPair();

    /// <summary>
    /// KEM Encap: generates a KEM output and shared secret for the recipient's public key.
    /// </summary>
    (byte[] kemOutput, byte[] sharedSecret) Encap(byte[] recipientPublicKey);

    /// <summary>
    /// KEM Decap: recovers the shared secret from the KEM output using the recipient's private key.
    /// </summary>
    byte[] Decap(byte[] kemOutput, byte[] recipientPrivateKey);

    /// <summary>
    /// Single-shot HPKE Seal: encrypts plaintext for the recipient.
    /// Returns kem_output prepended to the AEAD ciphertext (including tag).
    /// </summary>
    byte[] Seal(byte[] recipientPublicKey, byte[] info, byte[] aad, byte[] plaintext);

    /// <summary>
    /// Single-shot HPKE Open: decrypts ciphertext from the sender.
    /// The kemOutput is the KEM encapsulation from the sender.
    /// The ciphertext includes the AEAD authentication tag.
    /// </summary>
    byte[] Open(byte[] recipientPrivateKey, byte[] kemOutput, byte[] info, byte[] aad, byte[] ciphertext);
}
