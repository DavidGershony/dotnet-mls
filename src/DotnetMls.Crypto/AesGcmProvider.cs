using System.Security.Cryptography;

namespace DotnetMls.Crypto;

/// <summary>
/// AES-GCM AEAD encryption provider using System.Security.Cryptography.
/// Tag size is fixed at 16 bytes (128 bits).
/// </summary>
public sealed class AesGcmProvider
{
    /// <summary>
    /// The authentication tag size in bytes.
    /// </summary>
    public const int TagSize = 16;

    /// <summary>
    /// Encrypts plaintext using AES-GCM.
    /// </summary>
    /// <param name="key">The encryption key (16 or 32 bytes).</param>
    /// <param name="nonce">The nonce (12 bytes for AES-GCM).</param>
    /// <param name="aad">Additional authenticated data.</param>
    /// <param name="plaintext">The plaintext to encrypt.</param>
    /// <returns>Ciphertext with authentication tag appended (ciphertext || tag).</returns>
    public byte[] Encrypt(byte[] key, byte[] nonce, byte[] aad, byte[] plaintext)
    {
        var ciphertext = new byte[plaintext.Length];
        var tag = new byte[TagSize];

        using var aesGcm = new AesGcm(key, TagSize);
        aesGcm.Encrypt(nonce, plaintext, ciphertext, tag, aad);

        // Return ciphertext || tag
        var result = new byte[ciphertext.Length + TagSize];
        Buffer.BlockCopy(ciphertext, 0, result, 0, ciphertext.Length);
        Buffer.BlockCopy(tag, 0, result, ciphertext.Length, TagSize);

        return result;
    }

    /// <summary>
    /// Decrypts ciphertext using AES-GCM.
    /// </summary>
    /// <param name="key">The encryption key (16 or 32 bytes).</param>
    /// <param name="nonce">The nonce (12 bytes for AES-GCM).</param>
    /// <param name="aad">Additional authenticated data.</param>
    /// <param name="ciphertextWithTag">The ciphertext with authentication tag appended.</param>
    /// <returns>The decrypted plaintext.</returns>
    /// <exception cref="CryptographicException">Thrown if authentication fails.</exception>
    public byte[] Decrypt(byte[] key, byte[] nonce, byte[] aad, byte[] ciphertextWithTag)
    {
        if (ciphertextWithTag.Length < TagSize)
            throw new CryptographicException("Ciphertext is too short to contain an authentication tag.");

        var ciphertextLength = ciphertextWithTag.Length - TagSize;
        var ciphertext = new byte[ciphertextLength];
        var tag = new byte[TagSize];

        Buffer.BlockCopy(ciphertextWithTag, 0, ciphertext, 0, ciphertextLength);
        Buffer.BlockCopy(ciphertextWithTag, ciphertextLength, tag, 0, TagSize);

        var plaintext = new byte[ciphertextLength];

        using var aesGcm = new AesGcm(key, TagSize);
        aesGcm.Decrypt(nonce, ciphertext, tag, plaintext, aad);

        return plaintext;
    }
}
