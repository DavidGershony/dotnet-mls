using System.Security.Cryptography;

namespace DotnetMls.Crypto;

/// <summary>
/// HKDF (HMAC-based Key Derivation Function) provider using System.Security.Cryptography.
/// Uses SHA-256 as the underlying hash algorithm.
/// </summary>
public sealed class HkdfProvider
{
    private readonly HashAlgorithmName _hashAlgorithm;

    /// <summary>
    /// Creates an HkdfProvider with the specified hash algorithm.
    /// </summary>
    /// <param name="hashAlgorithm">The hash algorithm to use (e.g., SHA256).</param>
    public HkdfProvider(HashAlgorithmName hashAlgorithm)
    {
        _hashAlgorithm = hashAlgorithm;
    }

    /// <summary>
    /// Creates an HkdfProvider using SHA-256.
    /// </summary>
    public HkdfProvider() : this(HashAlgorithmName.SHA256)
    {
    }

    /// <summary>
    /// HKDF-Extract: derives a pseudorandom key from salt and input keying material.
    /// </summary>
    /// <param name="salt">Optional salt value (can be empty, in which case a zero-filled salt of HashLen is used).</param>
    /// <param name="ikm">Input keying material.</param>
    /// <returns>A pseudorandom key (PRK) of HashLen bytes.</returns>
    public byte[] Extract(byte[] salt, byte[] ikm)
    {
        return HKDF.Extract(_hashAlgorithm, ikm, salt);
    }

    /// <summary>
    /// HKDF-Expand: expands a pseudorandom key to the desired output length.
    /// </summary>
    /// <param name="prk">A pseudorandom key of at least HashLen bytes.</param>
    /// <param name="info">Context and application-specific information.</param>
    /// <param name="length">The desired output length in bytes.</param>
    /// <returns>Output keying material of the specified length.</returns>
    public byte[] Expand(byte[] prk, byte[] info, int length)
    {
        return HKDF.Expand(_hashAlgorithm, prk, length, info);
    }
}
