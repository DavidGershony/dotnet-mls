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
    // Managed RFC 5869 §2.3 implementation. Avoids System.Security.Cryptography.HKDF.Expand,
    // which throws CryptographicException on Linux + .NET 9 + OpenSSL 3.x.
    public byte[] Expand(byte[] prk, byte[] info, int length)
    {
        ArgumentNullException.ThrowIfNull(prk);
        ArgumentNullException.ThrowIfNull(info);
        if (length <= 0)
            throw new ArgumentOutOfRangeException(nameof(length), "Length must be positive.");

        int hashLen = HashLength(_hashAlgorithm);
        if (length > 255 * hashLen)
            throw new ArgumentOutOfRangeException(nameof(length), $"Length must be <= {255 * hashLen} for {_hashAlgorithm}.");

        int n = (length + hashLen - 1) / hashLen;
        byte[] output = new byte[length];
        byte[] previousBlock = [];
        byte[] hmacInput = new byte[hashLen + info.Length + 1];

        for (int i = 1; i <= n; i++)
        {
            int inputLen = previousBlock.Length + info.Length + 1;
            Buffer.BlockCopy(previousBlock, 0, hmacInput, 0, previousBlock.Length);
            Buffer.BlockCopy(info, 0, hmacInput, previousBlock.Length, info.Length);
            hmacInput[inputLen - 1] = (byte)i;

            previousBlock = HmacHash(_hashAlgorithm, prk, hmacInput.AsSpan(0, inputLen));

            int copyLen = Math.Min(hashLen, length - (i - 1) * hashLen);
            Buffer.BlockCopy(previousBlock, 0, output, (i - 1) * hashLen, copyLen);
        }

        return output;
    }

    /// <summary>
    /// Convenience for HKDF-Expand with SHA-256. Equivalent to <c>new HkdfProvider().Expand(prk, info, length)</c>.
    /// </summary>
    public static byte[] ExpandSha256(byte[] prk, byte[] info, int length)
        => new HkdfProvider(HashAlgorithmName.SHA256).Expand(prk, info, length);

    private static int HashLength(HashAlgorithmName name)
    {
        if (name == HashAlgorithmName.SHA256) return 32;
        if (name == HashAlgorithmName.SHA384) return 48;
        if (name == HashAlgorithmName.SHA512) return 64;
        if (name == HashAlgorithmName.SHA1) return 20;
        throw new NotSupportedException($"Hash algorithm {name} is not supported by HkdfProvider.");
    }

    private static byte[] HmacHash(HashAlgorithmName name, byte[] key, ReadOnlySpan<byte> data)
    {
        if (name == HashAlgorithmName.SHA256) return HMACSHA256.HashData(key, data);
        if (name == HashAlgorithmName.SHA384) return HMACSHA384.HashData(key, data);
        if (name == HashAlgorithmName.SHA512) return HMACSHA512.HashData(key, data);
        if (name == HashAlgorithmName.SHA1) return HMACSHA1.HashData(key, data);
        throw new NotSupportedException($"Hash algorithm {name} is not supported by HkdfProvider.");
    }
}
