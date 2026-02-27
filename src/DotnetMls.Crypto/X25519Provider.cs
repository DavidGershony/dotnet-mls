using Org.BouncyCastle.Crypto.Agreement;
using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Security;

namespace DotnetMls.Crypto;

/// <summary>
/// X25519 Diffie-Hellman key exchange provider using BouncyCastle.
/// Provides key generation and shared secret derivation for DHKEM.
/// </summary>
public sealed class X25519Provider
{
    private static readonly SecureRandom Rng = new();

    /// <summary>
    /// Generates a new X25519 key pair.
    /// </summary>
    /// <returns>A tuple of (32-byte private key, 32-byte public key).</returns>
    public (byte[] privateKey, byte[] publicKey) GenerateKeyPair()
    {
        var generator = new X25519KeyPairGenerator();
        generator.Init(new X25519KeyGenerationParameters(Rng));
        var keyPair = generator.GenerateKeyPair();

        var privateKeyParams = (X25519PrivateKeyParameters)keyPair.Private;
        var publicKeyParams = (X25519PublicKeyParameters)keyPair.Public;

        var privateKey = new byte[X25519PrivateKeyParameters.KeySize];
        var publicKey = new byte[X25519PublicKeyParameters.KeySize];

        privateKeyParams.Encode(privateKey, 0);
        publicKeyParams.Encode(publicKey, 0);

        return (privateKey, publicKey);
    }

    /// <summary>
    /// Derives a shared secret from a private key and a peer's public key using X25519.
    /// </summary>
    /// <param name="privateKey">The 32-byte private key.</param>
    /// <param name="publicKey">The peer's 32-byte public key.</param>
    /// <returns>The 32-byte shared secret.</returns>
    public byte[] DeriveSharedSecret(byte[] privateKey, byte[] publicKey)
    {
        var privateKeyParams = new X25519PrivateKeyParameters(privateKey, 0);
        var publicKeyParams = new X25519PublicKeyParameters(publicKey, 0);

        var agreement = new X25519Agreement();
        agreement.Init(privateKeyParams);

        var sharedSecret = new byte[agreement.AgreementSize];
        agreement.CalculateAgreement(publicKeyParams, sharedSecret, 0);

        return sharedSecret;
    }

    /// <summary>
    /// Derives the public key from a private key.
    /// </summary>
    /// <param name="privateKey">The 32-byte private key.</param>
    /// <returns>The corresponding 32-byte public key.</returns>
    public byte[] GetPublicKey(byte[] privateKey)
    {
        var privateKeyParams = new X25519PrivateKeyParameters(privateKey, 0);
        var publicKeyParams = privateKeyParams.GeneratePublicKey();

        var publicKey = new byte[X25519PublicKeyParameters.KeySize];
        publicKeyParams.Encode(publicKey, 0);

        return publicKey;
    }
}
