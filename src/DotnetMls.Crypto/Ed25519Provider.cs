using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Crypto.Signers;
using Org.BouncyCastle.Security;

namespace DotnetMls.Crypto;

/// <summary>
/// Ed25519 digital signature provider using BouncyCastle.
/// Implements ISignatureScheme for use with MLS cipher suites.
/// </summary>
public sealed class Ed25519Provider : ISignatureScheme
{
    private static readonly SecureRandom Rng = new();

    /// <inheritdoc />
    public (byte[] privateKey, byte[] publicKey) GenerateKeyPair()
    {
        var generator = new Ed25519KeyPairGenerator();
        generator.Init(new Ed25519KeyGenerationParameters(Rng));
        var keyPair = generator.GenerateKeyPair();

        var privateKeyParams = (Ed25519PrivateKeyParameters)keyPair.Private;
        var publicKeyParams = (Ed25519PublicKeyParameters)keyPair.Public;

        var privateKey = new byte[Ed25519PrivateKeyParameters.KeySize];
        var publicKey = new byte[Ed25519PublicKeyParameters.KeySize];

        privateKeyParams.Encode(privateKey, 0);
        publicKeyParams.Encode(publicKey, 0);

        return (privateKey, publicKey);
    }

    /// <inheritdoc />
    public byte[] Sign(byte[] privateKey, byte[] message)
    {
        var privateKeyParams = new Ed25519PrivateKeyParameters(privateKey, 0);

        var signer = new Ed25519Signer();
        signer.Init(forSigning: true, privateKeyParams);
        signer.BlockUpdate(message, 0, message.Length);

        return signer.GenerateSignature();
    }

    /// <inheritdoc />
    public bool Verify(byte[] publicKey, byte[] message, byte[] signature)
    {
        var publicKeyParams = new Ed25519PublicKeyParameters(publicKey, 0);

        var verifier = new Ed25519Signer();
        verifier.Init(forSigning: false, publicKeyParams);
        verifier.BlockUpdate(message, 0, message.Length);

        return verifier.VerifySignature(signature);
    }
}
