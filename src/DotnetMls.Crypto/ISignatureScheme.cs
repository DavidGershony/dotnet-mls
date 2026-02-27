namespace DotnetMls.Crypto;

/// <summary>
/// Interface for digital signature schemes used by MLS.
/// </summary>
public interface ISignatureScheme
{
    /// <summary>
    /// Generates a new signature key pair.
    /// </summary>
    (byte[] privateKey, byte[] publicKey) GenerateKeyPair();

    /// <summary>
    /// Signs a message using the private key.
    /// </summary>
    byte[] Sign(byte[] privateKey, byte[] message);

    /// <summary>
    /// Verifies a signature against a message using the public key.
    /// </summary>
    bool Verify(byte[] publicKey, byte[] message, byte[] signature);
}
