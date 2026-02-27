using DotnetMls.Codec;

namespace DotnetMls.Types;

/// <summary>
/// A node in an UpdatePath containing an encryption key and encrypted path secrets
/// (RFC 9420 Section 7.6).
/// </summary>
public sealed class UpdatePathNode
{
    /// <summary>
    /// The HPKE public key for this node.
    /// </summary>
    public byte[] EncryptionKey { get; set; } = Array.Empty<byte>();

    /// <summary>
    /// The encrypted path secrets, one per resolution member.
    /// Each entry is an HPKECiphertext.
    /// </summary>
    public HpkeCiphertext[] EncryptedPathSecret { get; set; } = Array.Empty<HpkeCiphertext>();

    public UpdatePathNode()
    {
    }

    public UpdatePathNode(byte[] encryptionKey, HpkeCiphertext[] encryptedPathSecret)
    {
        EncryptionKey = encryptionKey;
        EncryptedPathSecret = encryptedPathSecret;
    }

    public void WriteTo(TlsWriter writer)
    {
        writer.WriteOpaqueV(EncryptionKey);

        writer.WriteVectorV(inner =>
        {
            foreach (var ct in EncryptedPathSecret)
            {
                ct.WriteTo(inner);
            }
        });
    }

    public static UpdatePathNode ReadFrom(TlsReader reader)
    {
        byte[] encryptionKey = reader.ReadOpaqueV();

        byte[] secretsData = reader.ReadOpaqueV();
        var secrets = new List<HpkeCiphertext>();
        if (secretsData.Length > 0)
        {
            var secretsReader = new TlsReader(secretsData);
            while (!secretsReader.IsEmpty)
            {
                secrets.Add(HpkeCiphertext.ReadFrom(secretsReader));
            }
        }

        return new UpdatePathNode(encryptionKey, secrets.ToArray());
    }
}
