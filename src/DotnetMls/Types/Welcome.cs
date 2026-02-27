using DotnetMls.Codec;

namespace DotnetMls.Types;

/// <summary>
/// A Welcome message used to onboard new members to a group
/// (RFC 9420 Section 12.4.3.1).
/// </summary>
public sealed class Welcome
{
    /// <summary>
    /// The cipher suite used by the group.
    /// </summary>
    public ushort CipherSuite { get; set; }

    /// <summary>
    /// Per-member encrypted group secrets.
    /// </summary>
    public EncryptedGroupSecrets[] Secrets { get; set; } = Array.Empty<EncryptedGroupSecrets>();

    /// <summary>
    /// The encrypted GroupInfo.
    /// </summary>
    public byte[] EncryptedGroupInfo { get; set; } = Array.Empty<byte>();

    public Welcome()
    {
    }

    public Welcome(ushort cipherSuite, EncryptedGroupSecrets[] secrets, byte[] encryptedGroupInfo)
    {
        CipherSuite = cipherSuite;
        Secrets = secrets;
        EncryptedGroupInfo = encryptedGroupInfo;
    }

    public void WriteTo(TlsWriter writer)
    {
        writer.WriteUint16(CipherSuite);

        writer.WriteVectorV(inner =>
        {
            foreach (var s in Secrets)
            {
                s.WriteTo(inner);
            }
        });

        writer.WriteOpaqueV(EncryptedGroupInfo);
    }

    public static Welcome ReadFrom(TlsReader reader)
    {
        ushort cipherSuite = reader.ReadUint16();

        byte[] secretsData = reader.ReadOpaqueV();
        var secrets = new List<EncryptedGroupSecrets>();
        if (secretsData.Length > 0)
        {
            var secretsReader = new TlsReader(secretsData);
            while (!secretsReader.IsEmpty)
            {
                secrets.Add(EncryptedGroupSecrets.ReadFrom(secretsReader));
            }
        }

        byte[] encryptedGroupInfo = reader.ReadOpaqueV();

        return new Welcome(cipherSuite, secrets.ToArray(), encryptedGroupInfo);
    }
}
