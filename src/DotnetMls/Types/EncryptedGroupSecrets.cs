using DotnetMls.Codec;

namespace DotnetMls.Types;

/// <summary>
/// Encrypted group secrets for a specific new member in a Welcome message
/// (RFC 9420 Section 12.4.3.1).
/// </summary>
public sealed class EncryptedGroupSecrets
{
    /// <summary>
    /// The KeyPackage reference identifying the target new member.
    /// </summary>
    public byte[] NewMember { get; set; } = Array.Empty<byte>();

    /// <summary>
    /// The HPKE-encrypted group secrets.
    /// </summary>
    public HpkeCiphertext EncryptedGroupSecretsValue { get; set; } = new HpkeCiphertext();

    public EncryptedGroupSecrets()
    {
    }

    public EncryptedGroupSecrets(byte[] newMember, HpkeCiphertext encryptedGroupSecrets)
    {
        NewMember = newMember;
        EncryptedGroupSecretsValue = encryptedGroupSecrets;
    }

    public void WriteTo(TlsWriter writer)
    {
        writer.WriteOpaqueV(NewMember);
        EncryptedGroupSecretsValue.WriteTo(writer);
    }

    public static EncryptedGroupSecrets ReadFrom(TlsReader reader)
    {
        byte[] newMember = reader.ReadOpaqueV();
        var encryptedGroupSecrets = HpkeCiphertext.ReadFrom(reader);
        return new EncryptedGroupSecrets(newMember, encryptedGroupSecrets);
    }
}
