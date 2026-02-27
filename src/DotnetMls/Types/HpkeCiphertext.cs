using DotnetMls.Codec;

namespace DotnetMls.Types;

/// <summary>
/// An HPKE ciphertext consisting of KEM output and ciphertext
/// (RFC 9420 Section 5.1.1).
/// </summary>
public sealed class HpkeCiphertext
{
    /// <summary>
    /// The KEM output (encapsulated key).
    /// </summary>
    public byte[] KemOutput { get; set; } = Array.Empty<byte>();

    /// <summary>
    /// The AEAD ciphertext.
    /// </summary>
    public byte[] Ciphertext { get; set; } = Array.Empty<byte>();

    public HpkeCiphertext()
    {
    }

    public HpkeCiphertext(byte[] kemOutput, byte[] ciphertext)
    {
        KemOutput = kemOutput;
        Ciphertext = ciphertext;
    }

    public void WriteTo(TlsWriter writer)
    {
        writer.WriteOpaqueV(KemOutput);
        writer.WriteOpaqueV(Ciphertext);
    }

    public static HpkeCiphertext ReadFrom(TlsReader reader)
    {
        byte[] kemOutput = reader.ReadOpaqueV();
        byte[] ciphertext = reader.ReadOpaqueV();
        return new HpkeCiphertext(kemOutput, ciphertext);
    }
}
