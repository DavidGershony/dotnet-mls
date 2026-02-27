using DotnetMls.Codec;

namespace DotnetMls.Types;

/// <summary>
/// Capabilities of a leaf node, advertising supported protocol features
/// (RFC 9420 Section 7.2).
/// </summary>
public sealed class Capabilities
{
    /// <summary>
    /// Supported protocol versions.
    /// </summary>
    public ushort[] Versions { get; set; } = Array.Empty<ushort>();

    /// <summary>
    /// Supported cipher suites.
    /// </summary>
    public ushort[] CipherSuites { get; set; } = Array.Empty<ushort>();

    /// <summary>
    /// Supported extension types.
    /// </summary>
    public ushort[] Extensions { get; set; } = Array.Empty<ushort>();

    /// <summary>
    /// Supported proposal types.
    /// </summary>
    public ushort[] Proposals { get; set; } = Array.Empty<ushort>();

    /// <summary>
    /// Supported credential types.
    /// </summary>
    public ushort[] Credentials { get; set; } = Array.Empty<ushort>();

    public Capabilities()
    {
    }

    public void WriteTo(TlsWriter writer)
    {
        WriteUint16Vector(writer, Versions);
        WriteUint16Vector(writer, CipherSuites);
        WriteUint16Vector(writer, Extensions);
        WriteUint16Vector(writer, Proposals);
        WriteUint16Vector(writer, Credentials);
    }

    public static Capabilities ReadFrom(TlsReader reader)
    {
        return new Capabilities
        {
            Versions = ReadUint16Vector(reader),
            CipherSuites = ReadUint16Vector(reader),
            Extensions = ReadUint16Vector(reader),
            Proposals = ReadUint16Vector(reader),
            Credentials = ReadUint16Vector(reader),
        };
    }

    private static void WriteUint16Vector(TlsWriter writer, ushort[] values)
    {
        writer.WriteVectorV(inner =>
        {
            foreach (ushort v in values)
            {
                inner.WriteUint16(v);
            }
        });
    }

    private static ushort[] ReadUint16Vector(TlsReader reader)
    {
        byte[] data = reader.ReadOpaqueV();
        if (data.Length % 2 != 0)
        {
            throw new TlsDecodingException("Capabilities vector length is not a multiple of 2");
        }

        var result = new ushort[data.Length / 2];
        var vectorReader = new TlsReader(data);
        for (int i = 0; i < result.Length; i++)
        {
            result[i] = vectorReader.ReadUint16();
        }
        return result;
    }
}
