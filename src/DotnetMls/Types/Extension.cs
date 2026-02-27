using DotnetMls.Codec;

namespace DotnetMls.Types;

/// <summary>
/// A generic MLS extension (RFC 9420 Section 5.3).
/// </summary>
public sealed class Extension
{
    /// <summary>
    /// The extension type identifier.
    /// </summary>
    public ushort ExtensionType { get; set; }

    /// <summary>
    /// The opaque extension data.
    /// </summary>
    public byte[] ExtensionData { get; set; } = Array.Empty<byte>();

    public Extension()
    {
    }

    public Extension(ushort extensionType, byte[] extensionData)
    {
        ExtensionType = extensionType;
        ExtensionData = extensionData;
    }

    public void WriteTo(TlsWriter writer)
    {
        writer.WriteUint16(ExtensionType);
        writer.WriteOpaqueV(ExtensionData);
    }

    public static Extension ReadFrom(TlsReader reader)
    {
        ushort extensionType = reader.ReadUint16();
        byte[] extensionData = reader.ReadOpaqueV();
        return new Extension(extensionType, extensionData);
    }
}
