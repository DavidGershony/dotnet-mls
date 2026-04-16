using DotnetMls.Codec;

namespace DotnetMls.Types;

/// <summary>
/// Standard MLS extension type identifiers (RFC 9420 §17.3).
/// </summary>
public static class ExtensionType
{
    /// <summary>application_id (leaf context).</summary>
    public const ushort ApplicationId = 0x0001;
    /// <summary>ratchet_tree (GroupInfo context).</summary>
    public const ushort RatchetTree = 0x0002;
    /// <summary>required_capabilities (GroupContext context).</summary>
    public const ushort RequiredCapabilities = 0x0003;
    /// <summary>external_pub (GroupInfo context).</summary>
    public const ushort ExternalPub = 0x0004;
    /// <summary>external_senders (GroupContext context).</summary>
    public const ushort ExternalSenders = 0x0005;
}

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
