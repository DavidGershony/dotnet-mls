using DotnetMls.Codec;
using DotnetMls.Crypto;

namespace DotnetMls.Types;

/// <summary>
/// A reference (hash) to a KeyPackage (RFC 9420 Section 5.2).
/// </summary>
public sealed class KeyPackageRef
{
    /// <summary>
    /// The raw reference hash bytes.
    /// </summary>
    public byte[] Value { get; set; } = Array.Empty<byte>();

    public KeyPackageRef()
    {
    }

    public KeyPackageRef(byte[] value)
    {
        Value = value;
    }

    /// <summary>
    /// Computes a KeyPackage reference from its serialized form.
    /// </summary>
    /// <param name="cs">The cipher suite to use for hashing.</param>
    /// <param name="serializedKeyPackage">The TLS-serialized KeyPackage bytes.</param>
    /// <returns>A new <see cref="KeyPackageRef"/>.</returns>
    public static KeyPackageRef Compute(ICipherSuite cs, byte[] serializedKeyPackage)
    {
        byte[] hash = cs.RefHash("MLS 1.0 KeyPackage Reference", serializedKeyPackage);
        return new KeyPackageRef(hash);
    }

    public void WriteTo(TlsWriter writer)
    {
        writer.WriteOpaqueV(Value);
    }

    public static KeyPackageRef ReadFrom(TlsReader reader)
    {
        byte[] value = reader.ReadOpaqueV();
        return new KeyPackageRef(value);
    }
}
