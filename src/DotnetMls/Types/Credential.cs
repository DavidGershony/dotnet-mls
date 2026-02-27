using DotnetMls.Codec;

namespace DotnetMls.Types;

/// <summary>
/// Credential type identifiers (RFC 9420 Section 5.3).
/// </summary>
public enum CredentialType : ushort
{
    Basic = 1,
}

/// <summary>
/// Abstract base class for MLS credentials (RFC 9420 Section 5.3).
/// </summary>
public abstract class Credential
{
    /// <summary>
    /// The credential type.
    /// </summary>
    public abstract CredentialType CredentialType { get; }

    /// <summary>
    /// Serializes this credential to the writer.
    /// </summary>
    public abstract void WriteTo(TlsWriter writer);

    /// <summary>
    /// Deserializes a credential from the reader.
    /// </summary>
    public static Credential ReadFrom(TlsReader reader)
    {
        ushort rawType = reader.ReadUint16();
        return rawType switch
        {
            (ushort)CredentialType.Basic => BasicCredential.ReadBody(reader),
            _ => throw new TlsDecodingException($"Unknown CredentialType: {rawType}"),
        };
    }
}

/// <summary>
/// A basic credential containing an opaque identity (RFC 9420 Section 5.3).
/// </summary>
public sealed class BasicCredential : Credential
{
    public override CredentialType CredentialType => CredentialType.Basic;

    /// <summary>
    /// The opaque identity data.
    /// </summary>
    public byte[] Identity { get; set; } = Array.Empty<byte>();

    public BasicCredential()
    {
    }

    public BasicCredential(byte[] identity)
    {
        Identity = identity;
    }

    public override void WriteTo(TlsWriter writer)
    {
        writer.WriteUint16((ushort)CredentialType);
        writer.WriteOpaqueV(Identity);
    }

    internal static BasicCredential ReadBody(TlsReader reader)
    {
        byte[] identity = reader.ReadOpaqueV();
        return new BasicCredential(identity);
    }
}
