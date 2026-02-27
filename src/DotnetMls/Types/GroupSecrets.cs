using DotnetMls.Codec;

namespace DotnetMls.Types;

/// <summary>
/// The secrets provided to a new member in a Welcome message
/// (RFC 9420 Section 12.4.3.1).
/// </summary>
public sealed class GroupSecrets
{
    /// <summary>
    /// The joiner secret for deriving epoch secrets.
    /// </summary>
    public byte[] JoinerSecret { get; set; } = Array.Empty<byte>();

    /// <summary>
    /// The optional path secret from the committer's UpdatePath.
    /// </summary>
    public byte[]? PathSecret { get; set; }

    /// <summary>
    /// Optional pre-shared key identifiers.
    /// </summary>
    public PreSharedKeyId[]? Psks { get; set; }

    public GroupSecrets()
    {
    }

    public void WriteTo(TlsWriter writer)
    {
        writer.WriteOpaqueV(JoinerSecret);

        // optional path_secret
        if (PathSecret != null)
        {
            writer.WriteUint8(1);
            writer.WriteOpaqueV(PathSecret);
        }
        else
        {
            writer.WriteUint8(0);
        }

        // optional psks
        if (Psks != null)
        {
            writer.WriteUint8(1);
            writer.WriteVectorV(inner =>
            {
                foreach (var psk in Psks)
                {
                    psk.WriteTo(inner);
                }
            });
        }
        else
        {
            writer.WriteUint8(0);
        }
    }

    public static GroupSecrets ReadFrom(TlsReader reader)
    {
        var gs = new GroupSecrets();
        gs.JoinerSecret = reader.ReadOpaqueV();

        byte hasPath = reader.ReadUint8();
        if (hasPath == 1)
        {
            gs.PathSecret = reader.ReadOpaqueV();
        }
        else if (hasPath != 0)
        {
            throw new TlsDecodingException($"Invalid optional presence flag for PathSecret: {hasPath}");
        }

        byte hasPsks = reader.ReadUint8();
        if (hasPsks == 1)
        {
            byte[] pskData = reader.ReadOpaqueV();
            var psks = new List<PreSharedKeyId>();
            if (pskData.Length > 0)
            {
                var pskReader = new TlsReader(pskData);
                while (!pskReader.IsEmpty)
                {
                    psks.Add(PreSharedKeyId.ReadFrom(pskReader));
                }
            }
            gs.Psks = psks.ToArray();
        }
        else if (hasPsks != 0)
        {
            throw new TlsDecodingException($"Invalid optional presence flag for Psks: {hasPsks}");
        }

        return gs;
    }
}

/// <summary>
/// Identifies a pre-shared key (RFC 9420 Section 8.4).
/// </summary>
public sealed class PreSharedKeyId
{
    /// <summary>
    /// The type of PSK.
    /// </summary>
    public PskType PskType { get; set; }

    /// <summary>
    /// The external PSK identifier. Only used when PskType is External.
    /// </summary>
    public byte[] PskId { get; set; } = Array.Empty<byte>();

    /// <summary>
    /// The PSK nonce for uniqueness.
    /// </summary>
    public byte[] PskNonce { get; set; } = Array.Empty<byte>();

    /// <summary>
    /// Usage within the group. Only used when PskType is Resumption.
    /// </summary>
    public ResumptionPskUsage ResumptionUsage { get; set; }

    /// <summary>
    /// The group ID for resumption PSK. Only used when PskType is Resumption.
    /// </summary>
    public byte[] ResumptionGroupId { get; set; } = Array.Empty<byte>();

    /// <summary>
    /// The epoch for resumption PSK. Only used when PskType is Resumption.
    /// </summary>
    public ulong ResumptionEpoch { get; set; }

    public PreSharedKeyId()
    {
    }

    public void WriteTo(TlsWriter writer)
    {
        writer.WriteUint8((byte)PskType);
        if (PskType == PskType.External)
        {
            writer.WriteOpaqueV(PskId);
        }
        else if (PskType == PskType.Resumption)
        {
            writer.WriteUint8((byte)ResumptionUsage);
            writer.WriteOpaqueV(ResumptionGroupId);
            writer.WriteUint64(ResumptionEpoch);
        }
        writer.WriteOpaqueV(PskNonce);
    }

    public static PreSharedKeyId ReadFrom(TlsReader reader)
    {
        var psk = new PreSharedKeyId();
        byte rawType = reader.ReadUint8();
        psk.PskType = rawType switch
        {
            1 => PskType.External,
            2 => PskType.Resumption,
            _ => throw new TlsDecodingException($"Unknown PskType: {rawType}"),
        };

        if (psk.PskType == PskType.External)
        {
            psk.PskId = reader.ReadOpaqueV();
        }
        else if (psk.PskType == PskType.Resumption)
        {
            byte rawUsage = reader.ReadUint8();
            psk.ResumptionUsage = rawUsage switch
            {
                1 => ResumptionPskUsage.Application,
                2 => ResumptionPskUsage.ReInit,
                3 => ResumptionPskUsage.Branch,
                _ => throw new TlsDecodingException($"Unknown ResumptionPskUsage: {rawUsage}"),
            };
            psk.ResumptionGroupId = reader.ReadOpaqueV();
            psk.ResumptionEpoch = reader.ReadUint64();
        }

        psk.PskNonce = reader.ReadOpaqueV();
        return psk;
    }
}

/// <summary>
/// Pre-shared key type (RFC 9420 Section 8.4).
/// </summary>
public enum PskType : byte
{
    External = 1,
    Resumption = 2,
}

/// <summary>
/// Usage of a resumption PSK (RFC 9420 Section 8.4).
/// </summary>
public enum ResumptionPskUsage : byte
{
    Application = 1,
    ReInit = 2,
    Branch = 3,
}
