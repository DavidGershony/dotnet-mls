using DotnetMls.Codec;

namespace DotnetMls.Types;

/// <summary>
/// A Commit message that applies a set of proposals and optionally updates the path
/// (RFC 9420 Section 12.4).
/// </summary>
public sealed class Commit
{
    /// <summary>
    /// The proposals included in or referenced by this Commit.
    /// </summary>
    public ProposalOrRef[] Proposals { get; set; } = Array.Empty<ProposalOrRef>();

    /// <summary>
    /// The optional UpdatePath. Present when the committer needs to update
    /// the direct path (i.e., when there is a path-required proposal or
    /// the committer wishes to update their key material).
    /// </summary>
    public UpdatePath? Path { get; set; }

    public Commit()
    {
    }

    public Commit(ProposalOrRef[] proposals, UpdatePath? path)
    {
        Proposals = proposals;
        Path = path;
    }

    public void WriteTo(TlsWriter writer)
    {
        writer.WriteVectorV(inner =>
        {
            foreach (var por in Proposals)
            {
                por.WriteTo(inner);
            }
        });

        // optional<UpdatePath> is encoded as a presence flag (uint8)
        // followed by the value if present.
        if (Path != null)
        {
            writer.WriteUint8(1);
            Path.WriteTo(writer);
        }
        else
        {
            writer.WriteUint8(0);
        }
    }

    public static Commit ReadFrom(TlsReader reader)
    {
        byte[] proposalsData = reader.ReadOpaqueV();
        var proposals = new List<ProposalOrRef>();
        if (proposalsData.Length > 0)
        {
            var proposalsReader = new TlsReader(proposalsData);
            while (!proposalsReader.IsEmpty)
            {
                proposals.Add(ProposalOrRef.ReadFrom(proposalsReader));
            }
        }

        byte hasPath = reader.ReadUint8();
        UpdatePath? path = null;
        if (hasPath == 1)
        {
            path = UpdatePath.ReadFrom(reader);
        }
        else if (hasPath != 0)
        {
            throw new TlsDecodingException($"Invalid optional presence flag for UpdatePath: {hasPath}");
        }

        return new Commit(proposals.ToArray(), path);
    }
}
