using BenchmarkDotNet.Attributes;
using DotnetMls.Tree;
using DotnetMls.Types;

namespace DotnetMls.Benchmarks;

[MemoryDiagnoser]
public class TreeBenchmarks
{
    private RatchetTree _tree = null!;

    [Params(8, 64, 256)]
    public int GroupSize { get; set; }

    [GlobalSetup]
    public void Setup()
    {
        _tree = new RatchetTree();
        for (int i = 0; i < GroupSize; i++)
            _tree.AddLeaf(MakeLeaf((byte)(i & 0xFF)));
    }

    private static LeafNode MakeLeaf(byte id)
    {
        return new LeafNode
        {
            EncryptionKey = new byte[] { id },
            SignatureKey = new byte[] { id },
            Credential = new BasicCredential(new byte[] { id }),
            Capabilities = new Capabilities
            {
                Versions = new ushort[] { 1 },
                CipherSuites = new ushort[] { 1 },
                Extensions = Array.Empty<ushort>(),
                Proposals = Array.Empty<ushort>(),
                Credentials = new ushort[] { 1 }
            },
            Source = LeafNodeSource.Commit,
            Extensions = Array.Empty<Extension>(),
            Signature = new byte[] { id }
        };
    }

    [Benchmark]
    public uint AddAndRemoveLeaf()
    {
        var tree = _tree.Clone();
        var idx = tree.AddLeaf(MakeLeaf(0xFF));
        tree.BlankLeaf(idx);
        return idx;
    }

    [Benchmark]
    public IReadOnlyList<uint> Resolution_Root()
    {
        uint root = TreeMath.Root(_tree.LeafCount);
        return _tree.Resolution(root);
    }

    [Benchmark]
    public uint[] DirectPath_Leaf0()
        => TreeMath.DirectPath(0, _tree.LeafCount);

    [Benchmark]
    public uint[] Copath_Leaf0()
        => TreeMath.Copath(0, _tree.LeafCount);

    [Benchmark]
    public RatchetTree Clone()
        => _tree.Clone();
}
