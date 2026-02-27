using BenchmarkDotNet.Attributes;
using DotnetMls.Crypto;
using DotnetMls.KeySchedule;

namespace DotnetMls.Benchmarks;

[MemoryDiagnoser]
public class KeyScheduleBenchmarks
{
    private ICipherSuite _cs = null!;
    private byte[] _initSecret = null!;
    private byte[] _commitSecret = null!;
    private byte[] _groupContext = null!;
    private byte[] _joinerSecret = null!;
    private byte[] _encryptionSecret = null!;
    private byte[] _transcriptHash = null!;
    private KeyScheduleEpoch _epoch = null!;

    [GlobalSetup]
    public void Setup()
    {
        _cs = new CipherSuite0x0001();
        _initSecret = new byte[32];
        _commitSecret = new byte[32];
        _groupContext = new byte[64];
        Random.Shared.NextBytes(_groupContext);

        _epoch = KeyScheduleEpoch.Create(_cs, _initSecret, _commitSecret, _groupContext);
        _joinerSecret = _epoch.JoinerSecret;
        _encryptionSecret = _cs.RandomBytes(32);
        _transcriptHash = _cs.RandomBytes(32);
    }

    [Benchmark]
    public KeyScheduleEpoch KeySchedule_Create()
        => KeyScheduleEpoch.Create(_cs, _initSecret, _commitSecret, _groupContext);

    [Benchmark]
    public KeyScheduleEpoch KeySchedule_FromJoinerSecret()
        => KeyScheduleEpoch.FromJoinerSecret(_cs, _joinerSecret, _groupContext);

    [Benchmark]
    public byte[] ComputeConfirmationTag()
        => _epoch.ComputeConfirmationTag(_cs, _transcriptHash);

    [Benchmark]
    public byte[] ComputeMembershipTag()
        => _epoch.ComputeMembershipTag(_cs, _transcriptHash);

    [Benchmark]
    public byte[] DeriveExporterSecret()
        => _epoch.DeriveExporterSecret(_cs, "bench-label", Array.Empty<byte>(), 32);

    [Params(2, 8, 64)]
    public uint LeafCount { get; set; }

    [Benchmark]
    public (byte[] key, byte[] nonce, uint gen) SecretTree_DeriveKey()
    {
        var tree = new SecretTree(_cs, _encryptionSecret, LeafCount);
        return tree.GetApplicationKeyAndNonce(0);
    }
}
