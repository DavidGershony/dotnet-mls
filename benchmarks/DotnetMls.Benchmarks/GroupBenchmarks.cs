using BenchmarkDotNet.Attributes;
using DotnetMls.Crypto;
using DotnetMls.Group;
using DotnetMls.Types;

namespace DotnetMls.Benchmarks;

[MemoryDiagnoser]
public class GroupBenchmarks
{
    private ICipherSuite _cs = null!;
    private byte[] _aliceSigPriv = null!;
    private byte[] _aliceSigPub = null!;
    private byte[] _bobSigPriv = null!;
    private byte[] _bobSigPub = null!;
    private MlsGroup _aliceGroup = null!;
    private MlsGroup _bobGroup = null!;
    private byte[] _plaintext = null!;
    [GlobalSetup]
    public void Setup()
    {
        _cs = new CipherSuite0x0001();
        (_aliceSigPriv, _aliceSigPub) = _cs.GenerateSignatureKeyPair();
        (_bobSigPriv, _bobSigPub) = _cs.GenerateSignatureKeyPair();

        // Create group with Alice and Bob for message benchmarks
        _aliceGroup = MlsGroup.CreateGroup(_cs, "alice"u8.ToArray(), _aliceSigPriv, _aliceSigPub);
        var bobKp = MlsGroup.CreateKeyPackage(
            _cs, "bob"u8.ToArray(), _bobSigPriv, _bobSigPub,
            out var bobInitPriv, out var bobHpkePriv);
        var addProposals = _aliceGroup.ProposeAdd(new[] { bobKp });
        var (_, welcome) = _aliceGroup.Commit(addProposals);
        _aliceGroup.MergePendingCommit();
        _bobGroup = MlsGroup.ProcessWelcome(_cs, welcome!, bobKp, bobInitPriv, bobHpkePriv, _bobSigPriv);

        _plaintext = new byte[256];
        Random.Shared.NextBytes(_plaintext);
    }

    [Benchmark]
    public MlsGroup CreateGroup()
        => MlsGroup.CreateGroup(_cs, "bench"u8.ToArray(), _aliceSigPriv, _aliceSigPub);

    [Benchmark]
    public KeyPackage CreateKeyPackage()
        => MlsGroup.CreateKeyPackage(
            _cs, "bench"u8.ToArray(), _bobSigPriv, _bobSigPub,
            out _, out _);

    [Benchmark]
    public PrivateMessage EncryptMessage()
        => _aliceGroup.EncryptApplicationMessage(_plaintext);

    [Benchmark]
    public (byte[], uint) EncryptAndDecryptMessage()
    {
        var encrypted = _aliceGroup.EncryptApplicationMessage(_plaintext);
        return _bobGroup.DecryptApplicationMessage(encrypted);
    }
}
