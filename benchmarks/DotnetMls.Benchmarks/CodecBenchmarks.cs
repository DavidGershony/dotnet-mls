using BenchmarkDotNet.Attributes;
using DotnetMls.Codec;
using DotnetMls.Crypto;
using DotnetMls.Group;
using DotnetMls.Types;

namespace DotnetMls.Benchmarks;

[MemoryDiagnoser]
public class CodecBenchmarks
{
    private byte[] _serializedKeyPackage = null!;
    private KeyPackage _keyPackage = null!;
    private byte[] _quicVarintData = null!;

    [GlobalSetup]
    public void Setup()
    {
        var cs = new CipherSuite0x0001();
        var (sigPriv, sigPub) = cs.GenerateSignatureKeyPair();
        _keyPackage = MlsGroup.CreateKeyPackage(
            cs, "bench-user"u8.ToArray(), sigPriv, sigPub,
            out _, out _);

        _serializedKeyPackage = TlsCodec.Serialize(w => _keyPackage.WriteTo(w));

        _quicVarintData = TlsCodec.Serialize(w =>
        
        {
            QuicVarint.Write(w, 42);
            QuicVarint.Write(w, 16000);
            QuicVarint.Write(w, 1_000_000);
            QuicVarint.Write(w, 2_000_000_000);
        });
    }

    [Benchmark]
    public byte[] KeyPackage_Serialize()
        => TlsCodec.Serialize(w => _keyPackage.WriteTo(w));

    [Benchmark]
    public KeyPackage KeyPackage_Deserialize()
    {
        var reader = new TlsReader(_serializedKeyPackage);
        return KeyPackage.ReadFrom(reader);
    }

    [Benchmark]
    public byte[] QuicVarint_Encode()
        => TlsCodec.Serialize(w =>
        {
            QuicVarint.Write(w, 42);
            QuicVarint.Write(w, 16000);
            QuicVarint.Write(w, 1_000_000);
            QuicVarint.Write(w, 2_000_000_000);
        });

    [Benchmark]
    public ulong QuicVarint_Decode()
    {
        var reader = new TlsReader(_quicVarintData);
        var a = QuicVarint.Read(reader);
        var b = QuicVarint.Read(reader);
        var c = QuicVarint.Read(reader);
        var d = QuicVarint.Read(reader);
        return a + b + c + d;
    }

    [Benchmark]
    public byte[] TlsWriter_MixedTypes()
        => TlsCodec.Serialize(w =>
        {
            w.WriteUint8(42);
            w.WriteUint16(1000);
            w.WriteUint32(0xDEADBEEF);
            w.WriteOpaque8(new byte[] { 1, 2, 3, 4, 5, 6, 7, 8 });
            w.WriteOpaque16(new byte[64]);
        });
}
