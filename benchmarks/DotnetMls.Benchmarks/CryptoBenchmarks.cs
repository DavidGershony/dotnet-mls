using BenchmarkDotNet.Attributes;
using DotnetMls.Crypto;

namespace DotnetMls.Benchmarks;

[MemoryDiagnoser]
public class CryptoBenchmarks
{
    private ICipherSuite _cs = null!;
    private byte[] _privateKey = null!;
    private byte[] _publicKey = null!;
    private byte[] _sigPriv = null!;
    private byte[] _sigPub = null!;
    private byte[] _message = null!;
    private byte[] _signature = null!;
    private byte[] _aeadKey = null!;
    private byte[] _aeadNonce = null!;
    private byte[] _aeadAad = null!;
    private byte[] _aeadCiphertext = null!;
    private byte[] _hpkeSealed = null!;
    private byte[] _hkdfPrk = null!;
    private byte[] _secret = null!;

    [GlobalSetup]
    public void Setup()
    {
        _cs = new CipherSuite0x0001();
        (_privateKey, _publicKey) = _cs.GenerateHpkeKeyPair();
        (_sigPriv, _sigPub) = _cs.GenerateSignatureKeyPair();
        _message = new byte[256];
        Random.Shared.NextBytes(_message);
        _signature = _cs.SignWithLabel(_sigPriv, "bench", _message);

        _aeadKey = _cs.RandomBytes(_cs.AeadKeySize);
        _aeadNonce = _cs.RandomBytes(_cs.AeadNonceSize);
        _aeadAad = new byte[32];
        Random.Shared.NextBytes(_aeadAad);
        _aeadCiphertext = _cs.AeadEncrypt(_aeadKey, _aeadNonce, _aeadAad, _message);

        _hpkeSealed = _cs.HpkeSeal(_publicKey, Array.Empty<byte>(), Array.Empty<byte>(), _message);

        _hkdfPrk = _cs.Extract(new byte[32], new byte[32]);
        _secret = _cs.RandomBytes(32);
    }

    // --- HPKE ---

    [Benchmark]
    public byte[] HpkeSeal()
        => _cs.HpkeSeal(_publicKey, Array.Empty<byte>(), Array.Empty<byte>(), _message);

    [Benchmark]
    public byte[] HpkeOpen()
    {
        var kemOutput = _hpkeSealed.AsSpan(0, 32).ToArray();
        var ciphertext = _hpkeSealed.AsSpan(32).ToArray();
        return _cs.HpkeOpen(_privateKey, kemOutput, Array.Empty<byte>(), Array.Empty<byte>(), ciphertext);
    }

    // --- AES-GCM ---

    [Benchmark]
    public byte[] AeadEncrypt()
        => _cs.AeadEncrypt(_aeadKey, _aeadNonce, _aeadAad, _message);

    [Benchmark]
    public byte[] AeadDecrypt()
        => _cs.AeadDecrypt(_aeadKey, _aeadNonce, _aeadAad, _aeadCiphertext);

    // --- Ed25519 ---

    [Benchmark]
    public byte[] Ed25519Sign()
        => _cs.SignWithLabel(_sigPriv, "bench", _message);

    [Benchmark]
    public bool Ed25519Verify()
        => _cs.VerifyWithLabel(_sigPub, "bench", _message, _signature);

    // --- X25519 / HPKE KEM ---

    [Benchmark]
    public (byte[], byte[]) HpkeEncap()
        => _cs.HpkeEncap(_publicKey);

    [Benchmark]
    public byte[] HpkeDecap()
    {
        var kemOutput = _hpkeSealed.AsSpan(0, 32).ToArray();
        return _cs.HpkeDecap(kemOutput, _privateKey);
    }

    // --- HKDF ---

    [Benchmark]
    public byte[] HkdfExtract()
        => _cs.Extract(new byte[32], new byte[32]);

    [Benchmark]
    public byte[] HkdfExpand()
        => _cs.Expand(_hkdfPrk, new byte[] { 1, 2, 3 }, 32);

    [Benchmark]
    public byte[] ExpandWithLabel()
        => _cs.ExpandWithLabel(_secret, "test", Array.Empty<byte>(), 32);

    [Benchmark]
    public byte[] DeriveSecret()
        => _cs.DeriveSecret(_secret, "bench");

    // --- Hash / MAC ---

    [Benchmark]
    public byte[] Sha256Hash()
        => _cs.Hash(_message);

    [Benchmark]
    public byte[] HmacMac()
        => _cs.Mac(_secret, _message);
}
