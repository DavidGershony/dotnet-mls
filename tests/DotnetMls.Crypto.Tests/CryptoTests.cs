using DotnetMls.Crypto;
using Xunit;

namespace DotnetMls.Crypto.Tests;

public class HkdfTests
{
    [Fact]
    public void Extract_WithKnownInput_ProducesCorrectLength()
    {
        var hkdf = new HkdfProvider();
        var prk = hkdf.Extract(new byte[32], new byte[32]);
        Assert.Equal(32, prk.Length);
    }

    [Fact]
    public void Expand_ProducesRequestedLength()
    {
        var hkdf = new HkdfProvider();
        var prk = hkdf.Extract(new byte[32], new byte[32]);
        var okm = hkdf.Expand(prk, new byte[] { 1, 2, 3 }, 64);
        Assert.Equal(64, okm.Length);
    }

    [Fact]
    public void ExtractExpand_IsDeterministic()
    {
        var hkdf = new HkdfProvider();
        var ikm = new byte[] { 1, 2, 3, 4, 5 };
        var salt = new byte[] { 10, 20, 30 };
        var prk1 = hkdf.Extract(salt, ikm);
        var prk2 = hkdf.Extract(salt, ikm);
        Assert.Equal(prk1, prk2);
    }

    [Fact]
    public void Extract_DifferentSalts_ProduceDifferentPrks()
    {
        var hkdf = new HkdfProvider();
        var ikm = new byte[] { 1, 2, 3, 4, 5 };
        var prk1 = hkdf.Extract(new byte[] { 1 }, ikm);
        var prk2 = hkdf.Extract(new byte[] { 2 }, ikm);
        Assert.NotEqual(prk1, prk2);
    }

    [Fact]
    public void Expand_DifferentInfos_ProduceDifferentOutputs()
    {
        var hkdf = new HkdfProvider();
        var prk = hkdf.Extract(new byte[32], new byte[32]);
        var okm1 = hkdf.Expand(prk, new byte[] { 1 }, 32);
        var okm2 = hkdf.Expand(prk, new byte[] { 2 }, 32);
        Assert.NotEqual(okm1, okm2);
    }

    [Fact]
    public void Extract_WithEmptySalt_DoesNotThrow()
    {
        var hkdf = new HkdfProvider();
        var prk = hkdf.Extract(Array.Empty<byte>(), new byte[] { 1, 2, 3 });
        Assert.Equal(32, prk.Length);
    }

    [Theory]
    [InlineData(1)]
    [InlineData(16)]
    [InlineData(32)]
    [InlineData(64)]
    [InlineData(128)]
    public void Expand_VariousLengths_ProducesRequestedLength(int length)
    {
        var hkdf = new HkdfProvider();
        var prk = hkdf.Extract(new byte[32], new byte[32]);
        var okm = hkdf.Expand(prk, new byte[] { 0 }, length);
        Assert.Equal(length, okm.Length);
    }
}

public class AesGcmTests
{
    [Fact]
    public void EncryptDecrypt_RoundTrips()
    {
        var aes = new AesGcmProvider();
        var key = new byte[16]; // AES-128
        var nonce = new byte[12];
        var aad = new byte[] { 1, 2, 3 };
        var plaintext = "Hello, World!"u8.ToArray();

        var encrypted = aes.Encrypt(key, nonce, aad, plaintext);
        Assert.NotEqual(plaintext, encrypted);
        Assert.Equal(plaintext.Length + 16, encrypted.Length); // plaintext + 16-byte tag

        var decrypted = aes.Decrypt(key, nonce, aad, encrypted);
        Assert.Equal(plaintext, decrypted);
    }

    [Fact]
    public void Decrypt_WithWrongKey_Throws()
    {
        var aes = new AesGcmProvider();
        var key = new byte[16];
        var nonce = new byte[12];
        var plaintext = "test"u8.ToArray();

        var encrypted = aes.Encrypt(key, nonce, Array.Empty<byte>(), plaintext);

        var wrongKey = new byte[16];
        wrongKey[0] = 1;
        Assert.ThrowsAny<Exception>(() => aes.Decrypt(wrongKey, nonce, Array.Empty<byte>(), encrypted));
    }

    [Fact]
    public void Decrypt_WithWrongAad_Throws()
    {
        var aes = new AesGcmProvider();
        var key = new byte[16];
        var nonce = new byte[12];
        var plaintext = "test"u8.ToArray();

        var encrypted = aes.Encrypt(key, nonce, new byte[] { 1, 2, 3 }, plaintext);
        Assert.ThrowsAny<Exception>(() =>
            aes.Decrypt(key, nonce, new byte[] { 4, 5, 6 }, encrypted));
    }

    [Fact]
    public void Decrypt_WithTruncatedCiphertext_Throws()
    {
        var aes = new AesGcmProvider();
        Assert.ThrowsAny<Exception>(() =>
            aes.Decrypt(new byte[16], new byte[12], Array.Empty<byte>(), new byte[5]));
    }

    [Fact]
    public void Encrypt_WithAes256Key_RoundTrips()
    {
        var aes = new AesGcmProvider();
        var key = new byte[32]; // AES-256
        key[0] = 42;
        var nonce = new byte[12];
        nonce[0] = 99;
        var plaintext = "AES-256 test"u8.ToArray();

        var encrypted = aes.Encrypt(key, nonce, Array.Empty<byte>(), plaintext);
        var decrypted = aes.Decrypt(key, nonce, Array.Empty<byte>(), encrypted);
        Assert.Equal(plaintext, decrypted);
    }

    [Fact]
    public void Encrypt_EmptyPlaintext_ProducesTagOnly()
    {
        var aes = new AesGcmProvider();
        var key = new byte[16];
        var nonce = new byte[12];
        var encrypted = aes.Encrypt(key, nonce, Array.Empty<byte>(), Array.Empty<byte>());
        Assert.Equal(16, encrypted.Length); // tag only
        var decrypted = aes.Decrypt(key, nonce, Array.Empty<byte>(), encrypted);
        Assert.Empty(decrypted);
    }
}

public class Ed25519Tests
{
    [Fact]
    public void GenerateKeyPair_Returns32ByteKeys()
    {
        var ed = new Ed25519Provider();
        var (priv, pub) = ed.GenerateKeyPair();
        Assert.Equal(32, priv.Length);
        Assert.Equal(32, pub.Length);
    }

    [Fact]
    public void SignVerify_RoundTrips()
    {
        var ed = new Ed25519Provider();
        var (priv, pub) = ed.GenerateKeyPair();
        var message = "Test message"u8.ToArray();

        var sig = ed.Sign(priv, message);
        Assert.Equal(64, sig.Length);
        Assert.True(ed.Verify(pub, message, sig));
    }

    [Fact]
    public void Verify_WrongMessage_ReturnsFalse()
    {
        var ed = new Ed25519Provider();
        var (priv, pub) = ed.GenerateKeyPair();

        var sig = ed.Sign(priv, "message1"u8.ToArray());
        Assert.False(ed.Verify(pub, "message2"u8.ToArray(), sig));
    }

    [Fact]
    public void Verify_WrongKey_ReturnsFalse()
    {
        var ed = new Ed25519Provider();
        var (priv1, _) = ed.GenerateKeyPair();
        var (_, pub2) = ed.GenerateKeyPair();

        var sig = ed.Sign(priv1, "test"u8.ToArray());
        Assert.False(ed.Verify(pub2, "test"u8.ToArray(), sig));
    }

    [Fact]
    public void Sign_IsDeterministic()
    {
        var ed = new Ed25519Provider();
        var (priv, _) = ed.GenerateKeyPair();
        var message = "deterministic"u8.ToArray();

        var sig1 = ed.Sign(priv, message);
        var sig2 = ed.Sign(priv, message);
        Assert.Equal(sig1, sig2);
    }

    [Fact]
    public void GenerateKeyPair_ProducesUniqueKeys()
    {
        var ed = new Ed25519Provider();
        var (_, pub1) = ed.GenerateKeyPair();
        var (_, pub2) = ed.GenerateKeyPair();
        Assert.NotEqual(pub1, pub2);
    }

    [Fact]
    public void Sign_EmptyMessage_Works()
    {
        var ed = new Ed25519Provider();
        var (priv, pub) = ed.GenerateKeyPair();
        var sig = ed.Sign(priv, Array.Empty<byte>());
        Assert.Equal(64, sig.Length);
        Assert.True(ed.Verify(pub, Array.Empty<byte>(), sig));
    }
}

public class X25519Tests
{
    [Fact]
    public void GenerateKeyPair_Returns32ByteKeys()
    {
        var x = new X25519Provider();
        var (priv, pub) = x.GenerateKeyPair();
        Assert.Equal(32, priv.Length);
        Assert.Equal(32, pub.Length);
    }

    [Fact]
    public void DeriveSharedSecret_IsSymmetric()
    {
        var x = new X25519Provider();
        var (privA, pubA) = x.GenerateKeyPair();
        var (privB, pubB) = x.GenerateKeyPair();

        var secretAB = x.DeriveSharedSecret(privA, pubB);
        var secretBA = x.DeriveSharedSecret(privB, pubA);
        Assert.Equal(secretAB, secretBA);
    }

    [Fact]
    public void GetPublicKey_DerivesSameAsGenerate()
    {
        var x = new X25519Provider();
        var (priv, pub) = x.GenerateKeyPair();
        var derivedPub = x.GetPublicKey(priv);
        Assert.Equal(pub, derivedPub);
    }

    [Fact]
    public void DeriveSharedSecret_DifferentKeyPairs_ProduceDifferentSecrets()
    {
        var x = new X25519Provider();
        var (privA, _) = x.GenerateKeyPair();
        var (_, pubB) = x.GenerateKeyPair();
        var (_, pubC) = x.GenerateKeyPair();

        var secretAB = x.DeriveSharedSecret(privA, pubB);
        var secretAC = x.DeriveSharedSecret(privA, pubC);
        Assert.NotEqual(secretAB, secretAC);
    }

    [Fact]
    public void DeriveSharedSecret_Returns32Bytes()
    {
        var x = new X25519Provider();
        var (privA, _) = x.GenerateKeyPair();
        var (_, pubB) = x.GenerateKeyPair();
        var secret = x.DeriveSharedSecret(privA, pubB);
        Assert.Equal(32, secret.Length);
    }
}

public class HpkeTests
{
    [Fact]
    public void SealOpen_RoundTrips()
    {
        var hpke = new HpkeX25519Aes128();
        var (priv, pub) = hpke.GenerateKeyPair();

        var info = "test info"u8.ToArray();
        var aad = "test aad"u8.ToArray();
        var plaintext = "Hello HPKE!"u8.ToArray();

        var sealed_ = hpke.Seal(pub, info, aad, plaintext);
        Assert.True(sealed_.Length > plaintext.Length);

        // sealed_ = kem_output (32 bytes) || ciphertext (plaintext.Length + 16 tag)
        var kemOutput = sealed_.AsSpan(0, 32).ToArray();
        var ciphertext = sealed_.AsSpan(32).ToArray();

        var decrypted = hpke.Open(priv, kemOutput, info, aad, ciphertext);
        Assert.Equal(plaintext, decrypted);
    }

    [Fact]
    public void EncapDecap_ProduceSameSharedSecret()
    {
        var hpke = new HpkeX25519Aes128();
        var (priv, pub) = hpke.GenerateKeyPair();

        var (kemOutput, sharedSecret) = hpke.Encap(pub);
        var decappedSecret = hpke.Decap(kemOutput, priv);
        Assert.Equal(sharedSecret, decappedSecret);
    }

    [Fact]
    public void Seal_DifferentCallsProduceDifferentCiphertexts()
    {
        var hpke = new HpkeX25519Aes128();
        var (_, pub) = hpke.GenerateKeyPair();

        var info = "test"u8.ToArray();
        var aad = Array.Empty<byte>();
        var pt = "same plaintext"u8.ToArray();

        var s1 = hpke.Seal(pub, info, aad, pt);
        var s2 = hpke.Seal(pub, info, aad, pt);

        // Ephemeral keys differ, so outputs should differ
        Assert.NotEqual(s1, s2);
    }

    [Fact]
    public void Open_WrongPrivateKey_Throws()
    {
        var hpke = new HpkeX25519Aes128();
        var (_, pubA) = hpke.GenerateKeyPair();
        var (privB, _) = hpke.GenerateKeyPair();

        var sealed_ = hpke.Seal(pubA, Array.Empty<byte>(), Array.Empty<byte>(), "test"u8.ToArray());
        var kemOutput = sealed_.AsSpan(0, 32).ToArray();
        var ciphertext = sealed_.AsSpan(32).ToArray();

        Assert.ThrowsAny<Exception>(() =>
            hpke.Open(privB, kemOutput, Array.Empty<byte>(), Array.Empty<byte>(), ciphertext));
    }

    [Fact]
    public void SealOpen_EmptyPlaintext_RoundTrips()
    {
        var hpke = new HpkeX25519Aes128();
        var (priv, pub) = hpke.GenerateKeyPair();

        var sealed_ = hpke.Seal(pub, Array.Empty<byte>(), Array.Empty<byte>(), Array.Empty<byte>());
        var kemOutput = sealed_.AsSpan(0, 32).ToArray();
        var ciphertext = sealed_.AsSpan(32).ToArray();

        var decrypted = hpke.Open(priv, kemOutput, Array.Empty<byte>(), Array.Empty<byte>(), ciphertext);
        Assert.Empty(decrypted);
    }

    [Fact]
    public void SealOpen_LargePlaintext_RoundTrips()
    {
        var hpke = new HpkeX25519Aes128();
        var (priv, pub) = hpke.GenerateKeyPair();

        var plaintext = new byte[4096];
        new Random(42).NextBytes(plaintext);

        var sealed_ = hpke.Seal(pub, "info"u8.ToArray(), "aad"u8.ToArray(), plaintext);
        var kemOutput = sealed_.AsSpan(0, 32).ToArray();
        var ciphertext = sealed_.AsSpan(32).ToArray();

        var decrypted = hpke.Open(priv, kemOutput, "info"u8.ToArray(), "aad"u8.ToArray(), ciphertext);
        Assert.Equal(plaintext, decrypted);
    }
}

public class CipherSuite0x0001Tests
{
    [Fact]
    public void Id_Is0x0001()
    {
        var cs = new CipherSuite0x0001();
        Assert.Equal((ushort)0x0001, cs.Id);
    }

    [Fact]
    public void HashSize_Is32()
    {
        var cs = new CipherSuite0x0001();
        Assert.Equal(32, cs.HashSize);
    }

    [Fact]
    public void AeadKeySize_Is16()
    {
        var cs = new CipherSuite0x0001();
        Assert.Equal(16, cs.AeadKeySize);
    }

    [Fact]
    public void AeadNonceSize_Is12()
    {
        var cs = new CipherSuite0x0001();
        Assert.Equal(12, cs.AeadNonceSize);
    }

    [Fact]
    public void SecretSize_Is32()
    {
        var cs = new CipherSuite0x0001();
        Assert.Equal(32, cs.SecretSize);
    }

    [Fact]
    public void Hash_IsDeterministic()
    {
        var cs = new CipherSuite0x0001();
        var data = "test"u8.ToArray();
        Assert.Equal(cs.Hash(data), cs.Hash(data));
    }

    [Fact]
    public void Hash_DifferentInputs_DifferentOutputs()
    {
        var cs = new CipherSuite0x0001();
        var h1 = cs.Hash("hello"u8.ToArray());
        var h2 = cs.Hash("world"u8.ToArray());
        Assert.NotEqual(h1, h2);
    }

    [Fact]
    public void Hash_OutputIs32Bytes()
    {
        var cs = new CipherSuite0x0001();
        var h = cs.Hash("test"u8.ToArray());
        Assert.Equal(32, h.Length);
    }

    [Fact]
    public void MacVerifyMac_RoundTrips()
    {
        var cs = new CipherSuite0x0001();
        var key = cs.RandomBytes(32);
        var data = "test data"u8.ToArray();
        var mac = cs.Mac(key, data);
        Assert.True(cs.VerifyMac(key, data, mac));
    }

    [Fact]
    public void VerifyMac_WrongKey_ReturnsFalse()
    {
        var cs = new CipherSuite0x0001();
        var key1 = cs.RandomBytes(32);
        var key2 = cs.RandomBytes(32);
        var data = "test"u8.ToArray();
        var mac = cs.Mac(key1, data);
        Assert.False(cs.VerifyMac(key2, data, mac));
    }

    [Fact]
    public void VerifyMac_TamperedData_ReturnsFalse()
    {
        var cs = new CipherSuite0x0001();
        var key = cs.RandomBytes(32);
        var mac = cs.Mac(key, "original"u8.ToArray());
        Assert.False(cs.VerifyMac(key, "tampered"u8.ToArray(), mac));
    }

    [Fact]
    public void ExtractExpand_ProducesCorrectLengths()
    {
        var cs = new CipherSuite0x0001();
        var prk = cs.Extract(new byte[32], new byte[32]);
        Assert.Equal(32, prk.Length);
        var okm = cs.Expand(prk, "info"u8.ToArray(), 48);
        Assert.Equal(48, okm.Length);
    }

    [Fact]
    public void DeriveSecret_ProducesHashSizeOutput()
    {
        var cs = new CipherSuite0x0001();
        var secret = cs.RandomBytes(32);
        var derived = cs.DeriveSecret(secret, "test");
        Assert.Equal(cs.HashSize, derived.Length);
    }

    [Fact]
    public void DeriveSecret_DifferentLabels_ProduceDifferentOutputs()
    {
        var cs = new CipherSuite0x0001();
        var secret = cs.RandomBytes(32);
        var d1 = cs.DeriveSecret(secret, "label_a");
        var d2 = cs.DeriveSecret(secret, "label_b");
        Assert.NotEqual(d1, d2);
    }

    [Fact]
    public void RefHash_ProducesHashSizeOutput()
    {
        var cs = new CipherSuite0x0001();
        var result = cs.RefHash("TestLabel", "content"u8.ToArray());
        Assert.Equal(cs.HashSize, result.Length);
    }

    [Fact]
    public void RefHash_IsDeterministic()
    {
        var cs = new CipherSuite0x0001();
        var r1 = cs.RefHash("TestLabel", "content"u8.ToArray());
        var r2 = cs.RefHash("TestLabel", "content"u8.ToArray());
        Assert.Equal(r1, r2);
    }

    [Fact]
    public void AeadEncryptDecrypt_RoundTrips()
    {
        var cs = new CipherSuite0x0001();
        var key = cs.RandomBytes(cs.AeadKeySize);
        var nonce = cs.RandomBytes(cs.AeadNonceSize);
        var aad = "aad"u8.ToArray();
        var plaintext = "secret"u8.ToArray();

        var ct = cs.AeadEncrypt(key, nonce, aad, plaintext);
        var pt = cs.AeadDecrypt(key, nonce, aad, ct);
        Assert.Equal(plaintext, pt);
    }

    [Fact]
    public void SignWithLabel_VerifyWithLabel_RoundTrips()
    {
        var cs = new CipherSuite0x0001();
        var (priv, pub) = cs.GenerateSignatureKeyPair();
        var content = "test content"u8.ToArray();

        var sig = cs.SignWithLabel(priv, "test label", content);
        Assert.True(cs.VerifyWithLabel(pub, "test label", content, sig));
    }

    [Fact]
    public void VerifyWithLabel_WrongLabel_ReturnsFalse()
    {
        var cs = new CipherSuite0x0001();
        var (priv, pub) = cs.GenerateSignatureKeyPair();
        var content = "test"u8.ToArray();

        var sig = cs.SignWithLabel(priv, "label_a", content);
        Assert.False(cs.VerifyWithLabel(pub, "label_b", content, sig));
    }

    [Fact]
    public void ExpandWithLabel_ProducesRequestedLength()
    {
        var cs = new CipherSuite0x0001();
        var secret = cs.RandomBytes(32);
        var result = cs.ExpandWithLabel(secret, "test", Array.Empty<byte>(), 48);
        Assert.Equal(48, result.Length);
    }

    [Fact]
    public void ExpandWithLabel_DifferentContexts_ProduceDifferentOutputs()
    {
        var cs = new CipherSuite0x0001();
        var secret = cs.RandomBytes(32);
        var r1 = cs.ExpandWithLabel(secret, "test", new byte[] { 1 }, 32);
        var r2 = cs.ExpandWithLabel(secret, "test", new byte[] { 2 }, 32);
        Assert.NotEqual(r1, r2);
    }

    [Fact]
    public void HpkeSealOpen_RoundTrips()
    {
        var cs = new CipherSuite0x0001();
        var (priv, pub) = cs.GenerateHpkeKeyPair();
        var info = "context"u8.ToArray();
        var aad = Array.Empty<byte>();
        var plaintext = "secret data"u8.ToArray();

        var sealed_ = cs.HpkeSeal(pub, info, aad, plaintext);
        var kemOutput = sealed_.AsSpan(0, 32).ToArray();
        var ciphertext = sealed_.AsSpan(32).ToArray();

        var decrypted = cs.HpkeOpen(priv, kemOutput, info, aad, ciphertext);
        Assert.Equal(plaintext, decrypted);
    }

    [Fact]
    public void HpkeEncapDecap_ProduceSameSharedSecret()
    {
        var cs = new CipherSuite0x0001();
        var (priv, pub) = cs.GenerateHpkeKeyPair();

        var (kemOutput, sharedSecret) = cs.HpkeEncap(pub);
        var decapped = cs.HpkeDecap(kemOutput, priv);
        Assert.Equal(sharedSecret, decapped);
    }

    [Fact]
    public void RandomBytes_ProducesRequestedLength()
    {
        var cs = new CipherSuite0x0001();
        var r = cs.RandomBytes(64);
        Assert.Equal(64, r.Length);
    }

    [Fact]
    public void RandomBytes_ProducesUniqueOutputs()
    {
        var cs = new CipherSuite0x0001();
        var r1 = cs.RandomBytes(32);
        var r2 = cs.RandomBytes(32);
        Assert.NotEqual(r1, r2);
    }
}
