# Fix: SignWithLabel Missing VarInt Length Prefixes (RFC 9420 Section 5.1.2)

## Bug Summary

`BuildSignContent()` in `CipherSuite0x0001.cs` constructs the `SignContent` struct as raw byte concatenation **without VarInt length prefixes**, but RFC 9420 Section 5.1.2 specifies `opaque label<V>` and `opaque content<V>` which require QUIC-style VarInt length prefixes (RFC 9000 Section 16).

This causes **all signatures produced by DotnetMls to be incompatible with other MLS implementations** (e.g., OpenMLS/Rust). The Rust MLS library rejects DotnetMls-generated KeyPackages with: `"The leaf node signature is not valid."`

## Root Cause

In `src/DotnetMls.Crypto/CipherSuite0x0001.cs`, the `BuildSignContent` method (line ~276):

```csharp
// CURRENT (WRONG):
private static byte[] BuildSignContent(string label, byte[] content)
{
    var labelBytes = Encoding.UTF8.GetBytes(label);
    var result = new byte[MlsLabelPrefix.Length + labelBytes.Length + content.Length];
    var offset = 0;

    Buffer.BlockCopy(MlsLabelPrefix, 0, result, offset, MlsLabelPrefix.Length);
    offset += MlsLabelPrefix.Length;

    Buffer.BlockCopy(labelBytes, 0, result, offset, labelBytes.Length);
    offset += labelBytes.Length;

    Buffer.BlockCopy(content, 0, result, offset, content.Length);

    return result;
}
```

This produces: `"MLS 1.0 " || Label || Content` (raw concatenation, no length prefixes)

But RFC 9420 Section 5.1.2 specifies:

```
SignWithLabel(SignatureKey, Label, Content) =
    Sign(SignatureKey, SignContent)

struct {
    opaque label<V> = "MLS 1.0 " + Label;
    opaque content<V> = Content;
} SignContent;
```

The `<V>` notation means each field must be prefixed with a QUIC-style variable-length integer encoding its length. The correct output should be:

```
VarInt(len("MLS 1.0 " + Label)) || "MLS 1.0 " || Label || VarInt(len(Content)) || Content
```

## Evidence

1. **`ExpandWithLabel` in the SAME FILE correctly uses length prefixes** (line ~112):
   ```csharp
   // KDFLabel = uint16(length) || uint8(fullLabel.Length) || fullLabel || uint8(context.Length) || context
   ```
   This correctly encodes `opaque label<V>` with a length prefix. But `BuildSignContent` does not.

2. **Cross-MDK test failure**: When the Rust MLS DLL (OpenMLS) tries to verify a LeafNode signature from a DotnetMls-generated KeyPackage, it constructs `SignContent` WITH VarInt prefixes, computes a different byte sequence, and Ed25519 verification fails.

3. **OpenMLS reference implementation** uses `VLByteSlice`/`VLBytes` TLS types for `SignContent`, which encode with VarInt length prefixes:
   ```rust
   #[derive(TlsSerialize, TlsDeserialize, TlsSize)]
   struct SignContent {
       label: VLByteSlice,   // VarInt-prefixed
       content: VLBytes,     // VarInt-prefixed
   }
   ```

## QUIC VarInt Encoding (RFC 9000 Section 16)

The VarInt length prefix uses the top 2 bits to indicate the encoding length:
- `0b00xxxxxx` (1 byte): lengths 0-63
- `0b01xxxxxx xxxxxxxx` (2 bytes): lengths 64-16383
- `0b10xxxxxx xxxxxxxx xxxxxxxx xxxxxxxx` (4 bytes): lengths 16384-1073741823

This is the same encoding already used by `TlsWriter.WriteVarIntLength()` in the `DotnetMls` project.

## Fix Required

### 1. Fix `BuildSignContent` in `src/DotnetMls.Crypto/CipherSuite0x0001.cs`

Replace the raw concatenation with proper VarInt-prefixed encoding:

```csharp
private static byte[] BuildSignContent(string label, byte[] content)
{
    // RFC 9420 Section 5.1.2: SignContent = opaque label<V> || opaque content<V>
    // Both fields use QUIC-style VarInt length prefixes (RFC 9000 Section 16)
    var fullLabel = Encoding.UTF8.GetBytes("MLS 1.0 " + label);

    var labelLenBytes = EncodeVarInt(fullLabel.Length);
    var contentLenBytes = EncodeVarInt(content.Length);

    var result = new byte[labelLenBytes.Length + fullLabel.Length + contentLenBytes.Length + content.Length];
    var offset = 0;

    Buffer.BlockCopy(labelLenBytes, 0, result, offset, labelLenBytes.Length);
    offset += labelLenBytes.Length;

    Buffer.BlockCopy(fullLabel, 0, result, offset, fullLabel.Length);
    offset += fullLabel.Length;

    Buffer.BlockCopy(contentLenBytes, 0, result, offset, contentLenBytes.Length);
    offset += contentLenBytes.Length;

    Buffer.BlockCopy(content, 0, result, offset, content.Length);

    return result;
}

private static byte[] EncodeVarInt(int length)
{
    if (length <= 63)
        return new byte[] { (byte)length };
    if (length <= 16383)
        return new byte[] { (byte)(0x40 | (length >> 8)), (byte)(length & 0xFF) };
    if (length <= 1073741823)
        return new byte[]
        {
            (byte)(0x80 | (length >> 24)),
            (byte)((length >> 16) & 0xFF),
            (byte)((length >> 8) & 0xFF),
            (byte)(length & 0xFF)
        };
    throw new ArgumentOutOfRangeException(nameof(length), length, "VarInt length exceeds maximum.");
}
```

### 2. Fix `RefHash` in the same file (same bug pattern)

`RefHash` (line ~158) has a similar issue: `opaque value<V>` is missing its VarInt length prefix.

Current (WRONG):
```csharp
// RefHashInput = uint16(label_len) || label || content  (missing value<V> prefix!)
```

Fix: add VarInt prefix for the value field:
```csharp
public byte[] RefHash(string label, byte[] content)
{
    var labelBytes = Encoding.UTF8.GetBytes(label);

    // RFC 9420 Section 5.2: RefHashInput = opaque label<V> || opaque value<V>
    var labelLenBytes = EncodeVarInt(labelBytes.Length);
    var contentLenBytes = EncodeVarInt(content.Length);

    var input = new byte[labelLenBytes.Length + labelBytes.Length + contentLenBytes.Length + content.Length];
    var offset = 0;

    Buffer.BlockCopy(labelLenBytes, 0, input, offset, labelLenBytes.Length);
    offset += labelLenBytes.Length;
    Buffer.BlockCopy(labelBytes, 0, input, offset, labelBytes.Length);
    offset += labelBytes.Length;
    Buffer.BlockCopy(contentLenBytes, 0, input, offset, contentLenBytes.Length);
    offset += contentLenBytes.Length;
    Buffer.BlockCopy(content, 0, input, offset, content.Length);

    return Hash(input);
}
```

### 3. Update the interface doc comments in `ICipherSuite.cs`

Update the `SignWithLabel` and `RefHash` doc comments to reflect the correct encoding:
- `SignWithLabel`: `SignContent = VarInt(label_len) || label || VarInt(content_len) || content`
- `RefHash`: `RefHashInput = VarInt(label_len) || label || VarInt(value_len) || value`

## Testing

### Unit Test: Verify VarInt encoding in SignContent

Add a test that verifies `BuildSignContent("LeafNodeTBS", someContent)` produces bytes with VarInt length prefixes:

```csharp
[Fact]
public void BuildSignContent_IncludesVarIntLengthPrefixes()
{
    var cs = new CipherSuite0x0001();
    var (privKey, pubKey) = cs.GenerateSignatureKeyPair();

    var content = new byte[100]; // 100 bytes of TBS data
    new Random(42).NextBytes(content);

    var signature = cs.SignWithLabel(privKey, "LeafNodeTBS", content);

    // Verify round-trip: sign then verify
    Assert.True(cs.VerifyWithLabel(pubKey, "LeafNodeTBS", content, signature));
}
```

### Cross-implementation test: Verify against known Rust-generated signatures

The best end-to-end test is in the OpenChat project at:
`tests/OpenChat.Core.Tests/CrossMdkRelayIntegrationTests.cs`

Test: `CrossMdk_RustCreatesGroup_ManagedAcceptsWelcome_ThroughRelay`

This test is currently skipped with `[Fact(Skip = "...")]`. After fixing the DotnetMls library:

1. Rebuild the DotnetMls NuGet package
2. Update the OpenChat project to reference the new version
3. Remove the `Skip` attribute from the test
4. Run: `dotnet test --filter "CrossMdk_RustCreatesGroup"`

The test flow:
- User A (Rust MLS) creates a group
- User B (C# MLS / DotnetMls) generates a KeyPackage and publishes to relay
- User A fetches User B's KeyPackage and calls AddMemberAsync (THIS IS WHERE IT CURRENTLY FAILS)
- User A publishes Welcome to relay
- User B receives and processes the Welcome
- Both users exchange encrypted messages bidirectionally

### Additional test: Known-answer test with RFC test vectors

If available, use MLS RFC 9420 test vectors to verify `SignWithLabel` produces the correct output for known inputs. This ensures compatibility with ALL MLS implementations, not just OpenMLS.

## Impact

This fix affects ALL MLS signatures in the library:
- `LeafNode` signatures (in KeyPackages, UpdatePath, Commits)
- `KeyPackage` signatures (the outer KeyPackageTBS signature)
- Any other `SignWithLabel` / `VerifyWithLabel` callers

After the fix:
- Existing DotnetMls-to-DotnetMls signatures will BREAK (they used the wrong encoding)
- Cross-implementation compatibility with OpenMLS/Rust will be FIXED
- Any persisted MLS group state with old signatures will be incompatible

This is a correctness fix — the old behavior was non-compliant with RFC 9420.
