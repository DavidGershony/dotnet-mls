# Fix Report: Key Schedule and Ratchet Tree Interop Bugs

## Summary

Two protocol-level bugs prevented DotnetMls from interoperating with OpenMLS (Rust). Both were violations of RFC 9420 discovered during cross-MDK testing where Rust/OpenMLS created a group and C#/DotnetMls tried to process the resulting Welcome message.

---

## Bug 1: Wrong Key Schedule Derivation (welcome_secret and epoch_secret)

### What Was Wrong

The key schedule in `KeyScheduleEpoch.Create` and `KeyScheduleEpoch.FromJoinerSecret` derived `welcome_secret` directly from `joiner_secret`:

```
welcome_secret = ExpandWithLabel(joiner_secret, "welcome", "", Nh)
member         = ExpandWithLabel(joiner_secret, "member", "", Nh)
epoch_secret   = Extract(member, psk_secret)
```

### What RFC 9420 Section 8 Actually Requires

RFC 9420 specifies an **intermediate secret** derived via `KDF.Extract` between `joiner_secret` and `psk_secret`. Both `welcome_secret` and `epoch_secret` are derived from this intermediate, not from `joiner_secret` directly:

```
intermediate_secret = KDF.Extract(salt=joiner_secret, ikm=psk_secret)
                         |
                         +--> DeriveSecret(., "welcome") = welcome_secret
                         |
                         +--> ExpandWithLabel(., "epoch", GroupContext, Nh) = epoch_secret
```

When no PSKs are present, `psk_secret` defaults to `zeros(KDF.Nh)` (32 zero bytes for SHA-256).

### Why It Happened

The original implementation appears to have followed an earlier or simplified reading of the spec that skipped the intermediate extraction step. The `member` intermediate and `Extract(member, psk_secret)` pattern was used instead, which produces different cryptographic output. This meant:

1. **welcome_secret** was wrong -- the AEAD key/nonce for GroupInfo encryption in Welcome messages didn't match what OpenMLS computed, so decrypting the GroupInfo failed.
2. **epoch_secret** was wrong -- all per-epoch secrets (confirmation_key, encryption_secret, etc.) derived from it were also wrong, meaning even if GroupInfo decryption somehow succeeded, all subsequent operations would fail.

### What Was Fixed

**`KeyScheduleEpoch.Create` (KeyScheduleEpoch.cs)**:
- Replaced the `member` + `Extract(member, psk)` derivation with `intermediate_secret = Extract(joiner_secret, psk_secret)`
- Changed `welcome_secret = DeriveSecret(intermediate_secret, "welcome")`
- Changed `epoch_secret = ExpandWithLabel(intermediate_secret, "epoch", groupContext, Nh)`

**`KeyScheduleEpoch.FromJoinerSecret` (KeyScheduleEpoch.cs)**:
- Same fix as above (this is the path used during Welcome processing)

**`MlsGroup.ProcessWelcome` (MlsGroup.cs)**:
- The inline welcome_secret derivation was also fixed to use the intermediate secret

### Additional HPKE EncryptWithLabel Fix

RFC 9420 Section 5.1.3 defines `EncryptWithLabel` for HPKE operations. The Welcome message's group secrets must be encrypted using:

```
EncryptWithLabel(init_key_pub, "Welcome", encrypted_group_info, group_secrets)
```

This means the HPKE info parameter should be a serialized `EncryptContext`:

```
struct {
    opaque label<V>;    // "MLS 1.0 Welcome"
    opaque content<V>;  // encrypted_group_info
} EncryptContext;
```

The original code passed empty bytes for the HPKE info parameter in both the seal (Welcome creation) and open (Welcome processing) paths. A `BuildEncryptContext` helper was added and both call sites were updated.

### Additional CreateKeyPackage Fix

Added an optional `supportedExtensionTypes` parameter to `CreateKeyPackage` so that KeyPackages can advertise support for custom extension types (e.g., `0xF2EE` used by OpenMLS's required_capabilities). Without this, groups with required_capabilities for specific extensions would reject the KeyPackage.

---

## Bug 2: Ratchet Tree Serialization Format Mismatch

### What Was Wrong

`RatchetTree.WriteTo` wrote an explicit `nodeType` discriminator byte after the `present` flag:

```
[present=1][nodeType=1 (leaf)][LeafNode bytes]    -- for leaves
[present=1][nodeType=2 (parent)][ParentNode bytes] -- for parents
[present=0]                                        -- for blank nodes
```

`RatchetTree.ReadFrom` correspondingly read this discriminator byte to determine the node type.

### What RFC 9420 Section 12.4.3.3 Actually Requires

The standard MLS ratchet_tree extension determines node type by **position**, not by an explicit discriminator:

- Even positions (0, 2, 4, ...) are **leaf nodes**
- Odd positions (1, 3, 5, ...) are **parent nodes**

The wire format is simply:

```
[present=1][LeafNode bytes]   -- at even position
[present=1][ParentNode bytes] -- at odd position
[present=0]                   -- blank at any position
```

There is **no** `nodeType` byte.

### Why It Happened

The extra discriminator byte was likely added for implementation convenience -- it makes the serialization self-describing without needing a position counter. However, this violates the RFC and makes the format incompatible with every other MLS implementation.

When DotnetMls tried to deserialize a ratchet tree from an OpenMLS Welcome message, the first byte of the LeafNode data was misinterpreted as a `nodeType` discriminator, causing a cascade of parsing failures:

```
TlsDecodingException: Insufficient data: attempted to read 11408 byte(s)
at position 4, but only 28 byte(s) remain.
```

The 11408-byte read attempt came from the LeafNode parser misinterpreting bytes (shifted by one due to the missing discriminator) as a length field.

### What Was Fixed

**`RatchetTree.WriteTo` (RatchetTree.cs)**:
- Removed `inner.WriteUint8(1)` (leaf type) and `inner.WriteUint8(2)` (parent type) after the present flag

**`RatchetTree.ReadFrom` (RatchetTree.cs)**:
- Removed the `nodeType = sub.ReadUint8()` read
- Instead uses `TreeMath.IsLeaf(nodeIndex)` to determine whether to parse a LeafNode or ParentNode based on position

---

## Tests Added

Five new tests reproduce and verify the fixes:

| Test | Bug | What It Verifies |
|------|-----|-----------------|
| `WelcomeSecret_IsDerivedViaIntermediateSecret_PerRfc9420` | 1 | `Create` produces `welcome_secret` via intermediate extraction |
| `FromJoinerSecret_WelcomeSecret_IsDerivedViaIntermediateSecret` | 1 | `FromJoinerSecret` produces correct `welcome_secret` |
| `EpochSecret_IsDerivedViaIntermediateSecret_PerRfc9420` | 1 | `confirmation_key` (derived from epoch_secret) matches RFC derivation |
| `RatchetTree_Serialization_NoNodeTypeDiscriminator` | 2 | `WriteTo` format has no nodeType byte |
| `RatchetTree_ReadFrom_RfcCompliantFormat_RoundTrips` | 2 | `ReadFrom` correctly parses RFC-compliant (no nodeType) format |

All 5 tests **fail** before the fix and **pass** after. All 123 pre-existing tests continue to pass.

---

## Files Changed

| File | Changes |
|------|---------|
| `src/DotnetMls/KeySchedule/KeyScheduleEpoch.cs` | Fixed key schedule derivation in `Create` and `FromJoinerSecret` |
| `src/DotnetMls/Group/MlsGroup.cs` | Fixed welcome_secret in `ProcessWelcome`, added EncryptWithLabel for HPKE, added `BuildEncryptContext` helper, added `supportedExtensionTypes` to `CreateKeyPackage` |
| `src/DotnetMls/Tree/RatchetTree.cs` | Removed nodeType discriminator from `WriteTo` and `ReadFrom` |
| `tests/DotnetMls.Tests/MlsTests.cs` | Added 5 regression tests |

## Verification

```
dotnet test tests/DotnetMls.Tests  -- 128 passed, 0 failed
dotnet test                        -- 190 passed, 0 failed (including crypto tests)
```
