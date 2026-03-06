# Fix Key Schedule and Ratchet Tree Parsing for OpenMLS Interop

## Context
Cross-MDK tests (Rust/OpenMLS creates group, C#/DotnetMls processes Welcome) revealed two bugs preventing interoperability. These were discovered via the `CrossMdk_RustCreatesGroup_ManagedAcceptsWelcome_ThroughRelay` test in openChat.

## Bug 1: Key Schedule - Wrong welcome_secret Derivation

### Problem
`KeyScheduleEpoch.Create`, `KeyScheduleEpoch.FromJoinerSecret`, and `MlsGroup.ProcessWelcome` derive `welcome_secret` directly from `joiner_secret`:
```csharp
var welcomeSecret = cs.ExpandWithLabel(joinerSecret, "welcome", Array.Empty<byte>(), nh);
```

But RFC 9420 Section 8 and OpenMLS require an intermediate `KDF.Extract` step:
```
psk_secret (or 0) -> KDF.Extract(salt=joiner_secret, ikm=psk_secret) = intermediate_secret
                         |
                         +--> DeriveSecret(., "welcome") = welcome_secret
                         |
                         V
                   ExpandWithLabel(., "epoch", GroupContext_[n], KDF.Nh) = epoch_secret
```

### Evidence from OpenMLS Source
- `IntermediateSecret::new()` in `openmls/src/schedule/mod.rs`: `joiner_secret.secret.hkdf_extract(crypto, ciphersuite, psk.secret())`
- `Secret::hkdf_extract()`: `self` = SALT, `ikm_option` = IKM (verified in `openmls/src/ciphersuite/secret.rs`)
- `WelcomeSecret::new()`: `intermediate_secret.secret.derive_secret(crypto, ciphersuite, "welcome")`
- When no PSKs: `PskSecret` = `Secret::zero(ciphersuite)` = zeros(32)

### Required Fix

**In `KeyScheduleEpoch.Create` (line ~166-183):**
Replace:
```csharp
// Step 2: welcome_secret directly from joiner_secret
var welcomeSecret = cs.ExpandWithLabel(joinerSecret, "welcome", Array.Empty<byte>(), nh);
// Step 3: member from joiner_secret
var member = cs.ExpandWithLabel(joinerSecret, "member", Array.Empty<byte>(), nh);
// Step 4: psk_secret default = Extract(zeros, zeros)
var effectivePskSecret = cs.Extract(zeros, zeros);
// Step 5: epoch_secret = Extract(member, psk_secret)
var epochSecret = cs.Extract(member, effectivePskSecret);
```
With:
```csharp
// Step 2: intermediate = KDF.Extract(salt=joiner_secret, ikm=psk_secret)
// psk_secret defaults to zeros(KDF.Nh) when no PSKs
var effectivePskSecret = pskSecret ?? new byte[nh];
if (effectivePskSecret.Length == 0) effectivePskSecret = new byte[nh];
var intermediateSecret = cs.Extract(joinerSecret, effectivePskSecret);
// Step 3: welcome_secret = DeriveSecret(intermediate, "welcome")
var welcomeSecret = cs.DeriveSecret(intermediateSecret, "welcome");
// Step 4: epoch_secret = ExpandWithLabel(intermediate, "epoch", GroupContext, Nh)
var epochSecret = cs.ExpandWithLabel(intermediateSecret, "epoch", groupContext, nh);
```

**Same fix in `KeyScheduleEpoch.FromJoinerSecret` (line ~284-299).**

**In `MlsGroup.ProcessWelcome` (line ~634-640):**
Replace:
```csharp
byte[] welcomeSecret = cs.ExpandWithLabel(
    groupSecrets.JoinerSecret, "welcome", Array.Empty<byte>(), cs.SecretSize);
```
With:
```csharp
byte[] pskSecret = new byte[cs.SecretSize]; // zeros(32) when no PSKs
byte[] intermediateSecret = cs.Extract(groupSecrets.JoinerSecret, pskSecret);
byte[] welcomeSecret = cs.ExpandWithLabel(
    intermediateSecret, "welcome", Array.Empty<byte>(), cs.SecretSize);
```

**Also in `MlsGroup.ProcessWelcome` - EncryptWithLabel for HPKE (line ~623-629):**
The HPKE info parameter needs EncryptWithLabel context. Replace:
```csharp
byte[] groupSecretsBytes = cs.HpkeOpen(
    myInitPrivateKey,
    mySecrets.EncryptedGroupSecretsValue.KemOutput,
    Array.Empty<byte>(), // info
    Array.Empty<byte>(), // aad
    mySecrets.EncryptedGroupSecretsValue.Ciphertext);
```
With (using BuildEncryptContext helper from the Commit/Welcome creation path):
```csharp
byte[] hpkeInfo = BuildEncryptContext("Welcome", welcome.EncryptedGroupInfo);
byte[] groupSecretsBytes = cs.HpkeOpen(
    myInitPrivateKey,
    mySecrets.EncryptedGroupSecretsValue.KemOutput,
    hpkeInfo,
    Array.Empty<byte>(), // aad
    mySecrets.EncryptedGroupSecretsValue.Ciphertext);
```

**Also in Welcome creation (`MlsGroup.cs` line ~948-951) - same EncryptWithLabel fix:**
Replace:
```csharp
byte[] sealed_ = _cs.HpkeSeal(
    initKey, Array.Empty<byte>(), Array.Empty<byte>(), gsBytes);
```
With:
```csharp
byte[] hpkeInfo = BuildEncryptContext("Welcome", encryptedGroupInfo);
byte[] sealed_ = _cs.HpkeSeal(initKey, hpkeInfo, Array.Empty<byte>(), gsBytes);
```

**Also `CreateKeyPackage` needs `supportedExtensionTypes` parameter** so Rust groups with required_capabilities for extension 0xF2EE accept the KeyPackage. Add an optional parameter:
```csharp
public static KeyPackage CreateKeyPackage(
    ICipherSuite cs, byte[] identity, byte[] signingPrivateKey, byte[] signingPublicKey,
    out byte[] initPrivateKey, out byte[] hpkePrivateKey,
    ushort[]? supportedExtensionTypes = null)
```
And apply to capabilities:
```csharp
var capabilities = CreateDefaultCapabilities(cs);
if (supportedExtensionTypes is { Length: > 0 })
    capabilities.Extensions = supportedExtensionTypes;
```

### Verification
- Existing test `CommitAddMember_WelcomeCanBeProcessed` must still pass (C#-to-C# round-trip)
- The key schedule fix was verified: with the intermediate Extract step applied to BOTH Create and FromJoinerSecret, the C#-only test passes AND the cross-MDK AEAD decryption of GroupInfo succeeds

## Bug 2: Ratchet Tree Serialization Format Mismatch

### Problem
After fixing Bug 1, the Welcome processing gets past GroupInfo decryption but fails parsing the ratchet tree extension with:
```
TlsDecodingException: Insufficient data: attempted to read 11408 byte(s) at position 4, but only 28 byte(s) remain.
```
at `RatchetTree.ReadFrom -> LeafNode.ReadFrom -> LeafNode.ReadExtensionList -> Extension.ReadFrom -> TlsReader.ReadOpaqueV`

### Root Cause
`RatchetTree.ReadFrom` (line ~467) uses a custom format with explicit `nodeType` byte:
```csharp
byte present = sub.ReadUint8();  // 0 or 1
if (present == 1) {
    byte nodeType = sub.ReadUint8();  // 1=leaf, 2=parent
```

But the standard MLS ratchet_tree extension (RFC 9420 Section 12.4.3.3) determines node type from position:
- Even positions (0, 2, 4, ...) are leaves: `optional<LeafNode>`
- Odd positions (1, 3, 5, ...) are parents: `optional<ParentNode>`

There is NO explicit `nodeType` discriminator byte in the standard format. Each entry is just:
```
uint8 present;
if (present == 1) { LeafNode | ParentNode }  // type determined by position
```

### Required Fix
`RatchetTree.ReadFrom` should use position-based type detection:
```csharp
while (!sub.IsEmpty)
{
    byte present = sub.ReadUint8();
    if (present == 0)
    {
        // Blank node
        if (TreeMath.IsLeaf(nodeIndex))
            tree._nodes.Add(new TreeNode.Leaf(null));
        else
            tree._nodes.Add(new TreeNode.Parent(null));
    }
    else
    {
        // Present node - type determined by position, NOT by a discriminator byte
        if (TreeMath.IsLeaf(nodeIndex))
        {
            var leafNode = LeafNode.ReadFrom(sub);
            tree._nodes.Add(new TreeNode.Leaf(leafNode));
        }
        else
        {
            var parentNode = ParentNode.ReadFrom(sub);
            tree._nodes.Add(new TreeNode.Parent(parentNode));
        }
    }
    nodeIndex++;
}
```

Also fix `WriteTo` to NOT write the `nodeType` byte (remove `inner.WriteUint8(1)` for leaf and `inner.WriteUint8(2)` for parent).

### Verification
After fixing both bugs, clone OpenMLS locally and compare ratchet tree serialization format if needed:
```bash
git clone https://github.com/openmls/openmls.git C:\Users\david\openCodeProjects\openmls --depth 1
```
Reference files:
- `openmls/src/extensions/ratchet_tree_extension.rs` - serialization format
- `openmls/src/treesync/node.rs` - Node type
- `openmls/src/schedule/mod.rs` - key schedule

### Test Plan
1. Run existing tests: `dotnet test tests/DotnetMls.Tests` - all must pass
2. Especially: `CommitAddMember_WelcomeCanBeProcessed` (C#-to-C# Welcome round-trip)
3. After fixing, the cross-MDK test in openChat should pass:
   `dotnet test tests/OpenChat.Core.Tests --filter "CrossMdk"`
