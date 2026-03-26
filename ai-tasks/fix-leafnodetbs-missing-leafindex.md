# Bug: LeafNodeTBS missing leaf_index for Update/Commit sources

## Summary

`MlsGroup.SignLeafNode()` does not include `leaf_index` (uint32) in the `LeafNodeTBS`
for Update and Commit-sourced leaf nodes. RFC 9420 Section 7.2 requires both `group_id`
and `leaf_index` in the TBS for these sources. This causes cross-implementation signature
verification failures — other MLS implementations (ts-mls, OpenMLS) reject leaf node
signatures produced by DotnetMls.

## RFC 9420 Section 7.2 — LeafNodeTBS

```
struct {
    ProtocolVersion version = mls10;
    CipherSuite cipher_suite;
    HPKEPublicKey encryption_key;
    SignaturePublicKey signature_key;
    Credential credential;
    Capabilities capabilities;

    select (LeafNodeTBS.leaf_node_source) {
        case key_package:
            Lifetime lifetime;
        case update:
            /* nothing source-specific, but context below */
        case commit:
            opaque parent_hash<V>;
    };

    Extension extensions<V>;

    /* Context appended for TBS only (not in the wire LeafNode): */
    select (LeafNodeTBS.leaf_node_source) {
        case key_package:
            /* no additional context */
        case update:
            opaque group_id<V>;
            uint32 leaf_index;          <-- MISSING IN DOTNETMLS
        case commit:
            opaque group_id<V>;
            uint32 leaf_index;          <-- MISSING IN DOTNETMLS
    };
} LeafNodeTBS;
```

## Current Code (BUGGY)

File: `src/DotnetMls/Group/MlsGroup.cs`, line ~943

```csharp
private static void SignLeafNode(
    ICipherSuite cs, LeafNode leafNode, byte[] signingPrivateKey, byte[]? groupId)
{
    byte[] tbs = TlsCodec.Serialize(writer =>
    {
        writer.WriteOpaqueV(leafNode.EncryptionKey);
        writer.WriteOpaqueV(leafNode.SignatureKey);
        leafNode.Credential.WriteTo(writer);
        leafNode.Capabilities.WriteTo(writer);
        writer.WriteUint8((byte)leafNode.Source);
        if (leafNode.Source == LeafNodeSource.KeyPackage && leafNode.Lifetime != null)
        {
            leafNode.Lifetime.WriteTo(writer);
        }
        writer.WriteVectorV(inner =>
        {
            foreach (var ext in leafNode.Extensions)
                ext.WriteTo(inner);
        });
        if (leafNode.Source == LeafNodeSource.Update ||
            leafNode.Source == LeafNodeSource.Commit)
        {
            if (groupId != null)
                writer.WriteOpaqueV(groupId);
            // BUG: Missing writer.WriteUint32(leafIndex) here!
        }
    });

    leafNode.Signature = cs.SignWithLabel(signingPrivateKey, "LeafNodeTBS", tbs);
}
```

## Impact

- **Cross-implementation interop broken**: ts-mls (used by marmot-ts web client) correctly
  includes `leaf_index` in the TBS and rejects DotnetMls leaf node signatures with
  "Could not verify leaf node signature"
- **Self-verification works**: DotnetMls sign and verify use the same (wrong) TBS format,
  so round-trip tests pass. Only cross-impl scenarios fail.
- **Affects all Commit and Update operations**: Every time a group member commits or updates
  their leaf, the signature is wrong. KeyPackage-sourced leaves are NOT affected (no context).

## Fix Required

1. Add `uint leafIndex` parameter to `SignLeafNode`
2. Write `writer.WriteUint32(leafIndex)` after `groupId` for Update/Commit sources
3. Update all call sites to pass the correct leaf index:
   - `CreateGroup`: leaf index = 0 (creator is always first leaf)
   - `Commit`: leaf index = `_myLeafIndex`
   - `CreateKeyPackage`: not affected (KeyPackage source)
4. Also update `VerifyLeafNodeSignature` (if it exists) to include `leafIndex` in TBS reconstruction

## Why Tests Didn't Catch This — Detailed Analysis

### 1. RFC 9420 Test Vectors (Rfc9420TestVectorTests.cs)

| Test | What it verifies | Catches this bug? |
|------|-----------------|-------------------|
| `CryptoBasics_SignWithLabel_VerifiesOfficialVectors` (line 287) | SignWithLabel crypto primitive round-trip | NO — tests sign/verify with pre-built content, doesn't test TBS construction |
| `Welcome_ProcessWelcome_MatchesOfficialVectors` (line 1070) | GroupInfo deserialization + GroupInfoTBS signature | NO — verifies GroupInfo signature, not leaf node signatures |
| `PassiveClient_Welcome_MatchesOfficialVectors` (line 2470) | Full Welcome → key schedule | NO — verifies epoch_authenticator but never calls VerifyLeafNodeSignature |
| `PassiveClient_HandlingCommit_MatchesOfficialVectors` (line 2495) | Commit processing + FramedContentTBS | NO — verifies FramedContentTBS (commit signature), not LeafNodeTBS |
| `TreeValidation_TreeHash_MatchesOfficialVectors` (line 1387) | Tree hash computation | NO — computes hashes, doesn't verify signatures |

**Key gap**: No test reconstructs LeafNodeTBS and verifies a leaf node signature against
the RFC test vectors. The passive client tests skip leaf signature verification entirely.

### 2. Cross-MDK Tests (verify/openmls-cross-validation branch)

| Test | What it verifies | Catches this bug? |
|------|-----------------|-------------------|
| `SignWithLabel_CrossValidation` (line ~568) | C# signs → Rust verifies (and vice versa) | NO — uses pre-built content bytes, doesn't construct LeafNodeTBS |
| Commit processing tests | Tree updates during commit | PARTIALLY — updates tree and processes commits, but signature verification inside MlsGroup uses the same buggy TBS construction |

### 3. Self-contained tests (MlsTests.cs)

Only codec round-trips, tree math, and key schedule tests. No group lifecycle tests
(CreateGroup → AddMember → verify leaf signatures).

### What's Needed

A test that:
1. Creates a group (produces a Commit-sourced leaf node)
2. Extracts the leaf node from the ratchet tree
3. Reconstructs the LeafNodeTBS with `group_id` AND `leaf_index`
4. Verifies the signature against the RFC-specified TBS format
5. **Cross-validates** by computing the TBS the way ts-mls does and checking if the signature matches

This would catch the missing `leaf_index` immediately because step 4 would produce
different bytes from what was signed (missing 4 bytes of `uint32 leaf_index`).

## Second Bug Found: Signing Before Encap Mutates EncryptionKey

In `MlsGroup.Commit()`, `SignLeafNode` is called BEFORE `TreeKem.Encap()`. But Encap
modifies `newLeafNode.EncryptionKey` with a derived key (line ~61 of TreeKem.cs):
```csharp
newLeafNode.EncryptionKey = leafPub;  // AFTER SignLeafNode was already called!
```

This means the signature covers the original `EncryptionKey`, but the leaf node in the
tree (and in the Welcome) has the Encap-derived `EncryptionKey`. Any verifier that
reconstructs the TBS from the tree's leaf will use the wrong key, causing verification failure.

**Fix**: Move `SignLeafNode` to AFTER `TreeKem.Encap` completes, so the signature covers
the final `EncryptionKey`. The `ParentHash` must also be set before signing if required.

## Confirmed By

- ts-mls source: `src/leafNode.ts` — `leafNodeInfoCommitEncoder` includes
  `[..., varLenDataEncoder(groupId), uint32Encoder(leafIndex)]`
- RFC 9420 Section 7.2 — explicit `uint32 leaf_index` in LeafNodeTBS for update/commit
- Web client error: "Could not verify leaf node signature" when processing Welcome from OpenChat
