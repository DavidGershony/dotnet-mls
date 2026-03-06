# RFC 9420 Official Test Vectors

## Overview

We downloaded all 15 official test vector files from the [MLSWG test vectors repository](https://github.com/mlswg/mls-implementations/tree/main/test-vectors) and implemented tests against them for cipher suite 0x0001 (MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519).

Test file: `tests/DotnetMls.Tests/Rfc9420TestVectorTests.cs`

---

## Implemented Tests (15 tests, all passing)

### Tree Math (`tree-math.json`)

| Test | What It Verifies |
|------|-----------------|
| `TreeMath_MatchesOfficialVectors` | `NodeCount`, `Root`, `Left`, `Right`, `Parent`, `Sibling` for all tree sizes in the vectors |

### Crypto Basics (`crypto-basics.json`)

| Test | What It Verifies |
|------|-----------------|
| `CryptoBasics_ExpandWithLabel_MatchesOfficialVectors` | `ExpandWithLabel` with VarInt-encoded KDFLabel struct |
| `CryptoBasics_DeriveSecret_MatchesOfficialVectors` | `DeriveSecret(secret, label)` = `ExpandWithLabel(secret, label, "", Nh)` |
| `CryptoBasics_RefHash_MatchesOfficialVectors` | `RefHash(label, value)` with VarInt length prefixes |
| `CryptoBasics_SignWithLabel_VerifiesOfficialVectors` | Ed25519 `SignWithLabel`/`VerifyWithLabel` with VarInt-encoded SignContent |
| `CryptoBasics_EncryptWithLabel_DecryptsOfficialVectors` | HPKE `EncryptWithLabel`/Open with EncryptContext info struct |
| `CryptoBasics_DeriveTreeSecret_MatchesOfficialVectors` | `DeriveTreeSecret(secret, label, generation, length)` = `ExpandWithLabel` with `uint32(generation)` context |

### Key Schedule (`key-schedule.json`)

| Test | What It Verifies |
|------|-----------------|
| `KeySchedule_JoinerSecret_MatchesOfficialVectors` | Joiner secret derivation: `Extract(init_secret, commit_secret)` then `ExpandWithLabel(., "joiner", GroupContext, Nh)` |
| `KeySchedule_MatchesOfficialVectors` | Full key schedule across all epochs: joiner_secret, welcome_secret, all per-epoch secrets (sender_data, encryption, exporter, authentication, external, confirm, membership, resumption, init), plus MLS-Exporter |

### Deserialization (`deserialization.json`)

| Test | What It Verifies |
|------|-----------------|
| `Deserialization_VarInt_MatchesOfficialVectors` | QUIC VarInt (RFC 9000 section 16) encode/decode round-trips |

### Transcript Hashes (`transcript-hashes.json`)

| Test | What It Verifies |
|------|-----------------|
| `TranscriptHash_ConfirmedHash_MatchesOfficialVectors` | Confirmed transcript hash computation from `interim_before + ConfirmedTranscriptHashInput`, interim transcript hash from `confirmed_hash + VarInt(confirmation_tag)`, and confirmation tag = `MAC(key, confirmed_hash)` |

### Secret Tree (`secret-tree.json`)

| Test | What It Verifies |
|------|-----------------|
| `SecretTree_MatchesOfficialVectors` | Full secret tree derivation for 1, 8, and 32 leaf trees: tree node derivation with "left"/"right" contexts, handshake/application ratchet initialization, key/nonce derivation with `uint32(generation)` context, ratchet advancement across non-consecutive generations |
| `SecretTree_SenderDataKey_MatchesOfficialVectors` | Sender data key/nonce derivation from `sender_data_secret` using first `Nh` bytes of ciphertext as sample |

---

## Bugs Found and Fixed

The test vectors revealed several additional bugs beyond the earlier interop fixes:

### 1. Key Schedule: Joiner Secret Derivation Order (KeyScheduleEpoch.cs)

**Wrong:** `ExpandWithLabel(init_secret, "joiner", GroupContext, Nh)` then `Extract(result, commit_secret)`

**Correct (RFC 9420 section 8):**
```
extracted      = KDF.Extract(salt=init_secret, ikm=commit_secret)
joiner_secret  = ExpandWithLabel(extracted, "joiner", GroupContext, Nh)
```

The Extract happens FIRST, then the ExpandWithLabel.

### 2. Secret Tree: Node Derivation Context (SecretTree.cs)

**Wrong:** `ExpandWithLabel(parent, "tree", [0x00], Nh)` / `[0x01]`

**Correct (RFC 9420 section 9):** `ExpandWithLabel(parent, "tree", "left", Nh)` / `"right"`

The context is the ASCII strings "left" and "right", not single bytes.

### 3. Secret Tree: Ratchet Key/Nonce Context (SecretTree.cs)

**Wrong:** `ExpandWithLabel(secret, "key", "", Nk)` (empty context)

**Correct (RFC 9420 section 9):** Uses `DeriveTreeSecret` which passes `uint32(generation)` as context:
```
ratchet_key[j]   = DeriveTreeSecret(secret[j], "key", j, Nk)
ratchet_nonce[j] = DeriveTreeSecret(secret[j], "nonce", j, Nn)
secret[j+1]      = DeriveTreeSecret(secret[j], "secret", j, Nh)
```

### 4. Secret Tree: Ratchet Re-access After Erasure (SecretTree.cs)

After both handshake and application ratchets are initialized from a leaf secret, the leaf secret is erased for forward secrecy. Subsequent calls to `GetKeyAndNonceForGeneration` tried to re-derive the leaf secret, hitting "Root node has no parent" for single-leaf trees. Fixed by checking if the ratchet is already initialized before calling `EnsureLeafDerived`.

---

## Test Vectors Not Yet Implemented

These test vector files are downloaded but don't have tests yet. They require functionality that either doesn't exist yet or would need significant parsing work:

### Can Be Added Soon

| File | What It Tests | What's Needed |
|------|--------------|---------------|
| `psk_secret.json` | PSK secret computation from multiple PSKs | Implement `ComputePskSecret` per RFC 9420 section 8.4 (iterative Extract/ExpandWithLabel folding) |
| `welcome.json` | Full Welcome message processing | Parse Welcome TLS structure and verify decryption end-to-end |
| `tree-operations.json` | Add/Update/Remove operations on ratchet trees | Verify tree state after each operation matches expected |

### Requires More Infrastructure

| File | What It Tests | What's Needed |
|------|--------------|---------------|
| `treekem.json` | TreeKEM path secret derivation and encryption | Full TreeKEM implementation with path secret computation and HPKE encryption/decryption per path node |
| `tree-validation.json` | Ratchet tree validation (parent hash, signatures) | Tree validation logic including parent hash verification and leaf node signature checking |
| `messages.json` | MLS message serialization/deserialization | Full TLS codec for all MLS message types (PublicMessage, PrivateMessage, Welcome, GroupInfo, KeyPackage) |
| `passive-client-welcome.json` | Passive client joining via Welcome | Full Welcome processing pipeline including tree construction from welcome |
| `passive-client-handling-commit.json` | Passive client processing Commits | Commit processing including proposal application and tree updates |
| `passive-client-random.json` | Passive client with random operations | Full group operation processing (multiple proposal types, commits, tree updates) |

---

## Files Changed

| File | Changes |
|------|---------|
| `src/DotnetMls/KeySchedule/KeyScheduleEpoch.cs` | Fixed joiner_secret derivation order (Extract before ExpandWithLabel) |
| `src/DotnetMls/KeySchedule/SecretTree.cs` | Fixed tree node context ("left"/"right"), ratchet DeriveTreeSecret context (uint32 generation), and re-access after erasure bug |
| `src/DotnetMls.Crypto/CipherSuite0x0001.cs` | Changed ExpandWithLabel/RefHash/SignWithLabel to use VarInt length prefixes per RFC 9420 |
| `tests/DotnetMls.Tests/Rfc9420TestVectorTests.cs` | 15 new test methods against official test vectors |
| `tests/DotnetMls.Tests/DotnetMls.Tests.csproj` | Added System.Text.Json, DotnetMls.Crypto project reference, test vector file copy |
| `tests/DotnetMls.Tests/TestVectors/*.json` | 15 official test vector files from mlswg/mls-implementations |

## Verification

```
dotnet test  -- 203 passed, 0 failed (62 crypto + 141 main)
```
