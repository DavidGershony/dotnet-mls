# Security Audit Findings — dotnet-mls

Date: 2026-04-10

## Critical

### [x] FIXED — DeriveKeyPair deviates from RFC 9180 §7.1.3
- **File:** src/DotnetMls/Tree/TreeKem.cs
- **Issue:** Used incorrect labels (`Extract([], nodeSecret)` + `Expand(prk, "MLS 1.0 node key", 32)`) instead of HPKE `LabeledExtract("", "dkp_prk", ikm)` + `LabeledExpand(dkp_prk, "sk", "", 32)` with `HPKE-v1 || KEM suite_id` prefixes.
- **Impact:** Breaks interop with any RFC-compliant MLS peer. Undermines HPKE security proof.
- **Fix:** Commit 375adba. Also rewired test vectors to call production `DeriveKeyPair` instead of a local reimplementation.

## High

### [ ] Unbounded allocations in TlsReader (DoS)
- **File:** src/DotnetMls/Codec/TlsReader.cs
- **Issue:** `ReadBytes(count)`, `ReadOpaque32()`, `ReadOpaque24()` allocate `new byte[count]` from attacker-controlled length prefixes. `ReadOpaque32` allows up to `int.MaxValue` (~2 GB).
- **Impact:** OOM crash from a single malformed message.
- **Fix:** Add a configurable max message size and reject length prefixes exceeding it.

## Medium

### [ ] Missing zeroization of sensitive data
- **Files:** src/DotnetMls/KeySchedule/KeyScheduleEpoch.cs, src/DotnetMls/Group/MlsGroup.cs
- **Issue:** Epoch secrets (InitSecret, SenderDataSecret, EncryptionSecret, etc.) and group-level private keys stored as plain `byte[]` with no `IDisposable`/zeroization. `SecretTree` partially clears consumed secrets but epoch-level secrets persist until GC.
- **Impact:** Keys recoverable from memory dumps.
- **Fix:** Implement `IDisposable` on `MlsGroup` and `KeyScheduleEpoch`; call `CryptographicOperations.ZeroMemory` in `Dispose()`.

### [ ] Hardcoded X25519 dependency in TreeKem
- **File:** src/DotnetMls/Tree/TreeKem.cs (DeriveKeyPair)
- **Issue:** `new X25519Provider()` instantiated directly; KEM suite_id hardcoded to `0x0020`. Won't adapt to non-X25519 cipher suites.
- **Impact:** Silently wrong keys if a different KEM is used.
- **Fix:** Add `DeriveKeyPairFromSeed(byte[] ikm)` to `ICipherSuite` so each suite handles its own KEM derivation.

## Low

### [ ] Verbose exception messages in codec layer
- **File:** src/DotnetMls/Codec/TlsReader.cs
- **Issue:** Exceptions include hex bytes and internal parsing state.
- **Impact:** Minor information leakage if exposed to protocol peers.

### [ ] No AEAD nonce-reuse guard
- **Files:** src/DotnetMls.Crypto/AesGcmProvider.cs, ChaCha20Poly1305Provider.cs
- **Issue:** No defensive nonce tracking at AEAD layer. SecretTree ratchet prevents reuse in normal operation.
- **Impact:** Defense-in-depth gap.

## Test Vector Coverage Gaps

### [x] FIXED — TreeKEM test vectors bypassed production DeriveKeyPair
- Rewired to call `TreeKem.DeriveKeyPair` directly. Fixed in commit 375adba.

### [ ] Welcome test reimplements logic inline
- **File:** tests/DotnetMls.Tests/Rfc9420TestVectorTests.cs (Welcome_ProcessWelcome_MatchesOfficialVectors)
- **Issue:** Manually does HPKE decrypt, key derivation, GroupInfo decryption, and signature verification instead of calling `MlsGroup.ProcessWelcome()`.
- **Risk:** Bugs in production Welcome processing not caught.

### [ ] Passive Client tests reimplement protocol inline
- **File:** tests/DotnetMls.Tests/Rfc9420TestVectorTests.cs (ProcessWelcomeForPassiveClient, ProcessEpochForPassiveClient)
- **Issue:** ~350 lines reimplementing Welcome processing, commit handling, UpdatePath decryption, tree mutation, key schedule, and transcript hash computation. Does not call `MlsGroup.ProcessWelcome()` or `MlsGroup.ProcessCommit()`.
- **Risk:** Production commit processing only tested by self-consistent round-trip tests (MlsTests) that can't catch single-sided bugs.

### [ ] Transcript Hash test uses manual computation
- **File:** tests/DotnetMls.Tests/Rfc9420TestVectorTests.cs (TranscriptHash_ConfirmedHash_MatchesOfficialVectors)
- **Issue:** Manual `cs.Hash(Concat(...))` instead of calling production `TranscriptHash` class methods.
- **Risk:** Low — simple enough to verify by reading, but still a coverage gap.
