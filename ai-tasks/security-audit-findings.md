# Security Audit Findings — dotnet-mls

Last updated: 2026-04-10

## Critical

### [x] FIXED — DeriveKeyPair deviates from RFC 9180 §7.1.3
- **File:** src/DotnetMls/Tree/TreeKem.cs
- **Issue:** Used incorrect labels (`Extract([], nodeSecret)` + `Expand(prk, "MLS 1.0 node key", 32)`) instead of HPKE `LabeledExtract("", "dkp_prk", ikm)` + `LabeledExpand(dkp_prk, "sk", "", 32)` with `HPKE-v1 || KEM suite_id` prefixes.
- **Impact:** Breaks interop with any RFC-compliant MLS peer. Undermines HPKE security proof.
- **Fix:** Commit 375adba. Also rewired test vectors to call production `DeriveKeyPair` instead of a local reimplementation.

### [x] FIXED — ProcessCommitCore, Encap, and HPKE encryption non-compliant
- **Files:** src/DotnetMls/Group/MlsGroup.cs, src/DotnetMls/Tree/TreeKem.cs, src/DotnetMls/KeySchedule/TranscriptHash.cs
- **Issue:** Multiple RFC 9420 deviations: EncryptPathSecret used raw groupContext instead of EncryptWithLabel format; transcript hash computed from FramedContentTBS instead of ConfirmedTranscriptHashInput; provisional GroupContext had empty fields instead of old confirmed_transcript_hash; no filtered direct path; no proposal type ordering; no PSK support; no unmerged leaf tracking for added members.
- **Impact:** Broke interop for any commit processing with RFC-compliant peers. Welcome-only flows were unaffected.
- **Fix:** Commit a8e4417. Passive client tests now call production MlsGroup.ProcessWelcome and MlsGroup.ProcessCommit.

## High

### [x] FIXED — Unbounded allocations in TlsReader (DoS)
- **File:** src/DotnetMls/Codec/TlsReader.cs
- **Issue:** `ReadBytes(count)` allocated `new byte[count]` from attacker-controlled length prefixes with no cap beyond the buffer size.
- **Fix:** Added configurable `maxElementSize` parameter (default 4 MB) to all TlsReader constructors. `ReadBytes` rejects any element exceeding the limit before allocating. Sub-readers inherit the limit. All 354 tests pass with the default.

## Medium

### [ ] Missing zeroization of sensitive data
- **Files:** src/DotnetMls/KeySchedule/KeyScheduleEpoch.cs, src/DotnetMls/Group/MlsGroup.cs
- **Issue:** None of `MlsGroup`, `KeyScheduleEpoch`, or `SecretTree` implement `IDisposable`. Epoch secrets (InitSecret, SenderDataSecret, EncryptionSecret, ConfirmationKey, MembershipKey, ResumptionPsk, etc.) stored as plain `byte[]` with no cleanup. `SecretTree` partially clears consumed secrets via `Array.Clear` (forward-secrecy for ratcheted nodes) but epoch-level secrets and group-level private keys persist until GC.
- **Impact:** Keys recoverable from memory dumps. `Array.Clear` in SecretTree is not guaranteed non-optimizable (should use `CryptographicOperations.ZeroMemory`).
- **Fix:** Implement `IDisposable` on `MlsGroup`, `KeyScheduleEpoch`, and `SecretTree`; call `CryptographicOperations.ZeroMemory` in `Dispose()`. Replace `Array.Clear` in SecretTree with `CryptographicOperations.ZeroMemory`.

### [ ] Hardcoded X25519 dependency in TreeKem
- **File:** src/DotnetMls/Tree/TreeKem.cs (DeriveKeyPair, lines ~340-360)
- **Issue:** `new X25519Provider()` instantiated directly (line ~359); KEM suite_id hardcoded to `{ 0x4B, 0x45, 0x4D, 0x00, 0x20 }` (line ~343). Won't adapt to non-X25519 cipher suites. `ICipherSuite` already has `DeriveHpkeKeyPair(byte[] ikm)` which would handle this correctly.
- **Impact:** Silently wrong keys if a non-X25519 cipher suite is used. Currently safe because only cipher suites 0x0001 and 0x0003 are implemented (both use X25519).
- **Fix:** Replace `TreeKem.DeriveKeyPair` internals with a call to `cs.DeriveHpkeKeyPair(nodeSecret)`, eliminating both the hardcoded suite_id and the direct X25519Provider instantiation.

## Low

### [ ] Verbose exception messages in codec layer
- **File:** src/DotnetMls/Codec/TlsReader.cs
- **Issue:** Exceptions include hex bytes and internal parsing state.
- **Impact:** Minor information leakage if exposed to protocol peers.

### [ ] No AEAD nonce-reuse guard at provider level
- **Files:** src/DotnetMls.Crypto/AesGcmProvider.cs, ChaCha20Poly1305Provider.cs
- **Issue:** AEAD providers are stateless wrappers with no nonce tracking. `SecretTree` ratchet prevents reuse in normal operation via generation monotonicity (throws on `generation < current`) and secret erasure after derivation. However, nothing prevents a caller from bypassing `SecretTree` and passing an arbitrary nonce directly to the provider.
- **Impact:** Defense-in-depth gap. Low risk since all encryption in MlsGroup goes through SecretTree. No protection against state loss on crash/restart if ratchet generation is not persisted.

## Test Vector Coverage Gaps

### [x] FIXED — TreeKEM test vectors bypassed production DeriveKeyPair
- Rewired to call `TreeKem.DeriveKeyPair` directly. Fixed in commit 375adba.

### [x] FIXED — Passive Client tests reimplemented protocol inline
- **Was:** ~350 lines reimplementing Welcome processing, commit handling, UpdatePath decryption, tree mutation, key schedule, and transcript hash computation. Did not call production code.
- **Fix:** Commit a8e4417. `ProcessWelcomeForPassiveClient` now calls `MlsGroup.ProcessWelcome()`. `ProcessEpochForPassiveClient` now calls `MlsGroup.CacheProposal()` + `MlsGroup.ProcessCommit()`. `PassiveClientState` class removed.

### [x] FIXED — Transcript Hash test used manual computation
- **Was:** Manual `cs.Hash(Concat(...))` instead of calling production `TranscriptHash` class.
- **Fix:** Commit a8e4417. Test now creates `TranscriptHash` instance and calls `Update()`, asserting against production `ConfirmedTranscriptHash` and `InterimTranscriptHash` properties.

### [ ] Welcome test reimplements logic inline
- **File:** tests/DotnetMls.Tests/Rfc9420TestVectorTests.cs (Welcome_ProcessWelcome_MatchesOfficialVectors)
- **Issue:** Manually does HPKE decrypt, key derivation, GroupInfo decryption, and signature verification instead of calling `MlsGroup.ProcessWelcome()`.
- **Risk:** Bugs in production Welcome processing not caught by this specific test. Mitigated by passive client tests now using production ProcessWelcome.
