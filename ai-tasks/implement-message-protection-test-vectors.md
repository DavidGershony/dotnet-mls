# Implement Message Protection Test Vectors (RFC 9420 Section 13.3)

## Priority: HIGH

This is the most critical missing test coverage. These test vectors validate the full PrivateMessage encrypt/decrypt path including sender data key derivation, reuse_guard XOR, and content AEAD.

## Background

Two bugs were found and fixed in `MessageFraming.cs` that would have been caught by these tests:
1. `GetCiphertextSample` used `AeadKeySize` (Nk=16) instead of `HashSize` (Nh=32)
2. `reuse_guard` was not XORed with the content nonce before AEAD encrypt/decrypt

We currently have NO message-protection test vector file. The official RFC 9420 test vectors for this section are available at:
https://github.com/mlswg/mls-implementations/tree/main/test-vectors

## Task

1. Download the `message-protection.json` test vector file from the MLSWG test vectors repository
2. Place it in `tests/DotnetMls.Tests/TestVectors/`
3. Add test vector deserialization classes in `Rfc9420TestVectorTests.cs`
4. Implement tests that validate:
   - Sender data key/nonce derivation from `sender_data_secret` and ciphertext
   - PrivateMessage decryption (given known keys, verify plaintext matches)
   - PublicMessage signature verification
   - Content type handling (application, proposal, commit)

## Test Vector Format (RFC 9420 Section 13.3)

```json
{
  "cipher_suite": 1,
  "group_id": "hex",
  "epoch": 0,
  "tree_hash": "hex",
  "confirmed_transcript_hash": "hex",
  "signature_priv": "hex",
  "signature_pub": "hex",
  "encryption_secret": "hex",
  "sender_data_secret": "hex",
  "membership_key": "hex",
  "proposal": "hex",
  "proposal_pub": "hex",
  "proposal_priv": "hex",
  "commit": "hex",
  "commit_pub": "hex",
  "commit_priv": "hex",
  "application": "hex",
  "application_priv": "hex"
}
```

## Files to modify

- `tests/DotnetMls.Tests/Rfc9420TestVectorTests.cs` — add test classes and methods
- `tests/DotnetMls.Tests/TestVectors/` — add test vector file

## Important

The tests MUST be fully implemented, compiled, and executed. If any test is red (failing), investigate and fix the underlying issue in the production code — do not skip or disable failing tests. A failing test vector means the implementation has a bug that must be diagnosed and resolved before the task is considered complete.

## Acceptance Criteria

- All message-protection test vector tests pass for cipher suite 0x0001
- Tests call production code paths (`CreatePrivateMessage`, `DecryptPrivateMessage`)
- Tests validate intermediate values (sender data key, nonce, ciphertext sample)
- All tests green — any failures are investigated and the root cause fixed in the library code
