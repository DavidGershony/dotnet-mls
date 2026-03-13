# Implement Messages Test Vectors (RFC 9420 Section 13.10)

## Priority: MEDIUM

## Background

The `messages.json` test vector file (5,701 lines) exists in `tests/DotnetMls.Tests/TestVectors/` but has no corresponding test methods. These vectors validate TLS serialization/deserialization of all MLS message types.

## Task

1. Add test vector deserialization classes for `messages.json`
2. Implement tests that validate TLS deserialization of:
   - `mls_welcome` — Welcome message
   - `mls_group_info` — GroupInfo
   - `mls_key_package` — KeyPackage
   - `ratchet_tree` — RatchetTree serialization
   - `group_secrets` — GroupSecrets
   - `add_proposal`, `update_proposal`, `remove_proposal` — Proposal types
   - `pre_shared_key_proposal`, `re_init_proposal`, `external_init_proposal` — Special proposals
   - `commit` — Commit message
   - `public_message_application`, `public_message_proposal`, `public_message_commit` — PublicMessage variants
   - `private_message` — PrivateMessage serialization

3. For each message type: deserialize from hex, re-serialize, verify round-trip produces identical bytes

## Files to modify

- `tests/DotnetMls.Tests/Rfc9420TestVectorTests.cs` — add test classes and methods

## Important

The tests MUST be fully implemented, compiled, and executed. If any test is red (failing), investigate and fix the underlying issue in the production code — do not skip or disable failing tests. A failing test vector means the implementation has a bug that must be diagnosed and resolved before the task is considered complete.

## Acceptance Criteria

- All message type deserialization tests pass for all cipher suites in the vector file
- Round-trip (deserialize → serialize → compare) produces identical bytes
- All tests green — any failures are investigated and the root cause fixed in the library code
