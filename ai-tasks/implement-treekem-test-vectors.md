# Implement TreeKEM Test Vectors (RFC 9420 Section 13.9)

## Priority: MEDIUM

## Background

The `treekem.json` test vector file (14,877 lines — the LARGEST vector file) exists in `tests/DotnetMls.Tests/TestVectors/` but has no corresponding test methods. TreeKEM is the core key agreement mechanism in MLS.

## Task

1. Read and understand the `treekem.json` format
2. Add test vector deserialization classes
3. Implement tests that validate:
   - TreeKEM path secret derivation
   - Node encryption/decryption with HPKE
   - UpdatePath generation and processing
   - Commit secret derivation from path secrets

## Files to modify

- `tests/DotnetMls.Tests/Rfc9420TestVectorTests.cs` — add test classes and methods

## Important

The tests MUST be fully implemented, compiled, and executed. If any test is red (failing), investigate and fix the underlying issue in the production code — do not skip or disable failing tests. A failing test vector means the implementation has a bug that must be diagnosed and resolved before the task is considered complete.

## Acceptance Criteria

- TreeKEM encryption/decryption round-trips match test vectors for cipher suite 0x0001
- Path secret derivation produces expected intermediate values
- UpdatePath processing yields expected tree state
- All tests green — any failures are investigated and the root cause fixed in the library code
