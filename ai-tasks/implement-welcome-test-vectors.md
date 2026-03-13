# Implement Welcome Test Vectors (RFC 9420 Section 13.7)

## Priority: MEDIUM

## Background

The `welcome.json` test vector file (51 lines) exists in `tests/DotnetMls.Tests/TestVectors/` but has no corresponding test methods. Welcome messages are critical for group join flow.

## Task

1. Add test vector deserialization classes for `welcome.json`
2. Implement tests that validate:
   - Welcome message TLS deserialization (parse the hex bytes)
   - GroupSecrets decryption from Welcome using the joiner's HPKE private key
   - GroupInfo extraction and validation
   - Cipher suite handling across multiple cipher suites (file contains suites 1-7)

## Test Vector Format

The `welcome.json` file contains Welcome messages with associated KeyPackages and GroupInfo. Each entry has `cipher_suite` and hex-encoded `welcome`, `key_package`, `init_priv` fields.

## Files to modify

- `tests/DotnetMls.Tests/Rfc9420TestVectorTests.cs` — add test classes and methods

## Important

The tests MUST be fully implemented, compiled, and executed. If any test is red (failing), investigate and fix the underlying issue in the production code — do not skip or disable failing tests. A failing test vector means the implementation has a bug that must be diagnosed and resolved before the task is considered complete.

## Acceptance Criteria

- Welcome deserialization test passes for cipher suite 0x0001
- GroupSecrets can be decrypted from the Welcome using the test vector's init private key
- All tests green — any failures are investigated and the root cause fixed in the library code
