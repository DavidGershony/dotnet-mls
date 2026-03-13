# Implement Passive Client Test Vectors (RFC 9420 Section 13.11)

## Priority: LOW

## Background

Three passive client test vector files exist in `tests/DotnetMls.Tests/TestVectors/` but have no corresponding test methods:
- `passive-client-welcome.json` (813 lines) — passive client joining via Welcome
- `passive-client-random.json` (2,656 lines) — passive client with random operations
- `passive-client-handling-commit.json` (2,682 lines) — passive client handling commits

Total: 5,151 lines of unused test data.

These vectors simulate a client that only receives and processes messages (never sends), validating that the full protocol state machine works correctly from a receiver's perspective.

## Task

1. Read and understand each passive client vector format
2. Add test vector deserialization classes
3. Implement tests for each scenario:

### passive-client-welcome.json
- Process a Welcome message to join a group
- Verify the resulting group state (tree hash, group context, key schedule)

### passive-client-random.json
- Join a group, then process a sequence of Commits with various proposals
- Verify group state after each epoch transition

### passive-client-handling-commit.json
- Process Commit messages and verify correct epoch advancement
- Validate that the key schedule produces expected secrets after each commit

## Files to modify

- `tests/DotnetMls.Tests/Rfc9420TestVectorTests.cs` — add test classes and methods

## Important

The tests MUST be fully implemented, compiled, and executed. If any test is red (failing), investigate and fix the underlying issue in the production code — do not skip or disable failing tests. A failing test vector means the implementation has a bug that must be diagnosed and resolved before the task is considered complete.

## Acceptance Criteria

- Passive client can join via Welcome and reach expected group state
- Sequential commit processing produces expected key schedule outputs
- All three vector files are exercised for cipher suite 0x0001
- All tests green — any failures are investigated and the root cause fixed in the library code
