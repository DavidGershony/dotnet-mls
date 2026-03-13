# Implement Tree Operations Test Vectors (RFC 9420 Section 13.8)

## Priority: LOW

## Background

The `tree-operations.json` test vector file (47 lines) exists in `tests/DotnetMls.Tests/TestVectors/` but has no corresponding test methods. These vectors validate tree modification operations (add, remove, update).

## Task

1. Read and understand the `tree-operations.json` format
2. Add test vector deserialization classes
3. Implement tests that validate tree add/remove/update operations produce the expected ratchet tree state

## Files to modify

- `tests/DotnetMls.Tests/Rfc9420TestVectorTests.cs` — add test classes and methods

## Important

The tests MUST be fully implemented, compiled, and executed. If any test is red (failing), investigate and fix the underlying issue in the production code — do not skip or disable failing tests. A failing test vector means the implementation has a bug that must be diagnosed and resolved before the task is considered complete.

## Acceptance Criteria

- Tree operation tests pass for cipher suite 0x0001
- Tests validate that applying proposals to a tree produces the expected tree hash
- All tests green — any failures are investigated and the root cause fixed in the library code
