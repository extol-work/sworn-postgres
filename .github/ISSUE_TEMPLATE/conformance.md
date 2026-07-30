---
name: Conformance test proposal
about: Propose a new test case for the conformance suite
title: "[conformance] "
labels: conformance
---

## What behavior does this test?

Which SWORN spec section (or which invariant across sections) does the test verify?

## Why is this test necessary?

What class of implementation bug does it catch that isn't caught by existing tests?

## Test cases (input / expected)

```
Input:  <describe or attach>
Expected: <describe or attach>
```

## Cross-implementation applicability

Is this test something ANY SWORN implementation should pass, or is it Postgres-specific? (Only cross-implementation-applicable tests belong in `conformance/`; Postgres-specific tests go in `store/`.)
