Status: open
Source: session-audit 2026-10-01, `feat/h12-secure-updates` (uncommitted working tree) — audit nit

## What's wrong

A tautological filler assertion exists only to consume destructured variables:

```
tests/h12-secure-updates.test.ts:412: assert.ok(v1.releaseVersion === 1 && v1sig.length > 0, 'v1 fixture was used');
```

In `'a burned version stays burned after rollback...'` the helper returns
`{ v1, v1sig, v2, v2sig }`; the test uses `v2`, `v2sig`, and a fresh `v3`, so
`v1`/`v1sig` are otherwise unused and this line asserts nothing about
behavior.

## Why it matters

A passing assertion that cannot fail is noise: it inflates apparent coverage
and teaches the next reader that `v1` is intentionally checked.

## Minimal fix

Destructure only what is used (`const { v2, v2sig } = appliedPair(...)`) and
delete line 412 (or extend the helper's return type). No behavior change.

## Evidence

`Select-String -Path tests/h12-secure-updates.test.ts -SimpleMatch "v1 fixture was used"` (this run):

```
test.ts:412: assert.ok(v1.releaseVersion === 1 && v1sig.length > 0, 'v1 fixture was used');
```
