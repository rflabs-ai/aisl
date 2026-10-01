Status: resolved (7c30aad)
Source: session-audit 2026-10-01, `feat/h12-secure-updates` (uncommitted working tree) — audit nit F-05

## What's wrong

Two exports in `src/updates.ts` have no external consumers:

```
updates.ts:118: export class UpdateStateError extends Error {
updates.ts:125: export function initialState(): UpdateState {
```

`Select-String -Path src/*.ts,tests/*.ts -Pattern "initialState|UpdateStateError"`
(this run) matches only `src/updates.ts` itself (lines 118, 125, and internal
uses) — the CLI catches generic `Error` in its `try/catch` around `loadState`,
and no test imports either symbol.

## Why it matters

Public API surface that no one consumes invites accidental coupling; the
doc comment for `UpdateStateError` says "callers surface it as
`state-malformed`" but callers never see the type.

## Minimal fix

Drop the `export` keyword from both (module-private is sufficient:
`loadState` uses both internally). Alternatively, make the CLI catch
`UpdateStateError` specifically — either resolves the mismatch; deletion is
smaller.

## Evidence

`Select-String -Path src/updates.ts -SimpleMatch "export class UpdateStateError","export function initialState"` (this run):

```
updates.ts:118: export class UpdateStateError extends Error {
updates.ts:125: export function initialState(): UpdateState {
```

And `Select-String -Path src/*.ts,tests/*.ts -Pattern "initialState|UpdateStateError"` (this run) matches only `src/updates.ts` — no other file in `src/` or `tests/` references either symbol.
