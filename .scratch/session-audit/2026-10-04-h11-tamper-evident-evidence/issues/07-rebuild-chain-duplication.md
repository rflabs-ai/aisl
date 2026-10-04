# Ticket 07 — `resignChain` (CLI demo) duplicates the H11 test's `rebuildChain`

Status: resolved as accepted — no code change (3f71244)
Source: session-audit b3e345b..HEAD (H11, ADR-031), Notes/N4

## What's wrong

Two adversarial-chain rebuild helpers exist: `resignChain` in `src/cli.ts`
(demo section 24) and `rebuildChain` in `tests/h11-tamper-evident-evidence.test.ts`.

## Why no change

They serve different contracts: the test helper supports targeted per-event
mutation (fork/rewrite cases), the demo helper only relinks/rehashes/re-signs
the kept prefix for one visible demonstration. Sharing would mean exporting
adversarial chain-rebuilding code from `src/` into the test suite or importing
test wiring into the CLI — both worse than the duplication. Accepted; revisit
if a third consumer appears.

## Evidence

`git grep -n "function resignChain" HEAD -- src/cli.ts` →
`HEAD:src/cli.ts:function resignChain(`;
`git grep -n "function rebuildChain" HEAD -- tests` →
`HEAD:tests/h11-tamper-evident-evidence.test.ts:function rebuildChain(`.