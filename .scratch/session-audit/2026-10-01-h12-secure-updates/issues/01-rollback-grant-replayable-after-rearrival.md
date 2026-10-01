Status: resolved (b31987c)

Source: session-audit 2026-10-01, `feat/h12-secure-updates` (uncommitted working tree; no commits since midnight)

## Resolution (2026-10-01)

Fixed test-first: regression test added first (red: `ℹ pass 18 / ℹ fail 2`,
failure text "a used grant must not revive when its from-version becomes
current again"), then `UpdateState.rollbackGeneration` +
`RollbackGrant.generation` (validated in `stateStructure`/`grantStructure`),
`rollbackUpdate` requires generation equality and increments on success, CLI
`update grant` embeds the current generation. Green: H12 suite 20/20; full
gate 560 (545 pass, 15 PG skips, 0 fail); typecheck clean. Docs updated:
ADR-025 item 3, Claim 34, ROADMAP H12, CURRENT_STATE, DEPLOYMENT.

## What's wrong

A consumed rollback grant re-applies whenever `current` independently returns
to its `fromVersion`. `src/updates.ts:391` gates only on the current version:

```
391:   if (grant.fromVersion !== state.current.releaseVersion) return { ok: false, reason: 'grant-mismatch', state };
```

Nothing in `UpdateState` records a grant as used. Sequence (probe-confirmed):
apply v1→v2; grant A (2→1) succeeds; apply v3→v4; grant B (4→2) succeeds;
replaying grant A then succeeds (2→1) because `fromVersion === current`.
This falsifies the single-use claims: `src/updates.ts:15-16` ("replay fails
`grant-mismatch`"), `src/updates.ts:359-360` ("after one use … the same grant
can never apply again"), `DECISIONS.md:1512-1514` ("the emergency path cannot
itself become the replay path"), `SECURITY_CLAIMS.md:1576/1601`,
`ROADMAP.md:321-322`, `THREAT_MODEL.md:53`. The existing replay test
(`tests/h12-secure-updates.test.ts:383`) covers only immediate replay, where
`current` has changed.

## Why it matters

The emergency rollback path is the exact path H12 claims cannot be replayed.
An attacker who holds an old grant artifact gains an extra backward step
beyond the operator's authorized rollback whenever that version becomes
current again through any other signed grant. The high-water mark still holds
(forward recovery needs a new descriptor), so impact is bounded — but the
claim as written in five documents is false in the code.

## Minimal fix

Make the grant single-use with a monotonic generation, not a version match:

1. `UpdateState.rollbackGeneration: number` (initial 0; validate in
   `stateStructure`); `RollbackGrant.generation: number` (validate in
   `grantStructure`).
2. `rollbackUpdate`: require `grant.generation === state.rollbackGeneration`
   (else `grant-mismatch`) and increment it on success.
3. CLI `update grant` (src/cli.ts:1185 region): read state, embed the current
   generation.
4. Regression test: apply 1,2 → grant A 2→1 → apply 3,4 → grant B 4→2 →
   replay grant A must refuse (`grant-mismatch`). Update the existing grant
   fixtures in `tests/h12-secure-updates.test.ts` with the generation field.

(Alternative: persist used-grant digests — unbounded growth; generation is
bounded to one integer. No deployed state exists yet; the feature is
uncommitted, so no migration is needed.)

## Evidence

Throwaway probe (deleted after run), `node --test tests/z-probe-h12-grant-replay.test.ts`:

```
PROBE grantA first use: {"ok":true,"current":1,"mark":2}
PROBE apply v3: true
PROBE apply v4: true
PROBE grantB (4->2): {"ok":true,"current":2}
PROBE replay of used grantA: {"ok":true,"current":1,"mark":4}
✔ PROBE: old grant applies again after current returns to its fromVersion (1357.1079ms)
```

Ledger: `.scratch/session-audit/2026-10-01-h12-secure-updates/evidence.md` rows F-01 through F-01f.
