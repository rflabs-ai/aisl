Status: open

Source: session-audit 2026-10-01, `feat/h13-incident-response` (uncommitted working tree; no commits this session)

## What's wrong

`src/incident-store-pg.ts:18: import { type StoreMigration } from './event-store-pg.ts';`
— under Node's native type stripping this keeps a runtime load edge back to
`event-store-pg.ts`, which itself value-imports the channel
(`src/event-store-pg.ts:18: import { INCIDENT_MIGRATION } from './incident-store-pg.ts';`).
Entering the cycle at `incident-store-pg.ts` evaluates `event-store-pg.ts`
while `INCIDENT_MIGRATION` is still in its TDZ:

- probe crash: `ReferenceError: Cannot access 'INCIDENT_MIGRATION' before initialization`
  at `src/event-store-pg.ts:73` (the `MIGRATIONS` array literal,
  `event-store-pg.ts:73: INCIDENT_MIGRATION,`).

Today it only survives because every in-repo entry imports in the safe order
(`scenario.ts:10` before `scenario.ts:25`;
`tests/h13-revocation-pg.test.ts:13` before `:14`) — import-order luck, not a
guarantee, and `tsc --noEmit` does not flag it.

## Why it matters

A module that crashes on first import under the wrong entry order is a landmine
for the next consumer/test (`import { PostgresRevocationChannel }` before
anything touched `event-store-pg`) and fails with an obscure TDZ error rather
than a diagnosis.

## Minimal fix

One line: `import type { StoreMigration } from './event-store-pg.ts';` — a
full `import type` statement is stripped entirely, removing the runtime edge.
Replica probe of both forms: inline `{ type X }` →
`THREW: ReferenceError - Cannot access 'B' before initialization`; `import type`
form → `entry via mig-b: OK, no crash`.

## Evidence:

- `node probe-p3-stall.mts` (un-primed entry) → `ReferenceError: Cannot access 'INCIDENT_MIGRATION' before initialization` `at .../src/event-store-pg.ts:73`
- replica: `node -e "import('./.../cycle-replica/b.ts')..."` → `THREW: ReferenceError - Cannot access 'B' before initialization`
  vs `node -e "import('./.../cycle-replica/mig-b.ts')..."` → `entry via mig-b: OK, no crash`
- ledger rows 10–12 in `.scratch/session-audit/2026-10-01-h13-incident-response/evidence.md`
