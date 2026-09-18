Status: resolved (a0f0e4b)
Source: session-audit m12-phase0 (uncommitted DECISIONS.md ADR-018)

## What's wrong

DECISIONS.md:739-743 — the ADR's RLS section gives `security_events` a
tenant-scoped SELECT policy ("SELECT is tenant-scoped by the same policy")
while the same ADR mandates the global hash chain mechanics:
`EventLog.resume()` (src/events.ts:257), `verify()` (src/events.ts:406), and
`bundle()` (src/events.ts:453) read the WHOLE chain across all tenants.
Under `FORCE ROW LEVEL SECURITY` with a tenant-scoped SELECT policy,
`PostgresEventLog` cannot rehydrate or verify the chain — cross-tenant rows
are filtered, so seq N+1 has no predecessor and `verify()` reports a broken
chain. An implementer following the ADR literally produces a broken backend
or an un-ADR'd deviation ("implementation must match the ADR or the ADR gets
amended").

## Why it matters

The ADR is the Phase 1 contract; everything (subagents B and C) waits on it.
Shipping this contradiction forward guarantees a broken first build or
silent drift from the ADR's own no-drift rule.

## Minimal fix

Amend ADR-018's RLS section before Phase 1: two roles — `app_rw` (runtime:
global SELECT on security_events for chain verify/resume, INSERT for
append, RLS-protected access to tenant tables) and `app_reader`
(audit-query path: tenant-scoped RLS SELECT on security_events, so hostile
cross-tenant reads through that role return zero rows). State the boundary
honestly: the runtime role reads all events because it signs every one; the
reader role is where database-enforced cross-tenant denial is proven.
