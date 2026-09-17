# M12 — Platform shift: Postgres control plane

Baseline: M11 complete (RBAC + classification propagation landed — RLS and
per-tenant-key design build on them). This milestone introduces the **first new
runtime dependency since `jose`** — AGENTS.md: "No runtime dependencies without
an ADR", and the dependency-admission row ([DONE]) demands pinning + review.
Sequence accordingly.

Scope (ROADMAP rows): Postgres schema + migrations (ADR-010), Tenant isolation
hardening (RLS, per-tenant keys), Backup + restore, plus the Stage-0 row
Project/task/session persistence.

## 0. Phase 0 — ADR + schema design (docs only; runs PARALLEL with M11/M13)

Zero code conflict — this is the piece that can start before M11 lands.

- **ADR-017** (next free number — verify in `DECISIONS.md`): Postgres as the
  multi-node control plane. Must decide: driver (`pg` vs `postgres.js` — pick
  one, pin it), connection/secret handling (env + secret broker, never logged),
  fail-closed behavior when the DB is unreachable (deny with a distinct reason,
  H15 loud denial), **SQLite stays the default embedded/test backend behind an
  EventStore port** (dual backend, not a rewrite), the RLS model, and
  per-tenant key derivation.
- Schema design written into the ADR: tables for events (parity with
  `security_events`), capability requests, projects/tasks/sessions
  (persistence), migrations bookkeeping. Implementation must match the ADR or
  the ADR gets amended — no drift.

## 1. Subagents + parallelization (explicit)

- **Phase 1 (after M11 + ADR): Subagent A — EventStore port + Postgres event
  backend + migrations framework.** Owns the `src/events.ts` seam + new
  `src/event-store-pg.ts` + migrations. B and C **wait** — everything depends
  on the schema.
- **Phase 2 (after A): B — tenant isolation ∥ C — backup/restore +
  persistence, in PARALLEL.** Disjoint surfaces: B owns RLS policies +
  per-tenant key derivation; C owns pg_dump tooling + the persistence
  tables/API. Both consume A's schema; neither edits the event backend.
- **Shared-file rule:** only the main session edits `src/cli.ts`; benchmark
  additions go through the main session (M10's gate must stay green — if a
  Postgres-mode latency target needs to become advisory, that conversion is
  documented in the ADR, not silently done).

## 2. Hard requirements (never simplify away)

- **Evidence invariants hold on Postgres:** hash chain, per-event Ed25519
  signatures, append-only enforcement (no UPDATE/DELETE — triggers or revoked
  privileges), `verifyBundle` unchanged, decision audit completeness unchanged
  (SLO gate proves it).
- **Fail closed:** unreachable DB → deny with a distinct `denyReason` and a
  loud event (H15).
- **RLS is the database enforcing isolation:** deny-by-default policies; the
  app connects as a non-superuser role; tests prove cross-tenant reads return
  ZERO rows even against hostile queries. Do not rely on app-code tenant
  checks alone.
- **Per-tenant keys:** derived from the existing HKDF master with `tenantId`
  in the derivation; versioned keyIds; **no silent re-encryption** of existing
  sealed data — document the migration path instead.
- **Backup/restore:** a `pg_dump`-based script plus a restore test asserting
  `verify()` passes on the restored store. Restore is rehearsed in a test, not
  assumed.
- **Dual backend:** SQLite remains the default; Postgres tests skip cleanly
  when no `DATABASE_URL` (mirror the container-sandbox fallback pattern).
- **Migrations:** forward-only, versioned, recorded (migration table + event);
  no destructive steps.

## 3. Tests / acceptance

- Parity suite: the existing events/audit tests run against both backends (or
  a documented subset with reasons).
- RLS cross-tenant test; fail-closed test (DB down → deny, reason recorded);
  backup → restore → `verify()` test; migration up-only test; persistence
  roundtrip (create project/task/session, "restart", resume).
- SLO gate green (or advisory conversions documented in the ADR).

## 4. Docs sweep (main session)

- ROADMAP rows Postgres schema + migrations / Tenant isolation hardening /
  Backup + restore / Project-task-session persistence → `[DONE]` with
  milestone refs.
- DECISIONS.md: ADR-017.
- CURRENT_STATE: counts; runtime deps 1 → 2; known-gap #4 (env keys) and #7
  (shared process) get honest updates if this milestone changes them.
- DEPLOYMENT.md: provisioning, RLS setup, backup cadence, restore drill.
- AGENT-SESSION entry.

## 5. Constraints

- No ORM — raw SQL through the EventStore port. No pooling library. No
  multi-node revocation broadcast (H13 stays open). No query federation.

## 6. Acceptance + skip list

Acceptance: gate green on SQLite default; Postgres suite green when a database
is present and skipped otherwise; restore test passes; docs updated.

skipped: multi-node active-active, read replicas, connection pooling tuning.
add when: a second node actually runs.
