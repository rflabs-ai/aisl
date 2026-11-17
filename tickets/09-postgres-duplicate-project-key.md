# Postgres parity run hits a duplicate primary key on projects

Status: done
Source: mining S6-D0097, shard-6.md.
Repo: `ai-security-layer`.

## Evidence

A Postgres parity run failed with `duplicate key value violates unique
constraint projects_pkey`. `createProject` in `src/persistence.ts:260` does a
plain `INSERT INTO projects` with no conflict handling, so re-creating a
project id that already exists throws instead of returning the existing row or
a typed refusal.

Candidate text: "duplicate key value violates unique constraint
projects_pkey".

## Action

Decide the contract and implement it: either make `createProject` idempotent
with `ON CONFLICT (id) DO UPDATE` scoped to the tenant, or return a typed
`project-exists` refusal. Add a Postgres parity test that creates the same
project twice and asserts the chosen behavior.

## Decision

Chosen contract: idempotent create, keyed on the project id and scoped to the
tenant. The observed failure is a parity/bootstrap replay, so a repeat create
must return the existing row rather than turn every replay into an error path.

- Same tenant, repeat id: return the existing row. `created_at` is preserved
  and `name` is refreshed (last declaration wins, matching the `saveSession`
  upsert posture).
- Same id under another tenant: the conflict row is invisible under RLS, the
  update affects zero rows, and the call refuses with
  `project <id> belongs to another tenant: refusing to create`. Never a silent
  success, never a raw `projects_pkey` violation.
- RLS and the per-transaction tenant context are unchanged; the conflict update
  carries the same `tenant_id` predicate as the existing session upsert.

Not chosen: a typed `project-exists` refusal. It would make the replay path an
error and leave no way to correct a project name (there is no update method).

**SQLite path:** no SQLite project store exists to align. ADR-018 makes
`projects`/`tasks`/`agent_sessions` Postgres-only Stage-0 state; the SQLite
backend is the evidence `EventLog` and stores no projects. Any future SQLite
state store must implement the same rule: insert-on-conflict on `(id)`, a
tenant predicate on the conflict update, and zero rows means tenant refusal.

## Acceptance

- A live-Postgres test creates the same project id twice and gets the
  documented result, not a raw constraint error.
- The SQLite path behaves the same way. (No SQLite project store exists to
  align; see the Decision note. The SQLite EventStore path is untouched.)
- The parity suite passes with `DATABASE_URL` set.

## Result

Done 2026-11-17, `fix/postgres-project-idempotent`.

- `createProject` (`src/persistence.ts:261`) now does
  `INSERT ... ON CONFLICT (id) DO UPDATE SET name = EXCLUDED.name WHERE
  projects.tenant_id = $tenant RETURNING ...`, throwing the tenant refusal when
  zero rows come back.
- Parity test added to `tests/persistence-restore.test.ts` (the M12 Postgres
  suite, skipped cleanly without `DATABASE_URL`): first create, repeat create,
  then a same-id create under another tenant. It asserts one row, preserved
  `created_at`, refreshed `name`, the refusal, and that the foreign-tenant
  attempt changed nothing and wrote nothing.
- Live disposable `postgres:16`: file suite 6 tests, 5 pass, 1 skip
  (`RESTORE_DATABASE_URL` unset), 0 fail. Without `DATABASE_URL` the new test
  skips with the ADR-018 reason.
- Gate: `npm run typecheck` green; `npm test` 872 tests, 850 pass, 22 skip,
  0 fail.

