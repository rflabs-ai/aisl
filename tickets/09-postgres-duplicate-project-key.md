# Postgres parity run hits a duplicate primary key on projects

Status: open
Source: mining S6-D0097, shard-6.md.
Repo: C:\Users\kcpat\projects\ai-security-layer.

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

## Acceptance

- A live-Postgres test creates the same project id twice and gets the
  documented result, not a raw constraint error.
- The SQLite path behaves the same way.
- The parity suite passes with `DATABASE_URL` set.
