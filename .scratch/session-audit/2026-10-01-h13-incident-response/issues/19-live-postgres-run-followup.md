Status: resolved (fix/h13-audit-tickets-10-19)

Source: session-audit 2026-10-01, `feat/h13-incident-response` (audit notes → ticketed on request)

## What's wrong

The live Postgres half of the new code is unverified in this environment:
`Start-Service com.docker.service` → `Cannot open 'com.docker.service' service
on computer '.'` and no `DATABASE_URL`, so `tests/h13-revocation-pg.test.ts`
(4 live tests: two-instance broadcast, append-only privilege, hostile-row
refusal, audit-01 skip-and-count) and the migration-4 application skipped
cleanly (`ℹ skipped 19`). PG-mode process-exit behavior (the revocation
channel's own `postgres` client is closed by `incidentCommand`/demo nodes but
not by `demo()`/`attack()`/`benchmark()`'s main world) was never exercised.

## Why it matters

The multi-node claim's only real proof runs when a disposable database
exists; the migration and the channel have never been applied to a live
server in this session.

## Minimal fix

Next session with Docker: `docker run -d --name sec-layer-pg -e
POSTGRES_PASSWORD=... -p 5433:5432 postgres:16`, set `DATABASE_URL` +
`MIGRATION_DATABASE_URL`, run `npm test`, and `EVENT_STORE=postgres npm run
demo` to confirm exit and channel behavior (and check whether `demo`/`attack`/
`benchmark` need `world.incident.close()` for the main world).

## Evidence:

- `Start-Service com.docker.service` → `Cannot open 'com.docker.service' service on computer '.'`
- `node --test tests/h13-revocation-pg.test.ts` → `﹣ ... # DATABASE_URL is not set (ADR-026: Postgres tests skip cleanly)`
- `.scratch/session-audit/2026-10-01-h13-incident-response/evidence.md` row 35

## Resolution (fix/h13-audit-tickets-10-19)

Run executed against a disposable `postgres:16` container (Docker):
`DATABASE_URL` + `MIGRATION_DATABASE_URL`; full suite serialized
(`node --test --test-concurrency=1` — the suites assume an exclusive scratch DB)
→ 612 tests / 611 pass / 1 environment-gated skip / 0 fail.
`EVENT_STORE=postgres npm run demo` and `npm run attack` exit 0 (no hang);
`npm run benchmark` exits 0 on a fresh chain.

Live-only findings, all fixed in the same session:
- migration 4's `GRANT ... ON SEQUENCE revocation_channel_seq` aborted the
  migration on a live server — BIGSERIAL on `seq` names the sequence
  `revocation_channel_seq_seq`; the static DDL test now pins the name.
- `flush()` awaited a bare `SELECT 1` on a pooled connection rather than the
  queued inserts; the channel now tracks pending queries and awaits them.
- `eventBody` hashed raw `metadata`; an explicit `undefined` value (the
  envelope-secrets deny path) made the stored hash irreproducible on reload
  (Postgres and SQLite). Metadata is JSON-normalized before hashing;
  regression test in `tests/m3-evidence-hardening.test.ts`.
- demo section 22 built its two simulated nodes through the process's store;
  it now forces in-memory worlds (`WorldOptions.memory`), and
  `demo`/`attack`/`benchmark` close `world.incident` before exit.
- one live-only test bug: M15 capability-requests reused an id across tenants
  (ids are service-generated UUIDs); the test now proves isolation with
  distinct ids.
- PG-mode benchmark expects a fresh chain — a reused database inflates
  `auditCompleteness` (noted in ADR-026 addendum 2).
