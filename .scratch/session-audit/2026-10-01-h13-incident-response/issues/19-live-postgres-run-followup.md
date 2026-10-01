Status: open

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
