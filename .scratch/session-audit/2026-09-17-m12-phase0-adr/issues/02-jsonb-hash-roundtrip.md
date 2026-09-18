Status: resolved (a0f0e4b)
Source: session-audit m12-phase0 (uncommitted DECISIONS.md ADR-018)

## What's wrong

DECISIONS.md:676-680 — the ADR's `security_events` schema stores `event`
as `JSONB NOT NULL`, while the SQLite column it claims parity with is
`event TEXT` (src/events.ts:227). `verify()` recomputes `eventHash` from the
PARSED event object via `canonicalJson`, not from stored bytes, so JSONB
normalization (number representation, key ordering) must round-trip exactly
through `JSON.parse`. Edge: a finite JS number whose decimal form survives
Postgres `numeric` but re-parses differently (e.g. `1e+999` → PG numeric →
JS `Infinity` → `canonicalJson` → `"null"` → hash mismatch), plus silent
reformatting of large numbers — a hostile metadata value could break the
chain on Postgres while the same data verifies on SQLite.

## Why it matters

The hash chain must be byte-semantics-stable across backends; a backend-
dependent verification failure is both a correctness bug and an
evidence-integrity risk (Claim 8/Claim 21 parity suite would diverge).

## Minimal fix

Amend the ADR schema: `event TEXT NOT NULL` (true parity with
src/events.ts:227; the event object is only ever read back whole by the
port, and `json_extract`-style filters in `query()` become plain SQL on
tenant_id/seq/timestamp columns which are already real columns — the JSON
filters on `event` body can use `->>` on TEXT cast, or stay in JS after
parse, same as SQLite does today). Delete the JSONB claim from the schema
block so Phase 1 cannot follow it.
