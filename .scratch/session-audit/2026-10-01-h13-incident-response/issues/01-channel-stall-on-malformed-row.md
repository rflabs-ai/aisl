Status: open

Source: session-audit 2026-10-01, `feat/h13-incident-response` (uncommitted working tree; no commits this session)

## What's wrong

`src/incident-store-pg.ts:161` — `parseChannelRow(row)` throws inside the
`load()` loop *before* the cursor advances (`163: this.maxSeq = record.seq;`),
and the query re-reads `WHERE seq > ${this.maxSeq}` (`157`). A single row with
an unknown `action` (the column has no CHECK — `44-56` table DDL) therefore
leaves the cursor stuck forever:

- `src/incident-store-pg.ts:91: if (!REVOCATION_ACTIONS.includes(row.action as RevocationAction)) {`
- `src/incident-store-pg.ts:92: throw new Error('revocation channel row has an unknown action: refusing to apply');`

Probe (emulated SELECT, real parse/cursor path): 3 consecutive loads all threw,
`mirror=[] cursor=-1` each time, good row `seq=2` never applied — verdict
"NO - cursor stuck behind the bad row". The table is append-only by privilege
(`REVOKE UPDATE, DELETE ON revocation_channel FROM PUBLIC;`), so the bad row
cannot be removed in-band.

## Why it matters

The revocation channel *is* the kill-switch propagation path (ADR-026). One
hostile row — writable by any runtime node (`app_rw` INSERT), or produced by a
rolling upgrade where a newer node publishes a newer action — permanently
halts `freeze`/`revoke` propagation on every node that sees it, with no
in-band recovery. A compromised node can silence the global kill switch
forever after writing one garbage row.

## Minimal fix

In `load()`, don't let one bad row stall the batch: skip rows that fail
`parseChannelRow`, record a channel error (`recordError`-style counter with
the refusal reason), and still advance `maxSeq` past them (the row is rejected
forever, later rows keep flowing). Keep the loud `health()` surface so status
shows `DEGRADED`.

## Evidence:

- `node .scratch/session-audit/2026-10-01-h13-incident-response/probe-p3-stall.mts`
  → `P3 load attempt 1: threw - revocation channel row has an unknown action: refusing to apply`
  → `P3 after attempt 3: mirror=[] cursor=-1 errors=1`
  → `P3 verdict: good row seq=2 applied? NO - cursor stuck behind the bad row`
- ledger rows 13–14 in `.scratch/session-audit/2026-10-01-h13-incident-response/evidence.md`
