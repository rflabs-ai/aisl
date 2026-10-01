Status: resolved (06a8a89)

Source: session-audit 2026-10-01, `feat/h13-incident-response` (uncommitted working tree; no commits this session)

## What's wrong

`src/pdp.ts:303-304` `broadcastSyncFailures(): number { return this.syncFailures; }`
and `src/pdp.ts:316: this.syncFailures++;` are never read by any caller
(grep over `src`, `tests`, `security-tests`: definition + increment only).
The comment promises visibility that does not exist:

- `src/pdp.ts:314: // A channel outage never blocks local enforcement; it is counted so it`
- `src/pdp.ts:315: // surfaces in incident status instead of being silently ignored.`

But `incident status` reads the *IncidentService's own* counter
(`src/incident.ts:489: syncFailures: this.syncFailures,`), which counts
`channel.since()` failures — the PDP hook's counter is a different number that
stays 0, because `IncidentService.sync()` swallows its own errors before they
can reach `pdp.ts:316`.

## Why it matters

Dead code plus a false comment: a future reader debugging "why did sync
failures stay 0" gets misled, and the state duplicates a name that a real
counter already occupies.

## Minimal fix

Delete `broadcastSyncFailures()` / `pdp.syncFailures` and reword the catch
comment (`// a hook bug must not block the decision path; the service's own
sync counters report channel health`), or — if hook-level failures are wanted —
surface the PDP value inside `IncidentService.status()` instead of leaving it
unread. Prefer deletion (the service counter is the one status shows).

## Evidence:

- `Select-String src\*.ts,tests\*.ts,security-tests\*.ts -Pattern "broadcastSyncFailures|syncFailures"` → `pdp.ts:303`, `pdp.ts:304`, `pdp.ts:316` (no reader), `incident.ts:489` (separate counter)
- ledger row 24 in `.scratch/session-audit/2026-10-01-h13-incident-response/evidence.md`

## Resolution (06a8a89)

Deleted `AuthorizationService.broadcastSyncFailures()` and the
`syncFailures` field/increment; the catch comment now says the service's own
sync counters are the operator-visible health. No test referenced the removed
API.

**Evidence (this session):** `Select-String src\pdp.ts -Pattern
"syncFailures"` → no hits; typecheck + full suite green.