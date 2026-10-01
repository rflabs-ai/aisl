Status: resolved (06a8a89)

Source: session-audit 2026-10-01, `feat/h13-incident-response` (uncommitted working tree; no commits this session)

## What's wrong

`src/incident.ts:431-435` — single-target session revocation has no local
evidence record:

- `src/incident.ts:433: this.sessions.revoke(sessionId);`
- `src/incident.ts:434: this.channel.publish({ action: 'revoke-session', ... })`

There is no `eventLog.append` in `revokeSession` (contrast
`src/incident.ts:424-428` `revokeCapability`, which calls `authorization.revoke`
→ `src/pdp.ts:259` / `src/pdp.ts:271: action: 'capability.revoke',` — audited).
ADR-026 states the contract:
`DECISIONS.md:1628: The evidence of record stays each node's signed event log (the local`
and the DEPLOYMENT runbook advertises the command (`DEPLOYMENT.md:392-394:
**Narrow revocation:** ... incident revoke-session ... — local + broadcast`).

## Why it matters

The channel row is coordination data, not signed, tamper-evident evidence. As
shipped, an operator's single-target session revocation exists nowhere in the
evidence plane — reconstruction cannot show who revoked which session, only
whatever denials happen to follow.

## Minimal fix

Append an event in `revokeSession` before publishing (mirror `revokeCapability`'s
audited path), e.g. action `incident.revoke` with `metadata:
{ phase: 'incident-revoke-session', sessionId, tenantId, reason }` — or route
it through a small `SessionManager`-aware audit append so the local node's log
matches the channel record.

## Evidence:

- `Select-String src\incident.ts -Pattern "revokeSession|sessions.revoke\("` → lines 431-434 quoted above, no `eventLog.append` in the function body
- `Select-String src\pdp.ts -Pattern "action: 'capability.revoke'"` → `pdp.ts:271`
- ledger row 19 in `.scratch/session-audit/2026-10-01-h13-incident-response/evidence.md`

## Resolution (06a8a89)

`IncidentService.revokeSession` now appends an `incident.revoke` event
(`metadata.phase = 'incident-revoke-session'`, sessionId/tenantId/reason,
`revoked` flag) before publishing the channel record — mirroring
`revokeCapability`'s audited path. The existing cross-node test asserts the
event exists and carries the session id.

**Evidence (this session):** h13 suite green.