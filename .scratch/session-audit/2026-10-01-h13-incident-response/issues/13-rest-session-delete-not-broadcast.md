Status: open

Source: session-audit 2026-10-01, `feat/h13-incident-response` (audit notes → ticketed on request)

## What's wrong

The REST owner-revocation route revokes only in the local process:
`src/rest-sessions.ts:99: deps.sessions.revoke(id);` — it does not publish a
`revoke-session` record through the revocation channel (the H13
`IncidentService.revokeSession` path does; `src/incident.ts:431-435`).

## Why it matters

On a multi-node deployment, a session revoked via `DELETE /v1/sessions/:id`
stays valid on other nodes until the local node restarts syncing (and nodes
that never sync keep it). The incident runbook is covered; the ordinary REST
surface is not. Consequence of the single-node REST posture, but the gap
should be named or closed.

## Minimal fix

Either wire an optional `incident`/`sessionRevocation` hook into
`SessionRouteDeps` so the DELETE route publishes through
`IncidentService.revokeSession`, or state in ADR-026/DEPLOYMENT that
cross-node session revocation is the incident path (`incident revoke-session`)
and the owner DELETE is node-local.

## Evidence:

- `Select-String src\rest-sessions.ts -Pattern "deps.sessions.revoke"` → `rest-sessions.ts:99: deps.sessions.revoke(id);`
- audit report Notes
