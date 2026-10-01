Status: resolved (fix/h13-audit-tickets-10-19)

Source: session-audit 2026-10-01, `feat/h13-incident-response` (audit notes → ticketed on request)

## What's wrong

`incident engage|lift` reports the broadcast honestly —
`src/cli.ts:1412: const broadcastOk = result.broadcastOk && status.channelErrors === 0;`
and `src/cli.ts:1421: if (!broadcastOk) process.exitCode = 1;` — but
`incident revoke-cap|revoke-session` flushes and prints success
unconditionally:

- `src/cli.ts:1432: await world.incident.flush();`
- `src/cli.ts:1433: line(sub, 'REVOKED', ...)` — no `status().channelErrors`
  check, exit 0 even when the channel write failed

(`revokeSession`'s publish is also the only non-awaited, unchecked write path
in the incident CLI).

## Why it matters

An operator performing a narrow revocation during an incident sees `REVOKED`
and exit 0 while the broadcast failed — the exact "silently treated as
propagated" failure ADR-026's fail-loud rule forbids.

## Minimal fix

Mirror the engage branch: after `flush()`, read `world.incident.status()`;
print `broadcast FAILED` and set `process.exitCode = 1` when
`channelErrors > 0` (or `lastError` changed).

## Evidence:

- `Select-String src\cli.ts -Pattern "broadcastOk = result.broadcastOk|if \(!broadcastOk\)"` → `cli.ts:1412`, `cli.ts:1421` (engage path only)
- audit report Notes

## Resolution (fix/h13-audit-tickets-10-19)

The narrow-revocation branch mirrors engage: after `flush()` it reads `status().channelErrors`, prints `broadcast OK|FAILED` (plus the in-memory-mode note), and sets exit 1 when the channel errored.
