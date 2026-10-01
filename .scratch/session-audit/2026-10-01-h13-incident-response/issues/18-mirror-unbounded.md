Status: open

Source: session-audit 2026-10-01, `feat/h13-incident-response` (audit notes → ticketed on request)

## What's wrong

`src/incident-store-pg.ts:121: private readonly mirror: RevocationRecord[] = [];`
grows for the process lifetime and is never trimmed. Channel records are rare
(incidents), so this is bounded by incident volume rather than traffic — a
known ceiling, not an active leak.

## Why it matters

A long-lived node with a noisy channel writer (or many single-target
revocations) accumulates memory; the cursor would allow trimming records at or
below the *minimum* consumer cursor, which the channel does not track.

## Minimal fix

Leave as-is with a `ponytail:` marker naming the ceiling and the upgrade path
(trim mirror entries whose seq is below every consumer's cursor, or window the
mirror to the last N records once a long-running multi-node deployment
exists), or cap the mirror size in `load()` when that deployment appears.

## Evidence:

- `Select-String src\incident-store-pg.ts -Pattern "private readonly mirror"` → `incident-store-pg.ts:121`
- audit report Notes
