Status: open

Source: session-audit 2026-10-01, `feat/h13-incident-response` (audit notes → ticketed on request)

## What's wrong

Two small report-shape issues in `src/incident.ts`:
1. `src/incident.ts:225: readonly actions: Readonly<Record<string, number>>;`
   is computed by `reconstruct` but no consumer reads it — the CLI prints
   denyReasons and actors only (`Select-String src\cli.ts -Pattern
   "report.actions"` → no hits).
2. `src/incident.ts:141: readonly freezes: readonly { scope: IncidentScope;
   tenantId?: string; reason: string; at: number; actor: string }[];`
   re-declares `FreezeEntry` structurally instead of importing the type
   exported by `src/pdp.ts` (the shapes must be kept in sync by hand).

## Why it matters

Dead report field and a duplicated contract; both are easy drift points
(the interface compiles today only because the shapes happen to match).

## Minimal fix

Either print the action breakdown in the CLI's `incident report`, or drop
`IncidentReport.actions`; and type `IncidentStatus.freezes` as
`readonly FreezeEntry[]` (import type from `./pdp.ts`).

## Evidence:

- `Select-String src\incident.ts -Pattern "readonly actions:|readonly freezes:"` → `incident.ts:225`, `incident.ts:141`
- audit report Notes
