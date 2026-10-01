Status: open

Source: session-audit 2026-10-01, `feat/h13-incident-response` (audit notes → ticketed on request)

## What's wrong

`src/pdp.ts:237: grant(cap: Capability): void {` registers a caller-supplied
capability (stamping `registeredAt`) but, unlike `issue()`, it neither
force-syncs the revocation channel nor consults the freeze entry.
`IncidentService` wires the sync into `authorize`/`issue` only. In-repo
callers: only `tests/invariants.test.ts:480: authz.grant(` (grep), so this is
an embedder-surface gap, not an active path — and authorization still gates
every use (`evaluate` denies a frozen tenant regardless).

## Why it matters

An embedder that uses `grant()` for resumed/persisted capabilities skips the
kill switch's issuance guard (it can register authority while frozen; it
cannot *use* it until `lift`). The ADR's "freeze issuance" wording implies the
registration path is covered; today only minting is.

## Minimal fix

Either document `grant()` as an embedder escape hatch that bypasses the
issuance freeze (authorize still gates), or add the same
`syncBroadcast(true)` + `freezeFor` refusal to `grant()`.

## Evidence:

- `Select-String src\*.ts,tests\*.ts -Pattern "\.grant\("` → `invariants.test.ts:480` only
- `Select-String src\pdp.ts -Pattern "grant\(cap: Capability\)"` → `pdp.ts:237`
- audit report Notes
