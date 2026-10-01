Status: open

Source: session-audit 2026-10-01, `feat/h13-incident-response` (audit notes → ticketed on request)

## What's wrong

The expanded H13 prompt still carries its pre-ADR spec text:
- `PROMPTS/H-Track/H13-incident-response.md:84: - \`AuthorizationService\`: \`freeze(tenantId | '*', reason, actor)\`,`
  but the shipped signature is `scope`-based (`src/pdp.ts:334: freeze(scope:
  'tenant' | 'global', tenantId: string | undefined, reason: string, actor:
  string): void {`; same for `revokeAll`).
- `PROMPTS/H-Track/H13-incident-response.md:136: - CLI: \`node src/cli.ts
  incident status|engage|lift|preserve|report\`.` — 5 subcommands, while the
  shipped CLI has 7 (`cli.ts` usage lists `revoke-cap`/`revoke-session` too).
  The resolution section (prompt:223) already documents the shipped 7.

## Why it matters

A future reader following the prompt's Phase 1 text would implement a
different signature than ADR-026 and the code; the prompt is the execution
record and should not contradict what shipped.

## Minimal fix

Update prompt lines 84/85 to the scope-based signatures and line 136 to the
7-subcommand list (or add "see resolution"), matching ADR-026.

## Evidence:

- `Select-String PROMPTS\H-Track\H13-incident-response.md -Pattern "freeze\(tenantId"` → `prompt:84: ... freeze(tenantId | '*', reason, actor)`
- `Select-String ... -Pattern "node src/cli.ts incident status\|"` → `prompt:136: ... status|engage|lift|preserve|report`
- audit report Notes
