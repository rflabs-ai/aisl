Status: resolved (06a8a89)

Source: session-audit 2026-10-01, `feat/h13-incident-response` (uncommitted working tree; no commits this session)

## What's wrong

`incident report|preserve <tenantId>` mints operator audit authority through
the scenario root, which is acme-scoped. For any other tenant the CLI dies
with a raw stack trace:

- `src/cli.ts:1442: world.authorization.issue(world.root, {` (the mint)
- `src/capability.ts:155: throw new CapabilityIssuanceError('issuer may not mint capabilities in another tenant');`

Probe: `node src/cli.ts incident report globex 0 5` →
`CapabilityIssuanceError: issuer may not mint capabilities in another tenant`
`at issueCapability (.../src/capability.ts:155:11)` `at incidentCommand
(.../src/cli.ts:1442:27)` → `exit=1`, no usage hint, no refusal line (contrast
`updateCommand`, which prints `... — refusing (fail closed).` and exits 1).

## Why it matters

The runbook documents the commands generically (`incident report <tenantId>`);
in practice they work only for `acme`, and every other tenant gets an opaque
crash instead of a diagnosable refusal — unusable during an incident.

## Minimal fix

Wrap the evidence commands in the same fail-closed handling as `updateCommand`:
catch `CapabilityIssuanceError` (and `IncidentEvidenceError`) and print a
one-line refusal naming the constraint (scenario root is acme-scoped /
evidence authority could not be minted) with `exit=1`; optionally note the
acme-only limitation in the runbook until a per-tenant operator identity
exists (the ADR-026 named upgrade).

## Evidence:

- `node src/cli.ts incident report globex 0 5` → stack quoted above, `exit=1`
- ledger row 22 in `.scratch/session-audit/2026-10-01-h13-incident-response/evidence.md`

## Resolution (06a8a89)

`incidentCommand` wraps the command body in a catch that prints
`incident command refused: <message>` and sets exit code 1 (mirroring
`updateCommand`'s fail-closed style) instead of an uncaught stack trace.

**Evidence (this session):** `node src/cli.ts incident report globex 0 5` →
`  incident command refused: issuer may not mint capabilities in another tenant`, exit=1.