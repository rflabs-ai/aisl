Status: resolved (db2a93a)
Source: session-audit 2026-10-03 (H2 short-lived credentials, branch feat/h2-short-lived-credentials)

## What's wrong

H2 added the `revoke-token` action/command, but three living docs that
enumerate the revocation action vocabulary or the operator CLI were not
updated to include it:

- `SECURITY_CLAIMS.md:1669-1670` (Claim 35, H13):
  `(`freeze`/`unfreeze`/`revoke-caps`/`revoke-sessions`) and single-target`
  `(`revoke-cap`/`revoke-session`); a tenant-scoped `revoke-cap` record can only`
- `SECURITY_CLAIMS.md:1681-1682` (same claim):
  `CLI: `node src/cli.ts incident status|engage|lift|revoke-cap|`
  `revoke-session|preserve|report`; operator commands build a bootstrap-free`
- `CURRENT_STATE.md:146-148`:
  `CLI:` / `node src/cli.ts incident status|engage|lift|revoke-cap|revoke-session|` /
  `preserve|report` (+ `npm run incident:status`; ...
- `DEPLOYMENT.md:424-425` (incident runbook, "Narrow revocation"):
  ``4. **Narrow revocation:** `incident revoke-cap <capabilityId> <tenantId>` `` /
  ``   "<reason>"`, `incident revoke-session <sessionId> <tenantId> "<reason>"` —``

The action exists and works: `src/incident.ts:53` (`| 'revoke-token';`),
`src/incident.ts:586` (`revokeToken(...)`), `src/cli.ts:1483` (usage) and
`src/cli.ts:1538` (`world.incident.revokeToken(...)`); the H2 commit updated
Claim 37 and added `revoke-token` to the DEPLOYMENT credential-contract section
(`DEPLOYMENT.md:135-140`) but missed these enumerations.

## Why it matters

The repo's commit ritual (AGENTS.md rule 8) says stale docs are fixed in the
same commit because "docs that drift from code rot into lies." Claim 35 is the
formal H13 claim surface: a reader auditing the claim sees a closed action
vocabulary that no longer matches `RevocationAction`. The DEPLOYMENT runbook is
the operator's narrow-revocation procedure — an operator following it will not
find the credential (`jti`) revocation step, which is the one an active
credential leak needs.

## Minimal fix

Append `revoke-token` to the three enumerations (one line each):
- `SECURITY_CLAIMS.md` Claim 35: add `revoke-token` to the single-target list
  and to the CLI command list.
- `CURRENT_STATE.md:147`: add `revoke-token` before `preserve`.
- `DEPLOYMENT.md:425`: add
  `incident revoke-token <jti> <tenantId> "<reason>"` to the runbook step.

No code change; no test change (the behavior is already covered by
`tests/h2-short-lived-credentials.test.ts`).

## Evidence

This audit's fresh commands:

- `Select-String -Path SECURITY_CLAIMS.md -Pattern '^## Claim'` → nearest
  heading before line 1669 is `## Claim 35 - The kill switch freezes authority
  immediately in-process and propagates within the poll interval; preserved
  evidence verifies offline (H13)`; before 1880 it is Claim 37 (H2).
- `git diff 6d9ddf4..26c0d67 -- SECURITY_CLAIMS.md CURRENT_STATE.md DEPLOYMENT.md`
  shows H2 edited those files but not the quoted lines.
- Code citations above from HEAD (`src/incident.ts:53`, `:586`; `src/cli.ts:1483`,
  `:1538`), and the H2 suite includes the operator-path test
  (`tests/h2-short-lived-credentials.test.ts:398` "the operator path applies
  locally first, publishes, and audits").
