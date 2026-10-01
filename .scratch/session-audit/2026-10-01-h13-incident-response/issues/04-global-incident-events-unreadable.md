Status: open

Source: session-audit 2026-10-01, `feat/h13-incident-response` (uncommitted working tree; no commits this session)

## What's wrong

Global-scope incident evidence is written with `tenantId: ''` —

- `src/pdp.ts:342: tenantId: scope === 'global' ? '' : tenantId!,` (freeze event)
- `src/pdp.ts:360: tenantId: scope === 'global' ? '' : tenantId!,` (lift event)
- `src/incident.ts:356: tenantId: input.scope === 'global' ? '' : input.tenantId!,` (engage event)
- `src/incident.ts:402: tenantId: input.scope === 'global' ? '' : input.tenantId!,` (lift event)

— and every authorized read path rejects an empty tenant:
`src/audit-query.ts:81: throw new AuditFilterError('tenantId is required');`
(both `reconstruct` and `preserve` go through `audit.query` → `validateFilters`).
Probe: after `engage global`,
`P5 global incident event tenantIds: ["incident.freeze=\"\"","incident.engage=\""]`
and `P5 reconstruct with tenantId "": THREW AuditFilterError - tenantId is required`.

## Why it matters

The runbook's own flow breaks for global scope: step 2 documents
`incident engage global "<reason>"` (`DEPLOYMENT.md:383`), step 6 documents
`incident report <tenantId> ...` (`DEPLOYMENT.md:403`) — with no argument that
can fetch the global engage/freeze/lift events. A global kill switch's evidence
is structurally invisible to reconstruction, preservation, `GET /v1/audit`, and
per-tenant exports: "cannot reconstruct what happened" stays open for exactly
the largest incident.

## Minimal fix

Give the reconstruction/preservation path a global view: accept a sentinel
(e.g. `tenantId: '*'`) that maps to events already recorded with
`tenantId === ''` (they belong to no tenant, so no cross-tenant data is
exposed), through the same authorized `exportWindow` path; surface it in the
CLI (`incident report '*' <from> <to>`). Tenant-isolation posture unchanged:
still only the global-incident events, still gated by `audit.export`.

## Evidence:

- `node probe-p5-global.mts` → `P5 global incident event tenantIds: ["incident.freeze=\"\"","incident.engage=\""]` / `P5 reconstruct with tenantId "": THREW AuditFilterError - tenantId is required`
- ledger rows 17–18 in `.scratch/session-audit/2026-10-01-h13-incident-response/evidence.md`
