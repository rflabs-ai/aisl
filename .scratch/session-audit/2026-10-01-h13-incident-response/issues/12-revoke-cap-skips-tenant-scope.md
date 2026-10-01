Status: open

Source: session-audit 2026-10-01, `feat/h13-incident-response` (audit notes → ticketed on request)

## What's wrong

`AuthorizationService.applyIncidentRecord` defines the tenant scope check
(`src/pdp.ts:397: const inScope = (tenantId: string): boolean => record.scope
=== 'global' || tenantId === record.tenantId;`) and uses it for `revoke-caps`
(`src/pdp.ts:413: if (!inScope(cap.tenantId)) continue;`), but the
`revoke-cap` case ignores it:

- `src/pdp.ts:419: case 'revoke-cap':`
- `src/pdp.ts:420: if (record.targetId) {`
- `src/pdp.ts:421: this.revoked.set(record.targetId, ...)` — no tenant check

so a tenant-scoped record from tenant A revokes a capability id belonging to
tenant B on every syncing node (and `IncidentService.revokeCapability` also
does not verify the local capability's tenant).

## Why it matters

Cross-tenant interference by a tenant-scoped operator (needs the target id,
and revocation only removes authority — fail-closed direction), but it is an
isolation gap in a security control and trivially closable.

## Minimal fix

Check the local capability's tenant before honoring a single-target record:
skip (and count) when the target is registered to another tenant; if it is
not registered locally, record the id revoked as today (the capability may
arrive later — a revocation ahead of registration is the safe direction).

## Evidence:

- `Select-String src\pdp.ts -Pattern "inScope\("` → `pdp.ts:397`, `pdp.ts:413` (revoke-caps only)
- `Select-String src\pdp.ts -Pattern "case 'revoke-cap':"` → `pdp.ts:419`; body 420–421 has no `inScope`
- audit report Notes
