Status: resolved (f61817e)
Source: session-audit 2026-10-04 (H8 cross-tenant isolation, feat/h8-cross-tenant-isolation)

## What's wrong

`tests/h8-cross-tenant-probe.test.ts:515-527` — the
`session-manager-tenant-scoped-bulk` row asserts one direction only: a
tenant-A bulk revoke must not revoke a tenant-B session. There is no reverse
assertion (a tenant-B bulk revoke must not revoke a tenant-A session):

- `:520: rig.world.sessions.revokeAllForTenant(TENANT_A);`

## Why it matters

The row's stated property ("tenant-wide revocation must not cross tenants")
is only proven east-to-west; the reverse relies on other rows
(`rest-sessions-cross-tenant`, `log-scan`) for coverage.

## Minimal fix

Inside the same case, add the reverse assertion: create a tenant-A session,
run `revokeAllForTenant(TENANT_B)`, assert the tenant-A session survives, then
clean up both sessions. (Same row count: no new `test()` case.)

## Evidence

- `Select-String tests\h8-cross-tenant-probe.test.ts -Pattern 'id: ''session-manager'','revokeAllForTenant\(TENANT_A\)'` → `515: id: 'session-manager-tenant-scoped-bulk',` / `520: rig.world.sessions.revokeAllForTenant(TENANT_A);`
