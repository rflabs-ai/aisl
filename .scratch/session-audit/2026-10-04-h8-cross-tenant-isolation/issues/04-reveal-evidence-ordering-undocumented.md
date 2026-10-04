Status: resolved (f61817e)
Source: session-audit 2026-10-04 (H8 cross-tenant isolation, feat/h8-cross-tenant-isolation)

## What's wrong

`src/pdp.ts:693` — the keyTenant refusal runs before the auth check (it must,
so the binding precedes both registration and authorization), but the code
comment does not say the ordering is deliberate. A reader comparing it with
`authorize()` (auth first) can read it as an oversight:

- `src/pdp.ts:687: // to another tenant BEFORE the lazy registry registration below - without`
- `src/pdp.ts:693: const keyTenant = tenantFromKeyId(sealed.keyId);`

## Why it matters

The ordering is load-bearing and fail-closed (an unauthorized caller can only
produce a deny event); leaving it unexplained invites a "fix" that reorders it
and re-opens the registration-before-binding window the H8 fix closed.

## Minimal fix

Extend the existing comment with one sentence: the check precedes the auth
check by design because the key binding must hold before any registration or
authorization, so an unauthorized caller can only produce a deny.

## Evidence

- `Select-String src\pdp.ts -Pattern 'const keyTenant','BEFORE the lazy'` → `687: // to another tenant BEFORE the lazy registry registration below - without` / `693: const keyTenant = tenantFromKeyId(sealed.keyId);`
