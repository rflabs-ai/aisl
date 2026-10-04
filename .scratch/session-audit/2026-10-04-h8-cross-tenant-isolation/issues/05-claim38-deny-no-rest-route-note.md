Status: resolved (f61817e)
Source: session-audit 2026-10-04 (H8 cross-tenant isolation, feat/h8-cross-tenant-isolation)

## What's wrong

Claim 38 credits `requireSameTenant` in `approve`/`deny` without noting that
`deny` is the only one of the pair with no REST route — the HTTP boundary
never calls it, so the decision-surface check is that path's only tenant
guard:

- `SECURITY_CLAIMS.md:2006: `src/capability-request.ts` (`requireSameTenant` in `approve`/`deny`). The`
- `Select-String src\rest-sessions.ts -Pattern 'addRoute'` → 6 routes (lines 81, 95, 105, 136, 144, 159), none of which call `deny`.

## Why it matters

The claim is correct but reads as "the boundary still covers this"; for
`deny` there is no boundary. An operator auditing the claim would over-trust
the REST layer for a route that does not exist.

## Minimal fix

Amend the Claim 38 mechanism sentence: "`deny` has no REST route, so the
decision-surface check is its only tenant guard".

## Evidence

- `Select-String SECURITY_CLAIMS.md -Pattern 'requireSameTenant` in'` → `2006: `src/capability-request.ts` (`requireSameTenant` in `approve`/`deny`). The`
- `Grep 'addRoute' src/rest-sessions.ts` → `Line 81: api.addRoute('POST', '/v1/sessions', ...` … six matches, no `deny` route.
