Status: resolved (f61817e)
Source: session-audit 2026-10-04 (H8 cross-tenant isolation, feat/h8-cross-tenant-isolation)

## What's wrong

`src/capability-request.ts:212` — the `requireSameTenant` docstring claims
"embedders and the guard's escalation lane call it directly", but the
escalation lane only SUBMITS a request; it never calls `approve`/`deny`:

- `src/capability-request.ts:212: * must hold on its own (embedders and the guard's escalation lane call it`
- `src/guard.ts:194: const request = ctx.capabilityRequestService.submit(`

## Why it matters

The docstring's audience list is wrong; the next reader looking for the
decision-surface callers would search the guard and find only a submit. The
real direct callers are embedders and tests (and `deny` has no REST route at
all).

## Minimal fix

Reword the parenthetical to "(embedders call it directly; the guard's
escalation lane submits through it; no REST route calls `deny`)".

## Evidence

- `Select-String src\capability-request.ts -Pattern 'escalation lane'` → `212: * must hold on its own (embedders and the guard's escalation lane call it`
- `Select-String src\guard.ts -Pattern 'capabilityRequestService.submit'` → `guard.ts:194: const request = ctx.capabilityRequestService.submit(`
