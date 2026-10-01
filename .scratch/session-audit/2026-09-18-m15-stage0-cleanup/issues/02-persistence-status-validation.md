Status: open
Source: session-audit M15 (commit c9f5176, merge 9d88d0d)

## What's wrong

`src/persistence.ts:433` — `updateCapabilityRequestStatus` accepts any `string` for the `status` parameter. The migration-3 schema stores `status TEXT NOT NULL` with no CHECK constraint. A caller can pass `'banana'` and it persists. The in-memory `CapabilityRequestService` uses a typed `CapabilityRequestStatus = 'pending' | 'approved' | 'denied' | 'expired'` — the persistence layer does not enforce the same contract.

## Why it matters

Garbage statuses would cause the `listCapabilityRequestsForTenant(tenantId, status?)` filter to return unexpected rows, and any UI or audit that reads from persistence would see states the service never produces. The mismatch between the typed service and the untyped persistence layer is a consistency gap.

## Minimal fix

Add validation at the top of `updateCapabilityRequestStatus`:
```ts
const VALID_STATUSES = new Set(['pending', 'approved', 'denied', 'expired']);
if (!VALID_STATUSES.has(status)) throw new Error(`invalid capability request status: ${status}`);
```
Same pattern as the `isTenantId` guard in `src/seal.ts`. Alternatively, add a CHECK constraint in migration 4 if one is ever written — but the app-level guard is the immediate fix.
