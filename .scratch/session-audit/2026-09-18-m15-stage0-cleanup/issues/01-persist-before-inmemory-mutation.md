Status: open
Source: session-audit M15 (commit c9f5176, merge9d88d0d)

## What's wrong

`src/rest-sessions.ts:161-170` — the approve handler calls `service.approve()` **before** `persist()`. If `persist()` throws (Postgres down, network blip), the handler throws 500 to the client. But `service.approve()` already:
- consumed the single-use capability in the in-memory CapabilityRequestService
- recorded the approval as `status: 'approved'` in memory

On restart: the approval is lost (not persisted) but the capability remains consumed. The capability is permanently unusable — there is no way to re-approve because the request is back to `pending` but the capability is already gone. This is a data loss bug.

The same pattern exists in the submit handler (`src/rest-sessions.ts:107-131`): `service.submit()` is called before `persist()`. If persist throws, the request exists in memory (visible on GET /v1/capability-requests) but the client saw500. On restart: request lost. This is split-brain, not just durability loss.

## Why it matters

The fail-closed posture says "propagate errors" — but propagating the persistence error after the in-memory mutation is the wrong order. The correct ordering is: **persist first, then mutate in-memory**. If persist fails, the in-memory state is unchanged and the client sees a clean error. If persist succeeds but the in-memory mutation fails (unlikely), the persisted record is orphaned but no capability is consumed.

The approve case is worse than the submit case: a consumed single-use capability cannot be recovered. The submit case is "just" split-brain (client thinks failed, request actually exists). The approve case is permanent data loss.

## Minimal fix

**Approve handler (critical):** move `persist()` before `service.approve()`:
```ts
if (deps.requestsStore) {
  await deps.requestsStore.updateCapabilityRequestStatus(ctx.principal.tenantId, id, 'approved', ctx.principal.id);
}
const approved = deps.requests.approve(id, ctx.principal, scope);
```
If persist throws, the capability is never consumed. If persist succeeds but service.approve() throws (e.g., request already approved), the persisted status is stale but no capability is consumed — acceptable.

**Submit handler:** refactor `CapabilityRequestService.submit()` to accept an externally-generated id (e.g., `submit(principal, sessionId, resources, actions, maxClassification, justification, id?)`), or use a two-phase approach: generate id, persist, then submit with the same id. The second option is a larger refactor; the first is a one-line optional parameter.
