Status: resolved (37c87df — `AND status = 'pending'` guard on the UPDATE + live-DB replay test; live verification pending the next Postgres-mode run)
Source: session-audit M15 fix commit 465b67b

## What's wrong

src/persistence.ts (updateCapabilityRequestStatus) + src/rest-sessions.ts:165-172 —
the M15 fix reorder made persist run unconditionally before `service.approve()`,
but the UPDATE had no status guard: a double-approve or self-approve attempt
(which the service correctly refuses → 409/403) still overwrote
`decided_at = now(), decided_by = <refused reviewer>`. Before the reorder the
service threw first and persist never ran — a regression that falsifies
decision attribution.

## Why it matters

`getCapabilityRequest` then returns false attribution: who decided, and when.
The append-only event plane still holds the true `capability.approve` event,
but the durable state table — the thing the M12 seam exists to keep faithful —
lies after any replayed attempt.

## Minimal fix

`AND status = 'pending'` in the UPDATE (state machine: one decision, ever), so
the replay affects zero rows. Plus a live-DB replay test asserting the second
attempt returns undefined and `decided_by`/`decided_at` are unchanged.
