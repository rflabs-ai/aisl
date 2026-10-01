Status: open
Source: session-audit 95d5075 (M16 sandbox lifecycle) — trunk c130c48
File: src/sandbox-registry.ts:244

## What's wrong
The `ponytail:` marker on the `sweepExit()` catch block names the ceiling ("swallow per-sandbox sweep failures") but does NOT name an upgrade path. Per AGENTS.md every ponytail marker must name a ceiling AND an upgrade path. Right now a failed sandbox teardown during exit sweep is silently swallowed with no operator signal — a broken destroy is invisible.

## Why it matters
If `destroy()` throws (e.g. the event store is mid-write, or a future destroy gains a failing side-effect), the exit sweep finishes "successfully" with a partial fleet teardown and no record of which sandboxes failed. An operator reading the event log sees every sandbox as cleanly destroyed. The current codebase has no telemetry sink (Claim 28: telemetry is not a control), so the only durable signal is the event log — and a swallowed failure leaves none.

## Minimal fix
Append the upgrade path to the existing marker, e.g.:

```
// ponytail: swallow per-sandbox sweep failures during exit — evidence for the rest
// of the fleet outweighs a clean exit code on one broken teardown. upgrade: surface
// partial-failure via a sweep summary event (sandbox.sweep with failedIds) or a
// process warning when any destroy throws.
```

No behavior change — this is a comment-only fix that makes the debt legible and ledgerable.
