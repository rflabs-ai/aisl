Status: resolved (bae96bb)
Source: session-audit 2026-10-02 (H15 fail-closed availability, uncommitted working tree)

## What's wrong

The H15 suite exercises the clock fault through `authorize` (and, after ticket
03, `issue`), but `queryAudit` has its own `readClock()` branch
(`src/pdp.ts:690-713`) with no test:

```
src/pdp.ts:690:     const clock = this.readClock();
src/pdp.ts:691:     if (!clock.ok) {
```

## Why it matters

`queryAudit` is the audit-read path (`GET /v1/audit`); its clock-fault deny is
part of the H15 contract and is currently only code-read, not run.

## Minimal fix

Add one H15 test: faulted clock → `queryAudit` denies with
`clock-unavailable` (and, since the store is healthy, the deny event lands).
