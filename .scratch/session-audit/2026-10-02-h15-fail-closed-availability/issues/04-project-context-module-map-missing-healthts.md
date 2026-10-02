Status: resolved (bae96bb)
Source: session-audit 2026-10-02 (H15 fail-closed availability, uncommitted working tree)

## What's wrong

`PROJECT_CONTEXT.md`'s module map was updated for H13 but not H15:

```
PROJECT_CONTEXT.md:91:   incident.ts         kill switch + revocation channel + evidence preservation (H13, ADR-026)
```

No row for `health.ts` (HealthState + ClockGuard, ADR-027), and the map's
changelog/status text still ends at H13.

## Why it matters

The repo's rule: docs that drift from code rot into lies (AGENTS.md build
discipline, item 8). PROJECT_CONTEXT is the orientation map the next session
reads first; a missing module makes the health/degraded-mode seam invisible.

## Minimal fix

Add a `health.ts` row beside `incident.ts`
("fail-closed availability: observed health + clock guard (H15, ADR-027)") and
advance the map's status line to H15 done / next H14 or H2–H9/H11. Check
ARCHITECTURE.md is unaffected (grep for H13/H15/health there returns no
matches — it enumerates no milestones).
