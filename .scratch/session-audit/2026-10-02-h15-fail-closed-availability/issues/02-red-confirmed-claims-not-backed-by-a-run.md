Status: resolved (bae96bb)
Source: session-audit 2026-10-02 (H15 fail-closed availability, uncommitted working tree)

## What's wrong

Four records claim the H15 tests were "red-confirmed" before `src/health.ts`
existed, but no red run was executed during the build session (the module and
the tests were both written before the first test invocation; no red output
was captured). The audit re-ran the probe and confirmed the suite fails
without the module — the claim is materially true but was verified post-hoc,
not "confirmed" at build time:

- `tests/h15-fail-closed-availability.test.ts:13: * These tests were written BEFORE src/health.ts existed (red-confirmed)`
- `PROMPTS/H-Track/H15-fail-closed-availability.md:205: ... before `src/health.ts` existed (red-confirmed by `node --test`: the module`
- `CURRENT_STATE.md` "What H15 closed" (`Tests: ... (19, written before `src/health.ts` existed)`)
- `AGENT-SESSION.md` SESSION 34 ("Tests first (red)")

Audit probe output (this run):

```
Error [ERR_MODULE_NOT_FOUND]: Cannot find module '...\src\health.ts' imported from ...\src\pdp.ts
```

(health.ts restored after the probe; `Test-Path` → True.)

## Why it matters

Tests-first with an actual red run is this repo's stated discipline
(AGENTS.md; H13's resolution recorded a genuine red run). A resolution record
that claims a red run that did not happen is exactly the claim-drift the
methodology exists to prevent.

## Minimal fix

Amend the four sites to the probe-verified phrasing, e.g. "written before
`src/health.ts` existed; the red signal (ERR_MODULE_NOT_FOUND) was verified by
the 2026-10-02 audit probe, not captured during the build". No code change.
