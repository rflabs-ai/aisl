Status: resolved (a0f0e4b)
Source: session-audit m12-phase0 (uncommitted ROADMAP.md marker)

## What's wrong

ROADMAP.md:84-86 — the M12 marker reads "driver `postgres.js` pinned", but
nothing is pinned yet: `package.json` has no `postgres` dependency and no
lockfile entry exists. ADR-018 *decides* the driver; Phase 1 adds and pins
it. The marker overstates completion.

## Why it matters

A future reader (or the dependency-admission review in Phase 1) could
believe the ADR-015 pinning requirement is already satisfied and skip the
review/SBOM step.

## Minimal fix

One-word edit: "driver chosen (`postgres.js`; pinned when the dependency
lands in Phase 1)".
