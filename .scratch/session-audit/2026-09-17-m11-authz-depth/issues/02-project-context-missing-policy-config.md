# PROJECT_CONTEXT.md file map missing src/policy-config.ts (M11 module)

Status: resolved (2026-09-17)
Source: session-audit 12ed44b..a951ad1

Resolution: `policy-config.ts` added to the PROJECT_CONTEXT file map — plus
the three M13 modules that were missing the same way (`model-http.ts`,
`check-command.ts`, `telemetry.ts`). Map now matches `src/` (31 modules).

## What's wrong

M11 added `src/policy-config.ts` (policy/role bundles, the Claim 26 mechanism)
but did not add it to the `PROJECT_CONTEXT.md` file map, which still lists the
pre-M11 module set (`slo.ts` present, `policy-config.ts` absent —
`PROJECT_CONTEXT.md:58` neighborhood). The repo's convention is to resync this
map (see `dad3a2e`: "resync PROJECT_CONTEXT file map").

## Why it matters

PROJECT_CONTEXT.md is the onboarding/breadcrumb doc a new session reads first;
an unlisted module is an unfindable module. M11 §6 did not list PROJECT_CONTEXT
as a required doc, so this is a breadcrumb gap, not a spec miss — but the audit
spec treats stale docs relative to the change as a finding.

## Minimal fix

Add one line to the file map, matching the existing style:

`policy-config.ts    versioned, hash-verified policy/role bundles (M11, Claim 26)`

and bump the module count if the map carries one.
