# Ticket 09 — `EVIDENCE_READ_ACTIONS` omits the new write actions (document the freeze interaction)

Status: resolved (3f71244)
Source: session-audit b3e345b..HEAD (H11, ADR-031), Notes/N6

## What's wrong

`src/pdp.ts:97`'s `EVIDENCE_READ_ACTIONS` (`query.audit`, `audit.export`,
`evidence.decrypt`) does not name `evidence.hold`/`evidence.release`. That is
correct today — they are write actions and the RetentionLedger appends through
the operator/embedder seam, not a PDP-routed capability — but the omission
was implicit, and a future capability-gated hold path would silently inherit
the freeze behavior (`issue` refuses `incident-frozen`).

## Fix

Added the rationale + the explicit future decision to the
`EVIDENCE_READ_ACTIONS` docstring in `src/pdp.ts`: holds are deliberately not
in the read set, and a future PDP-routed hold surface must decide the freeze
interaction explicitly. No behavior change.

## Evidence

`git grep -F "evidence.hold" HEAD -- src/pdp.ts` → hit in the new docstring
block above `const EVIDENCE_READ_ACTIONS`; `git grep -F "new Set(['query.audit', 'audit.export', 'evidence.decrypt'])" HEAD -- src` →
`HEAD:src/pdp.ts:const EVIDENCE_READ_ACTIONS: ReadonlySet<string> = new Set(['query.audit', 'audit.export', 'evidence.decrypt']);` (unchanged set).