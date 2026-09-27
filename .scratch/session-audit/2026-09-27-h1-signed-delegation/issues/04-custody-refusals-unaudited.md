Status: resolved (b1e8454)

Source: session-audit f62230d (session 2026-09-27)

## What's wrong

The two new service-level custody refusals — parent not registered
(src/pdp.ts:99-101) and parent revoked (src/pdp.ts:103-104) — throw
`CapabilityIssuanceError` without appending an audit event. A delegation
attempt from a revoked or unregistered parent is a security-relevant refusal
and leaves no trace in the evidence chain.

## Why it matters

The project's invariant-7 philosophy ("a denied action produces an audit
event") exists so incident response can see what was attempted and refused.
"Someone tried to delegate from a revoked capability" is precisely the signal
an incident responder wants. Pre-existing issuance throws (overreach, wrong
kind) are also silent — not a regression — but these two paths are new and
stateful, sitting right next to the event log.

## Minimal fix

Before throwing in `AuthorizationService.issue`, append a `capability.issue`
event with `decision: 'deny'` (reuse the existing event shape; a
`denyReason` or `result: 'denied'` plus the parent id), then throw as today.
Alternatively, document issuance-refusals as a named non-eventing class in
Claim 7's limitations if the event shape is deliberately out of scope.
