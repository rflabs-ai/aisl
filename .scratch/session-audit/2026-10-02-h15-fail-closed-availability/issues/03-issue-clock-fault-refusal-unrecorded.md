Status: resolved (bae96bb)
Source: session-audit 2026-10-02 (H15 fail-closed availability, uncommitted working tree)

## What's wrong

`issue()`'s clock-fault branch records no evidence event:

```
src/pdp.ts:224:     if (!clock.ok) {
src/pdp.ts:225:       throw new CapabilityIssuanceError(`clock unavailable, capability issuance refused: ${clock.detail}`);
src/pdp.ts:226:     }
```

Contrast: the freeze refusal and custody refusal in the same function both
append a `capability.issue` deny event before throwing (audited refusals),
and `clockFaultDeny` (authorize/queryAudit) appends the deny event too. Once
ticket 01 stops the syncBroadcast crash, a clock-faulted issuance refusal
leaves nothing in the evidence chain.

## Why it matters

Invariant 7 spirit and the H13 refusal precedent: refusals of authority
operations are security-relevant and audited. An unrecorded refusal is
indistinguishable from an attempt that never happened.

## Minimal fix

Wrap a `capability.issue` deny event (metadata
`{ phase: 'capability-issuance-refused', refusal }`, denyReason
`clock-unavailable`) in try/catch inside the `!clock.ok` branch before the
throw — the store may be healthy even when the clock is not (mirror the
freeze-refusal pattern in the same function). Add an H15 test case.
