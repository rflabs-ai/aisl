Status: resolved (bae96bb)
Source: session-audit 2026-10-02 (H15 fail-closed availability, uncommitted working tree)

## What's wrong

Safety/bookkeeping paths read the raw clock instead of a fault-tolerant
reading, so a faulted clock throws there even though none of these calls make
an authority decision from the timestamp:

- `src/pdp.ts:342: this.registeredAt.set(cap.id, this.now());` (`grant`)
- `src/pdp.ts:357: this.capabilities.set(capabilityId, markUsed(cap, this.now()));` (`consume`)
- `src/pdp.ts:364: revokedAt: this.now(),` (`revoke`)
- `src/pdp.ts:434: const entry: FreezeEntry = { scope, ..., at: this.now(), actor };` (`freeze`)

Worst case is `freeze()` during an `engage`: it throws before applying state,
`engage`'s catch rethrows (freeze not applied), and `revokeAll` never runs —
the kill switch fails entirely on a clock fault. `consume()` throwing after a
successful execution leaves a single-use capability unconsumed (replay
window). Timestamps here are bookkeeping; the H15 fix made the decision path
fault-tolerant but left the safety actions raw.

## Why it matters

H15's own rule: safety mechanisms must survive dependency faults better than
the decision path (ADR-027 decisions 4-5). A clock fault must not disable the
kill switch or leave consumption unrecorded.

## Minimal fix

Add a private `bookkeepingNow(): number` (`this.readClock()`; on fault fall
back to `Date.now()` — the same posture `clockFaultDeny` already uses:
`src/pdp.ts:186: Date.now(),`) and use it at the four sites. Add one H15 test:
faulted clock → `freeze` applies, `revoke` applies, `consume` marks the cap
used.
