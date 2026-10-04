# Ticket 08 — Untested branches: checkpoint `eventCount` mismatch and the witness head cap

Status: resolved (3f71244)
Source: session-audit b3e345b..HEAD (H11, ADR-031), Notes/N5

## What's wrong

Two refusal branches had no direct case: `verifyCheckpoint`'s
`eventCount !== seq+1` check (unreachable via `createCheckpoint`, which always
writes `events.length`) and `fetchWitnessHeads`'s `MAX_WITNESS_HEADS` cap.

## Fix

Two tests added to `tests/h11-tamper-evident-evidence.test.ts`:
- "a signed checkpoint whose eventCount disagrees with its seq is refused" —
  hand-signs a consistent body with `eventCount: 1` over seq 2, so only the
  count check can catch it; asserts the `/eventCount/` refusal.
- "a witness response beyond the head cap is refused (no paging)" — builds
  `MAX_WITNESS_HEADS + 1` heads and asserts the `WitnessProtocolError` names
  "too many heads".

## Evidence

`node --test tests/h11-tamper-evident-evidence.test.ts` (this session):
`✔ a signed checkpoint whose eventCount disagrees with its seq is refused`
and `✔ a witness response beyond the head cap is refused (no paging)`;
suite: `tests 39 / pass 39 / fail 0`.