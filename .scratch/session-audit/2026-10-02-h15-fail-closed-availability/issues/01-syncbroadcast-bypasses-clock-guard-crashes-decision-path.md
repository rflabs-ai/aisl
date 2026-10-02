Status: resolved (bae96bb)
Source: session-audit 2026-10-02 (H15 fail-closed availability, uncommitted working tree)

## What's wrong

`AuthorizationService.authorize()` and `issue()` call `syncBroadcast()` BEFORE
the guarded clock read, and `syncBroadcast()` reads the clock directly:

- `src/pdp.ts:556: this.syncBroadcast(false);` (before `pdp.ts:559: const clock = this.readClock();`)
- `src/pdp.ts:221: this.syncBroadcast(true);` (before `pdp.ts:223: const clock = this.readClock();`)
- `src/pdp.ts:406: if (!force && this.now() - this.lastSyncAt < this.syncIntervalMs) return;`
- `src/pdp.ts:407: this.lastSyncAt = this.now();`

The production wiring installs the hook (`src/incident.ts:379:
this.authorization.setBroadcastSync((force) => {`). With a faulted clock
(throws / non-finite), `syncBroadcast` throws before `readClock` ever runs, so
`authorize()` and `issue()` throw uncaught instead of producing the clean
`clock-unavailable` deny / typed issuance refusal.

Probe output (this run):

```
PROBE authorize THREW -> clock source dead
PROBE issue THREW -> Error : clock source dead
```

## Why it matters

H15's core contract is "a clock fault denies with the distinct reason and a
health signal" (ADR-027). On the deployed path (every world built through
`IncidentService`), a faulted clock instead crashes the decision: the REST
dispatcher maps the throw to a 500, and no deny event / health transition is
recorded. A crash is a worse operator signal than the pre-H15 behavior the
milestone set out to fix. The H15 test suite missed it because the bare test
stack never installs a broadcast hook.

## Minimal fix

Inside `private syncBroadcast(force: boolean)`, guard the two `this.now()`
reads with try/catch (skip the sync on clock failure — the hook invocation is
already inside the existing catch) so `readClock` remains the only clock fault
authority on both paths. Then add one H15 test that installs a broadcast hook
(`setBroadcastSync`) before faulting the clock, asserting `authorize` →
`clock-unavailable` deny and `issue` → typed refusal.
