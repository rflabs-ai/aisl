Status: resolved (bae96bb)
Source: session-audit 2026-10-02 (H15 fail-closed availability, uncommitted working tree)

## What's wrong

`clockFaultDeny` appends its deny event but never marks the store healthy on
success, unlike the main `authorize` path (`this.health.mark('store', 'ok')`
after a successful append). Source:

```
src/pdp.ts:190:     try {
src/pdp.ts:191:       this.eventLog.append({
...
src/pdp.ts:203:     } catch {
src/pdp.ts:204:       this.health.mark('store', 'unavailable', 'evidence append failed');
src/pdp.ts:205:     }
```

## Why it matters

With a faulted clock AND a recovered store, `/healthz` keeps reporting
`store: unavailable` until some non-clock-faulted decision appends — the
health surface lies in exactly the recovery window operators watch.

## Minimal fix

Add `this.health.mark('store', 'ok');` after the successful append inside the
try (one line). Test: fault the clock, recover the store, deny once, assert
`healthState.snapshot().store === 'ok'`.
