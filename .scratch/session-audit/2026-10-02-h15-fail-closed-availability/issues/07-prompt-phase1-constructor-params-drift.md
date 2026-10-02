Status: resolved (bae96bb)
Source: session-audit 2026-10-02 (H15 fail-closed availability, uncommitted working tree)

## What's wrong

The expanded H15 prompt specifies a constructor signature change that was not
shipped:

```
PROMPTS/H-Track/H15-fail-closed-availability.md:79: - `AuthorizationService` constructor gains two optional trailing params:
```

Shipped instead: setters, matching the class's existing `setBroadcastSync`
pattern:

```
src/pdp.ts:150:   setHealth(health: HealthState): void {
src/pdp.ts:155:   get healthState(): HealthState {
src/pdp.ts:160:   setClockGuard(guard: ClockGuard): void {
```

The Resolution section below line 200 records the shipped API, so the prompt
contradicts itself (spec body vs resolution).

## Why it matters

Spec drift inside the milestone prompt; the next agent reading Phase 1 would
look for constructor params that do not exist.

## Minimal fix

Update the Phase 1 bullet to state the shipped installation API
(`setHealth`/`healthState`/`setClockGuard`, the `setBroadcastSync` pattern)
and note the constructor was left unchanged. No code change.
