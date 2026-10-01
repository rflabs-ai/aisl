Status: open
Source: session-audit 2026-10-01, `feat/h12-secure-updates` (uncommitted working tree) — audit nit F-02

## What's wrong

`update promote` prints `stage=0/-1` on the no-rollout path. The format string
at `src/cli.ts:1141` computes `stages.length - 1` unconditionally:

```
cli.ts:1141: line('rollout', result.state.rollout.status.toUpperCase(), `stage=${result.state.rollout.stageIndex}/${result.state.rollout.stages.length - 1}${...}`);
```

The status command guards the same arithmetic (`src/cli.ts:1161`:
`stages.length === 0 ? '-' : stages.length - 1`), promote does not.

## Why it matters

Operator-facing display defect on a normal path (`update promote ok` with no
rollout in flight): a negative stage reads as evaluated state and is
indistinguishable from a bug in the state machine.

## Minimal fix

Use the same guard as status:
`stage=${result.state.rollout.stageIndex}/${result.state.rollout.stages.length === 0 ? '-' : result.state.rollout.stages.length - 1}`.

## Evidence

`node src/cli.ts update promote ok` (this run):

```
  NONE   rollout                                        stage=0/-1
  no rollout in flight — nothing to promote.
EXIT=0
```
