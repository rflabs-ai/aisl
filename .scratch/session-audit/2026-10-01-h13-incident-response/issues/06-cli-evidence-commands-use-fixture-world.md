Status: resolved (06a8a89)

Source: session-audit 2026-10-01, `feat/h13-incident-response` (uncommitted working tree; no commits this session)

## What's wrong

Every `incident` subcommand starts with `src/cli.ts:1367: const world = await buildWorldAsync();`,
which assembles the full scenario world — `src/scenario.ts:277` and
`src/scenario.ts:287` each `authorization.issue(root, ...)`. Probe:
`P2 bootstrap events on plain buildWorld: 2 {"capability.issue":2}` for
subject `agent:summarizer-1`. Consequences:

1. Default/SQLite mode: there is no shared store, so `incident report` /
   `preserve` reconstruct from this CLI's *fresh fixture world*. Probe:
   `OK     reconstruction                                 5 events, allow=5 deny=0, revocations=0, freezes=0, lifts=0` /
   `actors: authz-root:acme, user:alice` — printed as a successful
   reconstruction with zero incident content and no warning (the runbook's
   in-memory caveat at `DEPLOYMENT.md:373-375` covers only the channel/kill
   switch, not steps 5–6).
2. Postgres mode (`src/scenario.ts:152` / `scenario.ts:169` PG branches): those
   2 bootstrap `capability.issue` events append to the *shared* evidence chain
   on every status/engage/lift invocation, plus one more mint per
   preserve/report (`src/cli.ts:1442` / `:1449`).

## Why it matters

Two honesty failures in the incident path: (a) a SQLite-mode `incident report`
looks like reconstruction of an incident but reports bootstrap fixture data;
(b) in PG mode, "read-only" operator commands mutate the shared evidence chain
with fixture issuances — polluting exactly the chain the incident depends on.

## Minimal fix

Mode honesty + minimal assembly: for `status`/`report`/`preserve`, build the
world without scenario bootstrap (or skip issuing the fixture capabilities when
subcommand is an evidence command), and print the same in-memory note
engaged already prints when `EVENT_STORE !== 'postgres'` for `report`/`preserve`
so a fixture reconstruction cannot be mistaken for incident evidence.

## Evidence:

- `node probe-p2-bootstrap.mts` → `P2 bootstrap events on plain buildWorld: 2 {"capability.issue":2}`
- `node src/cli.ts incident report acme 0 5` → `OK reconstruction 5 events, allow=5 deny=0, revocations=0, freezes=0, lifts=0`
- ledger rows 20–21 in `.scratch/session-audit/2026-10-01-h13-incident-response/evidence.md`

## Resolution (06a8a89)

`WorldOptions` gains `bootstrap?: boolean`; `assembleWorld` skips the two
fixture issuances when false; `incidentCommand` builds
`buildWorldAsync({ bootstrap: false })` and `preserve`/`report` print the
in-memory-mode note in non-Postgres mode. Probe P2 (2 bootstrap events) is now
a test: `bootstrap: false` builds a world that issues/appends nothing.

**Evidence (this session):** `node src/cli.ts incident report acme 0 5` →
bootstrap-free 3 events + mode note; h13 suite green.