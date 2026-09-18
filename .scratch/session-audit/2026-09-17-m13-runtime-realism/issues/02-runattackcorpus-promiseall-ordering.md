# runAttackCorpus switched from sequential to Promise.all — shared-world interleaving is deterministic only by accident

Status: resolved (2026-09-17)
Source: session-audit 440ba58..89ec9db

Resolution: sequential `for ... await` loop restored in `runAttackCorpus`,
with a comment naming the invariant (shared world → corpus-deterministic
evidence order). No ordering test added: `runAttackCase` builds its own
synchronous `compromisedModel` internally, so a pinning test would need a
world refactor to inject an async model — the one-line restoration is the
audit's own minimal fix.

## What's wrong

`src/attacks.ts:118` now runs the corpus with
`Promise.all(loadAttackCorpus(dir).map((c) => runAttackCase(world, c)))` — a
concurrency change bundled silently into M13's async migration. All attack
cases share one `world` (registry, event log, authorization, content map) and
`runAttackCase` awaits inside `session.run()`
(`src/attacks.ts:72`), so cases interleave at that boundary. Today the
interleaving is still deterministic: `ScriptedModel.complete` returns
synchronously and microtask resumption order is FIFO — but the moment any
harness model returns a real promise (the new `HttpModelPort` async path makes
that a supported shape of `ModelPort`, `src/model.ts:30`), cross-session event
order in the evidence log becomes nondeterministic while remaining
hash-chain-valid — precisely the drift that makes audit trails unquotable.
The commit message never mentions the semantic change.

## Why it matters

The evidence plane's credibility rests on reproducible ordering, not just an
intact chain. An async model port is now first-class (that was the M13-A
change), so the assumption holding the determinism is one `await` away from
gone — with no test pinning it.

## Minimal fix

One line: replace `Promise.all(...map...)` with a sequential
`for (const c of loadAttackCorpus(dir)) results.push(await runAttackCase(world, c))`
loop, restoring the pre-M13 semantics. (If parallelism is actually wanted, it
needs per-case worlds — then say so in the commit message.)
