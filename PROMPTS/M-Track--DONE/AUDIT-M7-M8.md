# M7/M8 audit — drift between prompt and implementation

Audit performed as part of M9 scoping. The M7 prompt (`PROMPTS/M7-policy-testing-and-reliability.md`)
was the spec; the implementation that landed in commit `e86f9ec` is the artifact.
This file lists every drift found, where the drift lives, and what M9 closes.

**Status:** audit complete. Six drift items, all closed by M9.

## What passed the audit (no drift)

- 243 tests pass; 205 prior tests preserved.
- `npm run policy:diff` works: default invocation prints `0 changed`;
  with `overlay-deny-agent-read.json` it prints `3 changed` with
  per-scenario before/after.
- `npm run demo` runs all 15 sections; demo sections 14 + 15 work as
  specified.
- `npm run benchmark` regenerates `benchmarks/results.json` with the
  two new latency fields (`policyDiffLatencyMs ≈ 0.12 ms`,
  `guardLatencyP99Ms ≈ 0.007 ms`).
- `auditCompleteness = 1.0`; `unauthorizedActionDenialRate = 1.0`
  (preserved from prior milestones).
- ROADMAP Stage 1 rows for "Policy testing framework" and "Output
  reliability layer" flipped to `[DONE]` with M7 references and
  Claim 22/23.
- `SECURITY_CLAIMS.md` Claim 22 + 23 added with the required structure
  (Claim, Mechanism, Threat model, Assumptions, Evidence, Test, Known
  limitations, Residual risk).
- `CURRENT_STATE.md` updated with "What M7 closed" + "What M8 closed"
  sections, header "after M7/M8", test count 205 → 243.
- `AGENT-SESSION.md` SESSION 8 entry summarizing what the three
  subagents built, what was deferred, and the next session's first
  action.
- `RELIABILITY.md` status footer flipped from "design, not yet built"
  to "implemented; see SESSION 8".
- R3 dependency-direction test enforced (pdp.ts does not import
  guard.ts and vice versa).
- `src/pdp.ts` was not modified.

## Drift found

### Drift 1 — Escalate does not queue a `CapabilityRequest` (user-flagged)

**Location:** `src/guard.ts:171-174` (`runLadder` Escalate rung).

**Prompt said:**
> §8 minimum cases: "Ladder escalate: classification `>= confidential`,
> ladder reaches escalate rung → output is the structured awaiting-review
> message; `CapabilityRequest` is queued via the M4 path (test asserts
> request was created, not that it was approved)."

**Implementation did:**
```ts
const text = classificationRank(options.classification) >= classificationRank('confidential')
  ? (options.escalateText ?? ESCALATE_DEFAULT)
  : SAFE_COMPLETION;
return { status: 'withheld', text, flags, citations: [], guardId: GUARD_ID, originalSealed: sealed(initialText) };
```

No `CapabilityRequest` is created. The awaiting-review text is returned
and that's it. The session continues to `session.end`. There is no M4
request to approve.

**Prompt §14 said:** "The `Escalate` rung creates a `CapabilityRequest`
but does not wait for approval. The M4 approval flow handles that —
out of scope here." This was an explicit deferral, but the prompt §8
test minimum said the test should "assert request was created, not
that it was approved" — contradicting §14's "out of scope here".

**Why this matters:** M4 is built. `CapabilityRequestService` exists,
is tested, and the request→approval→capability lifecycle is wired
end-to-end. The guard's Escalate rung is the natural caller of M4 —
without it, the awaiting-review text is informational only, and there's
no record in M4 of the escalation request.

**Closed by:** M9 Subagent A. The Escalate rung will call
`CapabilityRequestService.submit()` when the gate fires, and the
awaiting-review text will name the returned request id.

### Drift 2 — `metadata.sealed` is JSON-stringified, not a raw `Sealed` object

**Location:** `src/guard.ts:163, 190` (`runLadder` and
`GroundedResponseGuard.guard`); `src/runtime.ts:277` (event emission).

**Prompt §5 said:**
```ts
sealed: Sealed | null,        // the original modelText, sealed per classification
```

**Implementation did:**
```ts
const sealed = (txt: string) => JSON.stringify(seal(txt, options.classification));
// ...
metadata: {
  // ...
  sealed: guarded.originalSealed,  // ← string, not Sealed
}
```

The `GuardedResponse.originalSealed` field is typed as `string | null`,
not `Sealed | null`. Other events (e.g., `record()` in
`src/runtime.ts:313-345`) emit `sealed` as a raw `Sealed` object — only
the guard event is inconsistent.

**Why this matters:** investigators reading the event log can't
directly see `sealed.ciphertext`, `sealed.keyId`, `sealed.iv`,
`sealed.tag` without JSON-parsing first. Inconsistent with the
existing sealing pattern from invariant 13.

**Closed by:** M9 Subagent C. `GuardedResponse.originalSealed` becomes
`Sealed | null`; `runLadder` and `GroundedResponseGuard` stop
JSON-stringifying; `runtime.ts` passes the raw object.

### Drift 3 — `metadata.ladderRung` is always `null`

**Location:** `src/runtime.ts:278`.

**Prompt §5 said:**
```ts
ladderRung?: 'repair' | 'regenerate' | 'abstain' | 'escalate' | null,
```

**Implementation did:**
```ts
ladderRung: null,  // hardcoded
```

The prompt explicitly listed the four valid rung values plus `null`.
The implementation always sets `null`. Operators reading the event log
can't tell whether the response was repaired, abstained, or escalated
without parsing the text.

**Closed by:** M9 Subagent C. `runLadder` returns the rung that fired;
`GroundedResponseGuard.guard` threads it through; `runtime.ts` records
it in metadata.

### Drift 4 — D4 produces duplicate flags

**Location:** `src/guard.ts:117-140`.

**Prompt §3 said:**
> **D2 — Claim-source binding.** ... An uncited consequential claim is
> flagged `unverified-claim`.
> **D4 — Numeric recomputation.** Numbers in the text attributed to
> tool output are compared against the actual (structured) tool
> outputs in `steps[].output`. Mismatch → flag `numeric-mismatch`.

These are distinct flags for distinct conditions. The implementation
adds BOTH for the same number when it appears in text without a
matching tool output:

```ts
// Line 118-125 (D2 logic)
for (const m of ctx.modelText.matchAll(NUMBER_RE)) {
  if (...) { ... }
  if (stepOutputs.some((o) => o.includes(n))) continue;  // skip if matched
  flags.push({ claim: n, reason: 'unverified-claim' });
}
// Line 135-140 (D4 logic)
if (stepOutputs.length > 0) {
  for (const m of ctx.modelText.matchAll(NUMBER_RE)) {
    const n = m[0]!;
    if (!stepOutputs.some((b) => b.includes(n))) flags.push({ claim: n, reason: 'numeric-mismatch' });
  }
}
```

When `stepOutputs.length > 0` and a number isn't in any step output,
it gets BOTH `unverified-claim` AND `numeric-mismatch` flags. The two
checks overlap.

**Why this matters:** the flag list shows the same claim twice with
different reasons. The repair function tries to strip both, but
should only strip one. The escalator sees two reasons for the same
claim.

**Closed by:** M9 Subagent C. The D2 number check and D4 number check
are merged: a number that's not in any step output gets
`numeric-mismatch` if there are step outputs, `unverified-claim` if
there aren't. Never both.

### Drift 5 — `regenerateFn` rung is untested

**Location:** `src/guard.ts:170` (code); `tests/guard.test.ts` (no
coverage).

**Prompt §8 said:**
> **Ladder regenerate:** flags persist after repair → `regenerateFn`
> called once; second failure → terminal `abstain`.

The code path exists (line 170 calls `regenerateFn` if repair fails),
but no test exercises it. The default wiring passes `null` for
`regenerateFn`, so in production this rung is never reached.

**Why this matters:** the rung is part of the documented contract.
The implementation has it; the test suite doesn't prove it works. A
future refactor that breaks the rung would not be caught.

**Closed by:** M9 Subagent C. Two tests added: one that passes a
`regenerateFn` returning clean text (asserts `repaired`); one that
passes a `regenerateFn` returning flagged text (asserts `withheld`,
no second regen).

### Drift 6 — `falseClaimRate` not in benchmark output

**Location:** `src/cli.ts` benchmark.

**Prompt §9 (in RELIABILITY.md §8) said:**
> - `falseClaimRate` — flagged claims / delivered claims on the
>   legitimate fixture corpus (target within assurance target 7's <= 1%
>   false-denial budget).

`tests/guard.test.ts` and `security-tests/guard-invariants.test.ts`
both measure `falseClaimRate`. The benchmark does not surface it.

**Why this matters:** the metric is the only R1 measurement that
operators see. It's measured on every test run (R1 test asserts
`falseClaimRate <= 0.01`) but not exported to `benchmarks/results.json`.
A regression in the guard's precision wouldn't show up in the
benchmark summary.

**Closed by:** M9 Subagent C. `src/cli.ts:benchmark()` runs the
legitimate fixture corpus through the guard and adds
`falseClaimRate` to `metrics.evidence` in `benchmarks/results.json`.

## Summary

| # | Drift | Where | Closed by |
|---|---|---|---|
| 1 | Escalate doesn't queue CapabilityRequest | `src/guard.ts:171-174` | M9 Subagent A |
| 2 | `metadata.sealed` is stringified, not raw | `src/guard.ts:163,190`, `src/runtime.ts:277` | M9 Subagent C |
| 3 | `metadata.ladderRung` is always `null` | `src/runtime.ts:278` | M9 Subagent C |
| 4 | D4 duplicates `unverified-claim` | `src/guard.ts:117-140` | M9 Subagent C |
| 5 | `regenerateFn` rung untested | `tests/guard.test.ts` | M9 Subagent C |
| 6 | `falseClaimRate` not in benchmark output | `src/cli.ts` | M9 Subagent C |

All six items are in scope for M9 (PROMPTS/M9-guard-followups-and-drift-closure.md).
Three additional SESSION 8 deferred items (per-session classification derivation,
second-pass guard, D6 critic hook) are also M9 scope.

## What was NOT drift

The prompt and implementation agree on:
- D2 / D3 / D5 detection semantics
- The ladder order: Repair → Regenerate → Abstain → Escalate
- D5 leak skipping the ladder
- Fail-closed when `guard()` throws
- `result: 'error'` when status is `'withheld'` (so audit-completeness still counts)
- `metadata.phase === 'guard'` on the session.guard event
- The action namespace (`session.guard`, not a new `KnownAction`)
- R3 dependency-direction (pdp.ts does not import guard.ts)
- The `R3 no-authority structural` test (GuardContext keys, no `issue|authoriz|secret|grant`)
- The R1 falseClaimRate budget (≤ 1%)
- The R2 withhold scan (forged citation, action-claim-mismatch, prose leak, poisoned source)
- 23+ new tests added (38 actual)
- JSON fixtures only (no DSL)
- Zero new runtime dependencies
- The poison-source ceiling documented as TM-002 residual

The audit found no other drift.