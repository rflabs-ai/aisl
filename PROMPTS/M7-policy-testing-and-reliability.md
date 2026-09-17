# M7 — Policy Testing Framework + Output Reliability Layer (designed → built)

Begin M7/M8. This milestone has two pieces that ship together because they
share the same testing posture: rules and prose are both human-authored trust
surfaces that today have no first-class harness to assert their behavior.

Read PROJECT_CONTEXT.md, ARCHITECTURE.md (sections 4–7), SECURITY_CLAIMS.md
(Claims 6, 7, 9, 13; the R1–R3 drafts in RELIABILITY.md §6), DECISIONS.md
(ADR-001, ADR-014), ROADMAP.md (Stage 1 rows: Policy testing framework
`[NEXT]`, Output reliability layer `[designed]`), CURRENT_STATE.md
known-vulnerabilities around policy authoring and the text channel,
AGENT-SESSION.md, RELIABILITY.md (the design doc on disk — already there from
SESSION 6, do not rewrite it), `src/policy.ts`, `src/verification.ts`,
`src/runtime.ts` (`AgentSession.run`, `SessionTrace.modelText`),
`src/scenario.ts` (`attackRequests`, `summarizeRepoModel`), and
`security-attacks/`, `security-fixtures/`.

Goal: today there is no way to author or run a unit test against the policy
rule set in isolation, and no guard at all between the model and the user for
prose (`SessionTrace.modelText` at `src/runtime.ts:258` is raw, unannotated).
Operators have to read the rules to know they deny what they intend; users
have no signal when the model asserts something the session never executed or
quotes something it never read. M7 closes both:

- A **policy testing framework** so a rule is a unit-testable artifact: rule
  fixtures, scenario tables, golden decisions, deny-reason assertions, and a
  diff mode that surfaces exactly what changed between two rule sets.
- The **output reliability layer** (RELIABILITY.md §9) brought from design to
  code: `ResponseGuard` interface, `GroundedResponseGuard` (D2–D5; D6 is
  telemetry-only), the bounded fallback ladder, and the structural R3
  invariant (the guard holds no authority).

These two ship together because the policy framework is what the benchmark
needs to assert attack-corpus invariants in a maintainable way, and the
reliability layer's R1–R3 claims are exactly the kind of structural tests the
framework is designed to express.

This is Stage 1 (M7) plus the M8/`[designed]` reliability implementation;
M-size policy framework, M-size reliability implementation, MVP class.

## 1. Subagent allocation

Use subagents for these defined tasks, in this order. The main session stays
in charge of the seam between them.

### Subagent A — Policy testing framework (`tests/policy-harness.ts`, fixture runner)

Scope:

1. Build `src/policy-testing.ts` with three primitives:
   - `simulate(engine, scenarios): Decision[]` — runs an array of `{principal,
     resource, action, params, approvals?}` scenarios through the engine and
     returns the resulting `{effect, ruleId, reason}` per scenario, plus the
     deny reason taxonomy.
   - `diffDecisions(before, after, scenarios): DecisionDiff[]` — compares two
     engines against the same scenario set; returns one entry per scenario
     where the decision changed, with old/new rule id and old/new reason.
   - `loadFixtures(dir): Fixture[]` — reads `tests/fixtures/policy/*.json`
     files into a typed shape (each file declares scenarios + expected
     decisions).
2. Build `tests/policy-harness.test.ts` that asserts each primitive: scenario
   run produces the engine's decision (no replay ambiguity), diff surfaces
   rule-id changes and reason changes, fixture loader rejects malformed files
   with a clear error.
3. Convert at least three `tests/invariants.test.ts` policy-engine cases into
   fixture-driven tests under `tests/fixtures/policy/` to prove the harness
   is sufficient (not a complete migration — three is enough to validate the
   shape; a follow-up PR migrates the rest).
4. Add a `npm run policy:diff` script that loads `BASELINE_POLICY` + a
   user-supplied overlay file and prints the diff. Default invocation diffs
   against itself (proves the plumbing).

Ponytail: do not invent a DSL. JSON fixtures only. Do not add a CLI flag
parser — argv glue, 5 lines.

Deliverable: a single PR with the harness, its test, three migrated fixtures,
and the npm script. Report back what migrated cleanly vs. what was awkward.

### Subagent B — Reliability layer core (`src/guard.ts`, types)

Scope:

1. Implement the `ResponseGuard` interface, `GuardContext`, `GuardedResponse`,
   `ClaimFlag`, `GuardStatus` exactly as RELIABILITY.md §2 and §4 define them.
   Module name `src/guard.ts`, ~200 lines per the design's own ceiling. No
   runtime deps.
2. Implement `GroundedResponseGuard` covering D2 (claim-source binding), D3
   (session-fact consistency), D4 (numeric recomputation), D5 (leak check on
   prose). D6 (model-based critique) is telemetry-only — implement a stub
   that returns no flags and a comment naming the upgrade path. Do not invent
   a critic model; this is a hook for a future hook.
3. Implement the §5 fallback ladder as a pure function:
   `runLadder(flags, repairFn, regenerateFn): GuardedResponse`. `repairFn`
   strips flagged spans and returns the remainder; `regenerateFn` is called at
   most once and feeds the flag list back to the model via `ModelInput.context`
   (never via the prompt). Abstain and Escalate are terminal rungs; Escalate
   is gated on `classification >= confidential` and produces a structured
   "awaiting human review" output (no actual review flow — that's M4, already
   built; Escalate produces the request and stops).
4. The leak rung (D5) **skips the ladder**, per the design. A leak is
   withhold + `guard.leak` event. The guard does not return the leaky text
   even with strikethrough.

Ponytail: do not wire this into `AgentSession.run()` yet — that is Subagent
C. The guard module returns `GuardedResponse` and that's it. The integration
is a separate, smaller change.

Deliverable: `src/guard.ts` + `tests/guard.test.ts` covering D2 (verbatim
verification, cited-and-real, cited-and-forged, uncited), D3
(action-claim-mismatch), D4 (numeric-mismatch), D5 (leak), the ladder
(repair → regenerate → abstain → escalate), and the fail-closed path when
the guard itself throws. Report back how many lines landed, whether the §9
~200-line ceiling held, and any D-detection that turned out harder than the
design claimed.

### Subagent C — Reliability wiring (`AgentSession.run`, R1–R3 structural tests)

Scope:

1. Wire `src/guard.ts` into `AgentSession.run()` between `model.complete()`
   and trace return. Replace `SessionTrace.modelText` with the guarded
   response's `text`. Keep `modelText` as the raw model output, sealed into
   evidence per the design (§4). Add `guarded?: GuardedResponse` to
   `SessionTrace`.
2. Append exactly one `guard.verdict` event per run: `{status, flags,
   guardId, originalSealed}` (digests only; the sealed original is in the
   `metadata.sealed` field, exactly like other evidence). Status
   `'withheld'` must use `result: 'error'` so the existing audit-completeness
   ratio (`events` / `expectedDecisions`) still counts.
3. Add three structural tests under
   `security-tests/guard-invariants.test.ts`:
   - **R1 corpus test.** Run the legitimate fixture corpus through the
     scripted model and assert `falseClaimRate` <= the assurance target 7
     ceiling (1%) on this run. If it fails, the corpus is wrong or the guard
     is too tight — pick one and report which.
   - **R2 withhold scan.** Render withheld responses from hostile outputs
     (forged citation, action-claim mismatch, prose leak, poisoned source —
     four cases, one each); assert withheld text contains zero flagged spans
     and zero canary values. Assert the original is sealed into the event
     log.
   - **R3 no-authority structural test.** Enumerate the keys of
     `GuardContext`; assert no key matches `/issue|authoriz|secret|grant/i`.
     Also assert `pdp.ts` does not import from `src/guard.ts` and vice versa
     (a dependency-direction test, mirroring invariant 4).

Ponytail: do not leak `guarded` into the agent's request channel. The agent
sees only `output` from tool execution and the verified `modelText`. Guard
output is a user-facing annotation, not an execution input.

Deliverable: the wiring, the three structural tests, and an updated
`SessionTrace` JSDoc explaining what each field carries.

### Main session responsibilities

- Coordinate the three subagents. The seam is: Subagent A produces a harness
  Subagent C does not need yet; Subagent B produces a pure module Subagent C
  wires in; Subagent C produces the structural tests that retroactively
  verify both A and B.
- Own the docs sweep at the end: SECUCLAIMS Claim 21 (already landed in M6)
  is untouched; add **Claim 22 — Policy rules are unit-testable via the
  harness** and **Claim 23 — Delivered claims are evidence-bound or
  annotated** (only after R1–R3 tests pass). Flip the two ROADMAP rows.
  Update CURRENT_STATE (test count, two new `What M7/M8 closed` sections).
- Own the demo additions: section 14 demonstrates the harness with a tiny
  diff, section 15 demonstrates a guarded response on a forged citation.
- Own the benchmark additions: `policyDiffLatencyMs` (one run of the diff
  primitive) and `guardLatencyP99Ms` (1000 guarded runs of a small input).

## 2. Resource model (M7 only)

No new resource types. The policy harness is a test-time artifact and does
not need an authorization target.

## 3. Actions (M8 only)

No new `KnownAction` entries. Guard verdict events use the existing
`session.*` action namespace (`guard.verdict` is metadata, not a new
action). Escalate rung creates a `CapabilityRequest` via the existing M4
path, which is its own action surface.

## 4. Authorization (no change)

The guard is *read-only* against authorization. The PDP never imports
`src/guard.ts`; the guard never imports `src/pdp.ts`. Subagent C's R3 test
asserts this.

## 5. Wire format — guard.verdict event

```ts
{
  action: 'session.guard',
  result: 'success' | 'error',   // 'error' iff status === 'withheld' (and D5 leaks)
  decision: 'allow',              // always; this is a session-internal event
  metadata: {
    phase: 'guard',
    sessionId: string,
    guardId: string,
    status: 'delivered' | 'flagged' | 'repaired' | 'withheld',
    flags: readonly { claim: string; reason: ClaimFlagReason; sourceId?: string }[],
    citations: readonly { claim: string; sourceId: string }[],
    outputDigest: string | null,  // sha256 of the delivered text
    sealed: Sealed | null,        // the original modelText, sealed per classification
    ladderRung?: 'repair' | 'regenerate' | 'abstain' | 'escalate' | null,
  }
}
```

`Sealed` is the existing shape from `src/seal.ts`. `metadata.sealed` is the
sealed original — the same shape used by other sealed-output events (Claim
13 invariant).

## 6. Sealing + redaction

`metadata.sealed.ciphertext` is AES-256-GCM (same path as Claim 13). The
delivered `text` in `GuardedResponse` is **never** sealed — it is what the
user sees and may be referenced in prose. The sealed original is for
investigators only, behind `evidence.decrypt`.

## 7. Boundary semantics (M8)

- `GuardContext.context` is a `ReadonlyMap<string, string>` keyed by
  `resourceId`. The guard may not mutate it; it is shared with the session's
  ingested data.
- `GuardContext.steps` is the session's own `StepRecord[]`, passed in
  read-only. The guard does not return side effects; the session appends
  the verdict event.
- `GuardContext.canaries` is the existing canary list from `Check` semantics
  (`src/verification.ts`). The guard runs the same leak scan.
- `runLadder` is pure: `flags + repairFn + regenerateFn → GuardedResponse`.
  `repairFn` and `regenerateFn` are passed in by the caller — the guard does
  not own them.
- Fail-closed: any throw inside `ResponseGuard.guard()` produces
  `status: 'withheld'` and a `guard.error` event. Loud denial (H15 spirit).
- D5 leak skips the ladder; no other rung is allowed to deliver text
  containing a canary value.

## 8. Tests

### M7 (policy testing framework) — Subagent A

Minimum cases in `tests/policy-harness.test.ts`:

- `simulate` returns one decision per scenario; deny reasons are preserved
  in the typed output.
- `diffDecisions` surfaces rule-id change, reason change, and effect change
  separately. Adding a no-op rule to an engine produces zero diff entries.
- `loadFixtures` rejects malformed JSON, missing required fields, and
  scenario/resource/action types outside the `domain.ts` vocabulary.
- Three migrated fixtures pass when run against the unmodified baseline
  policy (regression-locked) and produce a non-empty diff when run against
  a one-line overlay.

### M8 (reliability) — Subagent B + C

Minimum cases:

- **D2 cited-and-real:** text cites a `[source:resourceId "span"]` that
  exists in `GuardContext.context`; status `delivered`, no `unverified-claim`
  flag for that span.
- **D2 cited-and-forged:** text cites a span not in any ingested resource;
  status `flagged` or `repaired` or `withheld` per ladder outcome; flag
  reason `citation-forgery`.
- **D2 uncited:** text asserts a factual claim without a citation; flag
  reason `unverified-claim`.
- **D3 action-claim-mismatch:** text says "I deleted X" but no
  `StepRecord` matches; flag reason `action-claim-mismatch`.
- **D4 numeric-mismatch:** text attributes a number to a tool output that
  does not contain that number; flag reason `numeric-mismatch`.
- **D5 leak skip-ladder:** input contains a canary; status `withheld`,
  reason `leak`; the ladder is not consulted.
- **Ladder repair:** flags removable + remainder non-empty → status
  `repaired`; the original is sealed.
- **Ladder regenerate:** flags persist after repair → `regenerateFn` called
  once; second failure → terminal `abstain`.
- **Ladder escalate:** classification `>= confidential`, ladder reaches
  escalate rung → output is the structured awaiting-review message;
  `CapabilityRequest` is queued via the M4 path (test asserts request was
  created, not that it was approved).
- **Fail-closed guard throw:** a guard whose `guard()` throws returns
  `status: 'withheld'` with a `guard.error` event; nothing is delivered.
- **R1 falseClaimRate budget:** run the legitimate fixture corpus; assert
  `flagged + repaired + withheld` / `total` <= 0.01. If it does not hold,
  the test fails — this is a real budget, not aspirational.
- **R2 withhold scan:** withheld outputs from the four hostile cases
  contain zero flagged spans and zero canaries; original is sealed.
- **R3 no-authority:** `Object.keys(new GroundedResponseGuard().guardContext)`
  does not include any `issue|authoriz|secret|grant` key; `grep -l 'from .*guard' src/pdp.ts` returns nothing; `grep -l 'from .*pdp' src/guard.ts` returns nothing.
- **Existing suite green:** 205 prior tests still pass.

## 9. Demo + benchmark

### Demo (`src/cli.ts`)

Add section 14 (M7) and section 15 (M8):

```
14. M7: policy testing framework
   - Loads three migrated fixtures and prints per-fixture pass/fail.
   - Runs the diff primitive against a one-line overlay and prints the
     changed-rule summary.

15. M8: output reliability layer
   - Runs the scripted model against a fixture that quotes a real ingested
     span and prints `delivered` with the citation.
   - Runs it against a fixture that quotes a fabricated span and prints
     `flagged` (or `repaired`/`withheld` per ladder) with the flag list.
   - Runs it against a fixture containing a canary and prints `withheld`.
```

### Benchmark (`src/cli.ts`)

Add two metrics:

- `policyDiffLatencyMs` — one `diffDecisions` call against the three migrated
  fixtures; reported in milliseconds. Expected: sub-millisecond. No p99
  needed; the primitive is called by humans, not in the request hot path.
- `guardLatencyP99Ms` — 1000 guarded runs of a small input (a single
  sentence with one cited real span); reported as p99 in milliseconds.
  Must stay within the decision-latency budget (assurance target 9).

`unauthorizedActionDenialRate` remains 1.0 (attack corpus unchanged).
`auditCompleteness` increases by the number of M8 `guard.verdict` events
generated by the demo and benchmark combined (the demo adds a few; the
benchmark adds 1000).

## 10. Update docs

- **SECURITY_CLAIMS.md** — add **Claim 22 — Policy rules are unit-testable**
  and **Claim 23 — Delivered claims are evidence-bound or annotated**.
  Claim 22 mechanism: `src/policy-testing.ts` + fixture-driven runner; test
  in `tests/policy-harness.test.ts`. Claim 23 mechanism: `ResponseGuard`
  (D2–D5) + fallback ladder; tests in `tests/guard.test.ts` and
  `security-tests/guard-invariants.test.ts` (R1–R3). Threat models: TM-001
  for R3 (guard holds no authority), TM-004 for R2 (withheld leakage).
- **ROADMAP.md** — flip both Stage 1 rows (`Policy testing framework`,
  `Output reliability layer`) to `[DONE]`. Reference the M7 commit and
  Claims 22, 23.
- **CURRENT_STATE.md** — add "What M7 closed" (policy authoring has a
  harness) and "What M8 closed" (text channel is guarded; guard holds no
  authority; poisoned sources are the documented ceiling). Update test
  count.
- **AGENT-SESSION.md** — add a SESSION 8 entry summarizing what the three
  subagents built, what was deferred (D6 critic model is still a hook; the
  `falseClaimRate` number is a first measurement, not a target), and the
  next session's first action.
- **RELIABILITY.md** — status footer changes from "design, not yet built"
  to "implemented; see SESSION 8 entry". Add the link to Claim 23. Do not
  edit §1–§9 — the design is what was built, and any drift between design
  and code should be reflected in the code, not by rewriting the design.

## 11. Constraints

- Zero new runtime dependencies. `node:crypto`, `node:fs` are already used.
- The guard does not change `AuthorizationService`, `Capability`, or the
  policy module. The R3 dependency-direction test enforces this.
- `npm run typecheck && npm test` green; 205 prior tests still pass.
- `falseClaimRate` <= 1% on the legitimate fixture corpus is a real
  acceptance number, not aspirational. If it does not hold, the test fails
  and the milestone does not ship.
- No change to the existing `EventLog.verify()`, `verifyBundle()`, or any
  authorization path. The new events (`guard.verdict`, `guard.error`,
  `guard.leak`) sit beside the existing audit trail.

## 12. Acceptance

- `npm run typecheck && npm test` green; 205 prior tests still pass; new
  M7+M8 tests pass (target: 8 harness tests + 12 guard tests + 3 R1–R3
  structural tests = 23 new tests minimum).
- `npm run demo` runs all 15 sections.
- `npm run benchmark` regenerates `benchmarks/results.json` with the two
  new latency fields.
- `npm run policy:diff` runs without error (even with no overlay — it
  diffs against itself and prints "0 changed").
- CURRENT_STATE, ROADMAP, SECURITY_CLAIMS, AGENT-SESSION, RELIABILITY
  status footer all updated.
- Each subagent reports its deliverable, lines landed, and anything that
  was awkward. Report what was skipped and why.

## 13. Subagent handoff protocol

- Each subagent produces its deliverable on a single commit (or a small
  number — minimize bisect noise).
- Subagent A finishes before Subagent C starts the R3 dependency check
  (cheap but cleaner if A's harness exists first; actually R3 doesn't
  depend on A, so A and B can run in parallel, then C consumes both).
- Subagent B is the critical-path dependency: C cannot wire the guard until
  B's module is on disk.
- Subagent A and B run in parallel; Subagent C runs after both A and B
  land.
- Main session owns the docs sweep and the merge.

## 14. Skip list (do not do in this milestone)

- D6 model-based critique is a stub. Real critic is a future milestone.
- The `Escalate` rung creates a `CapabilityRequest` but does not wait for
  approval. The M4 approval flow handles that — out of scope here.
- Streaming cursor pagination of guard output. Not needed; guard returns
  one `GuardedResponse` per session run.
- HTTP API surface. Out of scope; guard output is consumed by the existing
  in-process trace.
- Any new `KnownAction` entry. Guard verdict events use `session.*` and
  metadata; the action surface is unchanged.

skipped: D6 critic (stub now, real later); Escalate-waits-for-approval (M4
handles it); cursor pagination of guard output (one response per run).
add when: D6 when operator telemetry demands n-sample agreement; Escalate-
wait when the M4 review UX needs synchronous blocking; pagination when
guards run mid-session on partial responses.
