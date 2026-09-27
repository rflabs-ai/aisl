# M9 — Guard follow-ups + drift closure

Begin M9. This milestone closes the items SESSION 8 deferred ("M8 follow-ups")
plus the drift the M7/M8 audit found in the prompt-vs-code diff. It is a
**follow-up + repair milestone**, not a new Stage 1 row.

Read `PROJECT_CONTEXT.md`, `ARCHITECTURE.md` (§4–§7), `SECURITY_CLAIMS.md`
(Claims 21, 22, 23), `DECISIONS.md` (ADR-001, ADR-014), `ROADMAP.md` (Stage 1
row "Output reliability layer" — keep `[DONE]`), `CURRENT_STATE.md` (test
count + "What M8 closed" — the M9 results land in a new "What M9 closed"
section), `AGENT-SESSION.md` (SESSION 8 + new SESSION 10 entry — SESSION 9 is M6.1's
audit-drift entry),
`RELIABILITY.md` (§5 ladder + §6 R1–R3, §7 boundary semantics, §8 metrics —
add `falseClaimRate` to the metrics list), `src/guard.ts`, `src/runtime.ts`,
`src/scenario.ts`, `src/capability-request.ts`, `src/seal.ts`,
`tests/guard.test.ts`, `security-tests/guard-invariants.test.ts`,
`security-fixtures/`, `security-attacks/`.

Goal: SESSION 8 deferred three things (per-session classification,
second-pass guard, D6 hook) and the audit found six drift items. This
milestone ships them.

- **The Escalate rung wires into M4.** Today the Escalate rung produces the
  awaiting-review text and stops. M4 (`CapabilityRequestService`) is built
  and tested; the guard should call it. A `CapabilityRequest` is queued,
  the awaiting-review text names the request id, the event log gets both a
  `session.guard` and a `capability.request` event, and the approval flow
  (out of band, M4's existing surface) gates delivery.
- **Per-session classification derivation.** Today `src/runtime.ts:251`
  hardcodes `classification: 'public'` in the `GuardContext`. The
  classification should be derived from the session's visible ceiling —
  the highest (most sensitive) of the principal's capability
  `maxClassification` fields, the ingested resources, and the requested
  resources. The highest is the conservative choice. This makes the
  Escalate rung reachable in real workloads.
- **Second-pass guard after `steps` computed.** Today's guard runs once,
  before execution, with `steps: []`. Re-running the same detectors on the
  same model text with the executed `steps` populated can change the verdict
  — step data can clear an `action-claim-mismatch` or a numeric flag that the
  empty-steps pass raised (and, in principle, add a `numeric-mismatch`). The
  second pass is a robustness gate; it must NOT double-emit `session.guard`
  events. Add a second event only when the verdict changes.
- **Drift fixes from the audit.** The M7 prompt's wire-format spec said
  `metadata.sealed: Sealed | null` (raw object). The implementation
  JSON-stringifies it. `ladderRung` is hardcoded `null` instead of
  recording which rung fired. D4 flags a bare number both
  `unverified-claim` and `numeric-mismatch` (one or the other). The
  `regenerateFn` rung is exercised in code but never tested.
  `falseClaimRate` (the R1 measurement) is not surfaced in
  `benchmarks/results.json`.
- **D6 critic stub becomes a real hook.** Today `D6_STUB = true` and
  the detector returns no flags. The interface stays empty, but the
  `GroundedResponseGuard.guard()` method now accepts an optional
  `criticFn?: (modelText: string) => readonly ClaimFlag[]` parameter
  (default = no critic). This is a hook for a future milestone; the
  tests assert the hook exists, that no flags appear when no critic is
  supplied, and that the critic's flags merge into the existing
  `flags` list before the ladder runs.

These five items ship together because they share the same surface
(`src/guard.ts` + `src/runtime.ts` + tests + docs). One PR.

## 1. Subagent allocation

Use subagents for these defined tasks, in this order. The main session stays
in charge of the seam between them.

### Subagent A — Escalate-wires-to-M4 (`src/guard.ts` + `src/runtime.ts`)

Scope:

1. Add to `GuardContext` (`src/guard.ts:40`):
   - `readonly principal: Principal;` — the session principal. The guard
     needs it to decide whether escalation is allowed (agents only) and to
     pass the requester to `submit()`. `GuardContext` carries no principal
     today; populate it in `src/runtime.ts`.
   - `readonly capabilityRequestService?: CapabilityRequestService;` — the
     guard receives the service, it does not OWN it. Import the type only
     (`import { type CapabilityRequestService } from './capability-request.ts'`)
     so `src/guard.ts` keeps no runtime dependency on the authority plane
     and the R3 dependency check holds.
2. **Keep `runLadder` pure.** It returns which rung fired; it does NOT
   submit anything. `GroundedResponseGuard.guard()` performs the Escalate
   side effect after `runLadder` returns `ladderRung === 'escalate'`.
3. When the Escalate rung fires AND `capabilityRequestService` is provided
   AND `ctx.principal.kind === 'agent'` (users do not escalate), submit a
   `CapabilityRequest` using the real positional signature
   (`src/capability-request.ts:67`):
   ```ts
   const request = service.submit(
     ctx.principal,          // the agent (requester)
     ctx.sessionId,
     ['guard.review'],       // synthetic resource id (metadata, not a KnownAction)
     ['guard.review'],       // synthetic action; Action includes `string & {}`
     ctx.classification,
     `Guard Escalate: ${flags.map((f) => f.reason).join(', ')}`,
   );
   ```
   `submit()` already appends the `capability.request` event itself
   (`src/capability-request.ts:90`). Do NOT append a second one — the guard
   has no `EventLog` handle by design (RELIABILITY.md §2, R3), and the
   session's `session.guard` event carries the `requestId`.
4. The returned `request.id` is included in the awaiting-review text (e.g.
   `"This response is awaiting human review (escalation required). Review
   request: <id>."`) and in the `session.guard` event metadata as
   `requestId`. `runLadder` builds `escalateText` before the id exists, so
   `guard()` overrides `text` after submit (build a new object; do not
   mutate the readonly response).
5. If no `capabilityRequestService` is provided (or the principal is not an
   agent), the Escalate rung falls back to today's behavior (text only, no
   queued request, no `requestId` in metadata). This keeps the unit tests
   simple and lets deployments without M4 still use the guard.
6. **The guard does NOT wait for approval.** Escalation produces the request
   and returns the awaiting-review text. M4's existing approval flow handles
   the rest out of band.
7. **The Escalate rung fires only when `classification >= confidential`**.
   Today this gate is in `runLadder`. Keep it. With per-session
   classification (Subagent B's deliverable), the gate becomes
   meaningful in real workloads.
8. Tests in `tests/guard.test.ts`:
   - "escalate queues a CapabilityRequest when the service is provided"
   - "escalate falls back to text-only when no service"
   - "escalate does NOT queue a CapabilityRequest when classification < confidential"
   - "the awaiting-review text names the request id"

Adding the required `GuardContext.principal` field breaks every existing
context literal: update the builders in `tests/guard.test.ts` (`ctx()`),
`security-tests/guard-invariants.test.ts` (`sampleGuardContext()`), and the
`guardLatencyP99Ms` `smallInput()` in `src/cli.ts`. `src/runtime.ts` sets
it from `this.cfg.principal`.

Ponytail: do not invent a new action surface. Use the synthetic
`'guard.review'` string for both the resource id and the requested action;
this is metadata, not a new `KnownAction`. `CapabilityRequest.requestedActions`
is typed `readonly Action[]`, and `Action` includes `string & {}`.

Deliverable: the Escalate rung wired into M4 + tests.

### Subagent B — Classification derivation + second-pass guard (`src/runtime.ts`)

Scope:

1. **Classification derivation.** Today `src/runtime.ts:251` hardcodes
   `classification: 'public'`. Change it to derive from the session's
   resources:
   - Compute `maxClassification` as the highest (most sensitive) of:
     - the principal's capability `maxClassification` fields — the ceiling
       the session could legitimately reach; the highest is the conservative
       choice,
     - the highest classification among resources the session
       ingested (from `cfg.content` keys; each key is a resourceId;
       look up the resource in `cfg.registry`),
     - the highest classification among resources requested by
       `modelOutput.requests` (which is available after
       `model.complete()` but before `steps` are computed).
   - If no resources are visible, default to `'public'` (today's behavior).
2. **Second-pass guard.** After `steps` are computed (after line 254 in
   the current `src/runtime.ts`), run the guard a SECOND time with the
   updated `ctx.steps`. If the second pass produces a different verdict
   than the first, append ONE more `session.guard` event with
   `metadata.phase === 'guard-second-pass'`. If the verdict is the same
   (e.g., both delivered), no extra event.
3. The second pass uses the SAME `GuardedResponseGuard` instance and the
   SAME `modelOutput.text`, with `ctx.steps` populated from the executed
   steps (`steps` is assigned at `src/runtime.ts:254`, after the first
   pass). Its `originalSealed` is the sealed model text for that pass.
4. Tests in `tests/runtime-second-pass.test.ts`:
   - "first and second pass agree → exactly one session.guard event"
   - "second pass clears a first-pass action-claim-mismatch" (model text
     "I deleted X"; the delete executes; first pass with `steps: []` flags
     it, second pass with the executed delete does not)
   - "classification derives from ingested resources"
   - "classification defaults to 'public' when nothing is visible"

Ponytail: do not change the SessionTrace shape. Add
`session.guard` events; the second pass is metadata, not a new field
on the trace.

Deliverable: classification derivation + second-pass guard + tests.

### Subagent C — Drift fixes (`src/guard.ts` + `src/runtime.ts` + tests + docs)

Scope:

1. **`sealed` shape.** Change the wire format so `metadata.sealed` is the
   raw `Sealed` object (not JSON-stringified). Update
   `src/guard.ts` to return `originalSealed: Sealed | null` (not
   `string | null`). Update `src/runtime.ts` to pass the object
   directly. Update the `runLadder` helper to use a `Sealed`-returning
   `seal()` call (the existing `seal()` returns `Sealed`; just stop
   stringifying it).
2. **`ladderRung` tracking.** Add `readonly ladderRung: 'repair' |
   'regenerate' | 'abstain' | 'escalate' | null` to `GuardedResponse` as a
   new field (do NOT change `runLadder`'s return shape — `tests/guard.test.ts`
   calls it directly and reads `.status`). Map: delivered → `null`; repair
   success → `'repair'`; regenerate success → `'regenerate'`; withheld with
   `classification >= confidential` → `'escalate'`; other withheld →
   `'abstain'`; D5 leak withhold → `null` (the ladder is skipped). Update
   `src/runtime.ts` to thread the rung into `metadata.ladderRung`.
3. **D4 dedup.** When a bare number is flagged, set EITHER
   `unverified-claim` (D2, when no steps) OR `numeric-mismatch` (D4,
   when there are steps with output the number isn't in) — never both.
   The current code adds both; remove the duplicate.
4. **`regenerateFn` rung test.** Add a test that proves the rung fires
   once when repair fails: pass a `regenerateFn` that returns clean
   text on first call; assert `status === 'repaired'`, original sealed,
   no re-run. Add another test: pass a `regenerateFn` that returns
   flagged text; assert status `withheld`, original sealed, ladder
   did not retry the regen.
5. **`falseClaimRate` in benchmark output.** Extend
   `src/cli.ts:benchmark()` to compute `falseClaimRate` from the R1
   measurement: run the legitimate fixture corpus (`LEG-001` and
   `LEG-002`) through the guard and count non-delivered. Surface
   `falseClaimRate` and `totalLegitimateResponses` in the `metrics`
   object under `evidence.falseClaimRate`. Document the metric in
   `RELIABILITY.md` §8 and `benchmarks/results.json`.
6. **Tests** covering the above, in `tests/guard.test.ts` or
   `tests/runtime-drift-fixes.test.ts`.

Decision (resolved): `GuardedResponse.originalSealed` becomes
`Sealed | null`. Update the type in `src/guard.ts`, both emitters in
`runLadder`/`guard()`, and the `src/runtime.ts` `metadata.sealed` write.
This is a contract change, not a design rewrite — correct the §4
`GuardedResponse` snippet in `RELIABILITY.md` accordingly (§10).

Deliverable: drift fixes + tests + benchmark output + docs update.

### Main session responsibilities

- Coordinate the three subagents. Subagent A's work depends on Subagent
  B's classification derivation (the Escalate gate becomes meaningful
  only when classification derives from real data). Subagent C is
  independent.
- Own the docs sweep at the end:
  - **SECURITY_CLAIMS.md** — update Claim 23's mechanism to mention the
    M4 wiring (Escalate queues a `CapabilityRequest`), the per-session
    classification derivation, the second-pass guard, and the wire-format
    fixes (`metadata.sealed` is a raw `Sealed` object; `metadata.ladderRung`
    records the rung that fired). Update the Known limitations list: remove
    "per-session classification is a future enhancement", remove
    "second-pass guard is a follow-up". Update Evidence to reference the
    new tests.
  - **CURRENT_STATE.md** — add "What M9 closed" section (M8 follow-ups
    + drift closure + per-session classification + second-pass guard
    + Escalate-to-M4). Update test count. Those items were never on the
    known-vulnerabilities list, so there is nothing to strike there.
  - **ROADMAP.md** — Stage 1 row "Output reliability layer" already
    `[DONE]`; add a parenthetical to the status: "(M9: Escalate wired
    to M4, classification derived per session, second-pass guard)".
  - **AGENT-SESSION.md** — add SESSION 10 entry summarizing what the
    three subagents built.
  - **RELIABILITY.md** — status footer unchanged (still implemented);
    §8 metric list adds `falseClaimRate` to the benchmark description.
- Own the demo additions: section 16 demonstrates the Escalate-to-M4
  wiring (submit a request, show the request id in the awaiting-review
  text, show both `session.guard` and `capability.request` events).
- Own the benchmark additions: add `falseClaimRate` field to the
  metrics object (covered by Subagent C's deliverable; just verify).

## 2. Resource model (M9 only)

No new resource types. The synthetic `guard.review` resource id used
in the Escalate CapabilityRequest is metadata, not a registered
resource. It satisfies the existing M4 path which doesn't require the
resource to be in the registry (verify against
`src/capability-request.ts`).

## 3. Actions (M9 only)

No new `KnownAction` entries. `CapabilityRequest.requestedActions` is typed
as `readonly Action[]`, and `Action` includes `string & {}`. We use the
synthetic string `'guard.review'` for both the resource id and the action;
this does not require a `KnownAction` change.

## 4. Authorization (no change)

The guard still holds no authority. Adding the capability-request call
uses the existing `CapabilityRequestService.submit()` API; submitting a
request is intent, not authority, and it does not widen the guard's reach
(the service still enforces user-kind reviewer refusal and self-approval
refusal).

## 5. Wire format — second-pass guard event

```ts
{
  action: 'session.guard',
  result: 'success' | 'error',
  decision: 'allow',
  metadata: {
    phase: 'guard' | 'guard-second-pass',  // NEW: distinguishes the two
    sessionId: string,
    guardId: string,
    status: GuardStatus,
    flags: readonly ClaimFlag[],
    citations: readonly { claim: string; sourceId: string }[],
    outputDigest: string | null,
    sealed: Sealed | null,                  // RAW Sealed object (drift fix)
    ladderRung: 'repair' | 'regenerate' | 'abstain' | 'escalate' | null,
    requestId?: string,                     // NEW: present when Escalate queued an M4 request
  }
}
```

`Sealed` is the existing shape from `src/seal.ts` — invariant 13 path.
The drift fix is the `sealed: Sealed | null` change: investigators
reading the event log can now directly see `.ciphertext`, `.keyId`,
`.iv`, `.tag` without a JSON-parse step.

## 6. Sealing + redaction

`metadata.sealed.ciphertext` remains AES-256-GCM (same path as Claim
13). The delivered `text` is never sealed. Each `session.guard` event
seals the model text evaluated for that pass — the same `modelOutput.text`
both times; the second pass differs only in the populated `steps`.

## 7. Boundary semantics (M9)

- `GuardContext.context` remains a `ReadonlyMap<string, string>` keyed
  by `resourceId`.
- `GuardContext.steps` is populated with `[]` on the first pass and the
  executed `StepRecord[]` on the second pass.
- `GuardContext.principal: Principal` — the session principal, used to gate
  escalation to agents and as the `submit()` requester.
- `GuardContext.capabilityRequestService?: CapabilityRequestService`
  — when provided, the Escalate rung uses it. The guard does not own
  the service. The service is still injected from the session config.
- The guard does not import `src/pdp.ts` (R3 holds).
- Per-session classification derivation uses `cfg.registry.get()` —
  read-only, no mutation.

## 8. Tests

### Escalate-to-M4 (`tests/guard.test.ts`)

- Escalate fires + service provided → `CapabilityRequest` is submitted;
  `metadata.requestId` is set on the session.guard event; the
  awaiting-review text contains the request id.
- Escalate fires + service is null → fallback to text-only behavior
  (no request, no requestId in metadata).
- Escalate does NOT fire when classification is `'public'` or `'internal'`,
  regardless of whether a service is provided.
- The CapabilityRequest's `principalId` is the session's agent,
  `requestedActions` includes `'guard.review'`, and `justification` lists
  the flag reasons.

### Classification derivation (`tests/runtime-second-pass.test.ts`)

- Session with no ingested data → classification = `'public'`.
- Session with `LEG-001` content → classification = `'internal'`.
- Session with a confidential resource capability → classification =
  `'confidential'`.
- Classification flows into the Escalate gate: a hostile output +
  confidential classification + service provided → Escalate fires.

### Second-pass guard (`tests/runtime-second-pass.test.ts`)

- Same verdict across both passes → exactly one `session.guard` event
  (no `guard-second-pass` event). This is the common case.
- Verdict changes between passes → exactly one extra `session.guard`
  event with `metadata.phase === 'guard-second-pass'`, sealing the
  second-pass text. Construct a fixture where the post-`steps` context
  flips the verdict (e.g., first pass sees no executed steps and delivers,
  second pass sees steps that contradict the text), or call the per-pass
  helper directly.
- Skip: contrived tests that contradict themselves. Keep the
  second-pass test surface small.

### Drift fixes (`tests/guard.test.ts` + `tests/runtime-drift-fixes.test.ts`)

- `metadata.sealed` is a `Sealed` object, not a stringified one. Test
  reads back the event log and asserts `typeof sealed === 'object'`
  and `sealed.ciphertext` is a string.
- `metadata.ladderRung` is `'repair'` after a successful repair,
  `'abstain'` after abstain, `'escalate'` after Escalate, `null` after
  delivered.
- D4: a bare number with no steps → only `unverified-claim`, not
  `numeric-mismatch`. A bare number with steps that don't contain it
  → only `numeric-mismatch`, not `unverified-claim`. (Current code
  flags both; the dedup fix makes them exclusive.)
- `regenerateFn` rung: pass a `regenerateFn` that returns clean text
  → `status: 'repaired'`, original sealed. Pass one that returns
  flagged text → `status: 'withheld'`, original sealed, no second
  regen.

### Benchmark (`src/cli.ts`)

- `falseClaimRate` field present in `benchmarks/results.json` under
  `evidence.falseClaimRate`. Computed from running the legitimate
  fixture corpus through the guard.

### Existing suite green

- 252 prior tests still pass (M6.1 added 9 audit-drift tests). New tests
  ≥ 12 (estimated: 4 Escalate + 4 classification + 4 second-pass + 4 drift
  = ~16). Total target: ≥264 tests.

## 9. Demo + benchmark

### Demo (`src/cli.ts`)

Add section 16 (M9):

```
16. M9: guard follow-ups
   - Runs a hostile output against a confidential-classified session and
     prints the awaiting-review text with the request id.
   - Prints both session.guard and capability.request events for the
     escalation.
```

### Benchmark (`src/cli.ts`)

Add (Subagent C):

- `falseClaimRate` — fraction of legitimate corpus responses that were
  flagged/repaired/withheld. Target: ≤ 0.01 (per RELIABILITY.md §8).
  Reported in `benchmarks/results.json` under `evidence.falseClaimRate`.

Existing fields unchanged:
- `unauthorizedActionDenialRate` remains 1.0 (attack corpus unchanged).
- `auditCompleteness` is `decisionEvents / expectedDecisions`. Extra
  `session.guard` events do NOT move it (`metadata.phase` is `'guard'`, not
  `'decision'`). If `falseClaimRate` is measured by running sessions (which
  append decision events), add that count to `expectedDecisions`
  (`src/cli.ts:285`); measuring via direct `guard.guard()` calls (like
  `guardLatencyP99Ms`) leaves the accounting unchanged.

## 10. Update docs

- **SECURITY_CLAIMS.md** — Claim 23 mechanism: add the M4 wiring
  (Escalate queues `CapabilityRequest`), the per-session classification
  derivation, the second-pass guard, and the wire-format fixes
  (`metadata.sealed` is a raw `Sealed` object; `metadata.ladderRung`
  records the rung). Update Known limitations to remove the
  deferred-item limitations (per-session classification, second-pass
  guard). Evidence: add the new test files.
- **CURRENT_STATE.md** — add "What M9 closed" section. Update test
  count. Those items were never on the known-vulnerabilities list, so
  there is nothing to strike there.
- **ROADMAP.md** — Stage 1 row "Output reliability layer" status
  becomes: `[DONE]` (M7/M8 baseline; M9: Escalate wired to M4,
  classification derived per session, second-pass guard).
- **AGENT-SESSION.md** — add SESSION 10 entry.
- **RELIABILITY.md** — status footer unchanged; §8 metric list adds
  `falseClaimRate`. Correct the §4 `GuardedResponse` type snippet for the
  two wire-format fixes (`originalSealed: Sealed | null`, add
  `ladderRung`) — a contract, not design prose. Leave §1–§3 and §5–§9
  unchanged.

## 11. Constraints

- Zero new runtime dependencies.
- The guard does not change `AuthorizationService`, `Capability`, or
  the policy module. R3 dependency test continues to hold.
- The second-pass guard emits ONE additional `session.guard` event
  ONLY when the verdict changes. Same-verdict second passes emit
  nothing.
- The Escalate rung fires only when `classification >= confidential`
  AND `capabilityRequestService` is provided. Both conditions are
  required.
- `npm run typecheck && npm test` green; 252 prior tests still pass.
- `auditCompleteness` does not decrease.

## 12. Acceptance

- `npm run typecheck && npm test` green; 252 prior tests still pass;
  new M9 tests pass (target: 12+ new).
- `npm run demo` runs all 16 sections.
- `npm run benchmark` regenerates `benchmarks/results.json` with
  `falseClaimRate` and the existing two latency fields.
- The Escalate rung, when fired, appends both `session.guard` (with
  `metadata.requestId`) and `capability.request` events to the log.
- Per-session classification derives from the session's visible
  resources and capabilities; defaults to `'public'` when nothing is
  visible.
- Second-pass guard emits a `session.guard` event with
  `metadata.phase === 'guard-second-pass'` only when the verdict
  changes between passes.
- D4 dedup verified by test (a number with no steps gets
  `unverified-claim`; with steps, `numeric-mismatch`; never both).
- `regenerateFn` rung tested (success + abstain-on-second-failure).
- `metadata.sealed` is a raw `Sealed` object (not JSON-stringified).
- `metadata.ladderRung` records the rung that fired.
- CURRENT_STATE, ROADMAP, SECURITY_CLAIMS, AGENT-SESSION all updated.

## 13. Subagent handoff protocol

- Subagents A, B, C can run in parallel — A's wiring depends on B's
  classification derivation only at the test boundary, not at the
  code boundary; C is independent.
- Subagent C depends on the test file `tests/guard.test.ts` not
  having been moved by A or B; coordinate file ownership.
- Main session owns the merge and the docs sweep.

## 14. Skip list (do not do in this milestone)

- Streaming guard output (one response per run; not needed).
- D6 critic model implementation (the stub stays; the interface
  becomes callable with an optional `criticFn` parameter, but no
  real critic is wired up).
- New `KnownAction` entries (use the synthetic `guard.review`
  string).
- HTTP API surface (out of scope; the guard output is consumed by
  the existing in-process trace).
- Configuration management (versioned, reviewable, attributable
  policy — ROADMAP Stage 1; not in M9).

skipped: D6 real critic (stub with optional hook); synthetic
guard.review action (avoids `KnownAction` change); wait-for-approval
in Escalate (M4 approval flow is out of band, per the M8 prompt's
existing design).
add when: D6 when operator telemetry demands n-sample agreement;
guard.review as a real `KnownAction` if the request ever needs PDP
authorization (today it doesn't, the M4 service handles that);
wait-for-approval when the M4 review UX needs synchronous blocking.

---

## Audit notes (this milestone's reason for being)

A drift audit of M7/M8 found six items. M9 ships them.

1. **Escalate did not queue a `CapabilityRequest`** — the M7 prompt §8
   said "CapabilityRequest is queued via the M4 path" but §14 deferred
   the wiring; M4 was already built, so the deferral is no longer
   needed. **M9 Subagent A.**
2. **`metadata.sealed` was JSON-stringified** — the M7 prompt §5 said
   `Sealed | null` (raw object). Investigators reading the event log
   couldn't directly see `.ciphertext`. **M9 Subagent C.**
3. **`metadata.ladderRung` was always `null`** — the M7 prompt §5 said
   it should record the rung that fired. **M9 Subagent C.**
4. **D4 produced duplicate flags** — a bare number flagged both
   `unverified-claim` and `numeric-mismatch`. **M9 Subagent C.**
5. **`regenerateFn` rung was untested** — the rung existed in code
   but no test exercised it. **M9 Subagent C.**
6. **`falseClaimRate` was not surfaced in the benchmark output** —
   the metric was measured in the R1 test but not exported to
   `benchmarks/results.json`. **M9 Subagent C.**

Plus the three SESSION 8 deferred items:

7. **Per-session classification derivation** (hardcoded `'public'`).
   **M9 Subagent B.**
8. **Second-pass guard** after `steps` computed (catches post-execution
   discrepancies). **M9 Subagent B.**
9. **D6 critic hook** (optional `criticFn` parameter, no real critic).
   **M9 Subagent C** as a small addition (add the parameter to
   `GroundedResponseGuard.guard()`, default null, single test that
   confirms the hook works when supplied).