# RELIABILITY LAYER — output guardrails (implemented; see SESSION 8)

Status: **implemented**. Code lives in `src/guard.ts` (D2–D5, D6 hook, ladder,
sealed originals) and is wired into `AgentSession.run()` between
`model.complete()` and trace return. Tests: `tests/guard.test.ts` (33 cases),
`security-tests/guard-invariants.test.ts` (R1–R3 structural, 8 cases),
`tests/runtime-second-pass.test.ts` (8 cases) and `tests/runtime-drift-fixes.test.ts`
(3 cases). Claims: Claim 22 (M7 harness, policy testing) and Claim 23 (M7/M8
delivered claims are evidence-bound or annotated). M9 closed the M8 follow-ups
and the M7/M8 drift audit: the Escalate rung queues a real `CapabilityRequest`
through M4 (`src/capability-request.ts`), classification is derived per session
from capability ceilings + visible/requested resources (`deriveClassification`),
a post-execution second pass re-runs the guard on the executed `steps` and emits
one extra `session.guard` event only when the verdict changes, and the wire
format carries a raw `Sealed` object plus the `ladderRung` that fired. The D6
model-based critique has a callable hook but remains telemetry only; the upgrade
path is documented inline. The poisoned-source ceiling is documented as TM-002
residual (a poisoned source yields a well-cited lie — D2 cannot detect it). For
the implementation history see SESSION 8 (M8) and SESSION 10 (M9) in
`AGENT-SESSION.md`.

## 0. The hole this closes

The action channel is guarded: every `ActionRequest` funnels through
`AgentSession.attempt` -> PDP -> sandbox -> verification. The **text channel is
not**. `AgentSession.run()` returns `SessionTrace.modelText`
(`src/runtime.ts:258`) — raw model prose, delivered to the user with zero
checks. Today a model can:

- assert facts with no basis in the ingested context (hallucination),
- contradict what its own tool executions actually did ("I deleted X" — nothing
  was deleted),
- quote sources it was never given (citation forgery),
- leak a canary or secret value into prose (the leak check only runs on tool
  output, not on model text).

Authorization cannot fix this. The PDP constrains what an agent *does*; it says
nothing about what an agent *says*. This layer guards the saying.

## 1. What this layer is — and is not

**It is a quality control, not a security boundary.** The same lesson as
ADR-011 (injection detector demoted to telemetry) applies with full force: a
hallucination detector can be bypassed, and a smooth liar defeats every
probabilistic check. The authority boundary (data != authority, capabilities,
PDP) is what protects the system. This layer protects the *user's trust in the
prose*. Its output is annotation, repair, and withholding — never authority,
and the PDP must never read it.

**It does not claim zero hallucinations.** ROADMAP IMPOSSIBLE+ already records
that generative models hallucinate by construction, and names the engineering
approximation: *require evidence for consequential claims*. This design
operationalizes that row. The claim we will be able to make is narrow and
testable: **every delivered consequential claim is bound to a verified source
span, or the response is flagged, repaired, or withheld.**

## 2. Placement

```text
model.complete() -> ModelOutput { text, requests }
                          |              |
                          |              +--> AgentSession.attempt -> PDP   (exists, unchanged)
                          v
                   ResponseGuard.guard(text, GuardContext)                   (NEW)
                          |
                          v
                   GuardedResponse  -----> user
                          |
                          +--> guard verdict event appended to EventLog
                               (sealed per classification, like all output)
```

One seam, one trivial implementation first — the house pattern
(ARCHITECTURE.md §7):

```ts
export interface GuardContext {
  readonly sessionId: string;
  readonly modelText: string;
  readonly context: ReadonlyMap<string, string>;  // resourceId -> ingested content
  readonly steps: readonly StepRecord[];          // what actually executed
  readonly canaries: readonly string[];           // secret/canary values
  readonly classification: Classification;        // derived per session (M9)
  readonly principal: Principal;                  // gates Escalate to agents (M9)
  readonly capabilityRequestService?: CapabilityRequestService;  // M4 wiring (M9)
}

export interface ResponseGuard {
  readonly id: string;
  guard(ctx: GuardContext): GuardedResponse;
}
```

The guard runs inside `AgentSession.run()` after `model.complete()` and before
the trace is returned. `SessionTrace.modelText` is replaced by the guarded
response. The guard receives a `GuardContext` and nothing else — no
authorization handle, no event-log handle, no model handle. Verdicts are
returned to the session, and the *session* appends them to the log. A
structural test asserts the context exposes no `issue|authoriz|secret|grant`
keys, mirroring invariant 4.

## 3. Detection strategies

Deterministic checks first; probabilistic checks are telemetry-grade and never
sufficient alone. Each check produces a `ClaimFlag`; the formatter (§4) and the
fallback ladder (§5) consume flags, not raw text.

### D1 — Structural validation (exists)

`parseModelOutput` whitelist (`src/model.ts:42`). Unknown keys dropped, output
carries intent only. Listed for completeness; already a control.

### D2 — Claim-source binding (the core check)

Consequential claims must carry evidence. The output contract asks the model
to cite consequential claims as `[source:resourceId "quoted span"]`. The guard
verifies, deterministically:

1. the cited `resourceId` was actually ingested this session (`GuardContext.context`),
2. the quoted span appears **verbatim** in that resource's content,
3. an uncited consequential claim is flagged `unverified-claim`.

Consequentiality is declared per deployment (numeric claims, claims about
people, claims driving a decision) — ponytail: v1 treats *every* factual
assertion as consequential; upgrade path is a claim classifier when false
positive rate demands it.

This is the strongest check because it is not a detector — it is an evidence
requirement. A model cannot "beat" it except by quoting real source material.
Its ceiling: it verifies *support*, not *truth* — a poisoned source document
yields a well-cited lie. That ceiling is TM-002's residual risk (semantic
manipulation inside authorized scope), not a new one.

### D3 — Session-fact consistency

The text is compared against the session's own execution records
(`GuardContext.steps`). Claims of the form "I did X to Y" are checked against
`StepRecord`s: no matching executed step → flag `action-claim-mismatch`.
Deterministic, and catches the most operationally dangerous hallucination
class: false reports of side effects.

### D4 — Numeric recomputation

Numbers in the text attributed to tool output are compared against the actual
(structured) tool outputs in `steps[].output`. Mismatch → flag
`numeric-mismatch`. Deterministic where tool output is structured; skipped
silently where it is not. ponytail: v1 handles exact-value matching only; unit
normalization is the upgrade path.

### D5 — Leak check on prose

`secretLeakCheck` (`src/verification.ts:66`) already exists for tool output.
The guard runs the same check over `modelText` against the session's canary
and secret values. A leak is not a flag — it is an immediate withhold (§5).

### D6 — Model-based critique (telemetry only)

A second model pass (critic prompt, or n-sample agreement) may add flags.
Explicitly **not a control**: correlated failures and shared blind spots mean
a critic from the same model family proves nothing. Its flags are recorded as
telemetry and can trigger the fallback ladder, but a clean critic pass never
upgrades a `unverified-claim` flag to verified. Only D2 does that.

## 4. Response formatting

The user never receives raw model text. They receive a `GuardedResponse`:

```ts
export type GuardStatus = 'delivered' | 'flagged' | 'repaired' | 'withheld';

export interface ClaimFlag {
  readonly claim: string;          // the offending span
  readonly reason: 'unverified-claim' | 'citation-forgery' | 'action-claim-mismatch'
                 | 'numeric-mismatch' | 'leak' | 'critic-flag';
  readonly sourceId?: string;      // cited resource, when present
}

export interface GuardedResponse {
  readonly status: GuardStatus;
  readonly text: string;                       // what the user sees
  readonly flags: readonly ClaimFlag[];
  readonly citations: readonly { claim: string; sourceId: string }[];
  readonly guardId: string;
  readonly originalSealed: Sealed | null;      // sealed original, evidence only
  readonly ladderRung: 'repair' | 'regenerate' | 'abstain' | 'escalate' | null;
}
```

Rules:

- **No silent edits.** A `repaired` response marks every removal inline
  (`[removed: unverified claim]`) and the original is sealed into the evidence
  store (AES-256-GCM per classification, `src/seal.ts`) — readable only with
  an `evidence.decrypt` capability, same as all output.
- **Citations are machine-readable** so the REST API surface (ROADMAP Stage 0)
  can render provenance chips without parsing prose.
- **`withheld` text is a fixed safe completion** (§5) plus the flag list. It
  never contains the flagged claim. Structural test: withheld text contains no
  flagged span and no canary value.
- Every guard run appends exactly one `guard.verdict` event: status, flags,
  guard id, digests — sealed, hash-chained, signed like every other event.

## 5. Fallback path

A bounded ladder. Rungs are tried in order; each rung is attempted at most
once; the ladder always terminates.

```text
flags found
   |
   v
1. REPAIR    strip flagged claims; does the remainder still answer the task?
   |            (v1 heuristic: non-empty after stripping; ponytail: task-
   |             relevance classifier is the upgrade path)
   v  no
2. REGENERATE  one retry; the flag list is fed back to the model as data
   |            (never as instructions — ModelInput.context, not prompt)
   v  still flagged
3. ABSTAIN   deliver the safe completion: "I could not verify this answer."
   |            + flag list. This is the default terminal state.
   v  if classification >= confidential
4. ESCALATE  route the flagged response to human review via the M4
             capability-request flow; nothing is delivered until a `user`
             principal approves. Self-approval remains structurally refused.
```

**Fail-closed, same doctrine as the PDP:** if the guard itself throws, the
response is withheld and a `guard.error` event is appended. A broken guard
delivers nothing — H15's loud-denial requirement applies: the withhold event
carries a distinct reason, not a silent absence.

**D5 leaks skip the ladder.** A response containing a canary or secret value
goes straight to withhold + `guard.leak` event. There is no repair rung for a
leak; strikethrough is not a secrecy control.

## 6. Claims this design will support (once tested)

Drafted in SECURITY_CLAIMS.md structure; added to that file only when the
tests exist.

**Claim R1 — Delivered claims are evidence-bound.**
Every response with status `delivered` contains no consequential claim lacking
a verified source span; every other response is marked `flagged`, `repaired`,
or `withheld` with the reason recorded.
*Mechanism:* D2 verbatim-span verification + the §5 ladder.
*Test:* corpus of grounded, ungrounded, forged-citation, and poisoned-source
outputs; assert status and flags per case.
*Known limitation:* verifies support, not truth; poisoned sources yield
well-cited lies. Uncited-but-true claims are flagged (false positives) — the
false-denial budget (assurance target 7) applies.
*Residual risk:* claim-extraction misses a consequential claim; classifier
upgrade path noted in D2.

**Claim R2 — Withheld responses disclose nothing.**
A `withheld` response contains no flagged span and no registered canary or
secret value, and the original is sealed in the evidence store.
*Test:* structural — render withheld responses from hostile outputs, scan for
flagged spans and canaries; assert zero occurrences.

**Claim R3 — The guard holds no authority.**
`GuardContext` exposes no issuance, authorization, or secret handle; guard
output is never read by the PDP.
*Test:* structural key-enumeration, mirroring invariant 4; a PDP-imports-guard
dependency check.

## 7. What this layer does NOT claim

- It does not claim zero hallucinations (IMPOSSIBLE+).
- It does not claim detection of well-cited lies from poisoned sources.
- It does not claim the critic model (D6) detects anything; it is telemetry.
- It does not claim to be a security boundary. The authority boundary is
  unchanged and does not depend on this layer.
- It does not claim a false-positive rate; that is measured on the benchmark
  (`falseClaimRate`, `falseWithholdRate`) before any number is published.

## 8. Metrics added to the benchmark

- `falseClaimRate` — the fraction of legitimate-corpus guard verdicts that were
  flagged/repaired/withheld (non-delivered); target within assurance target 7's
  <= 1% false-denial budget. Benchmark note (M9 audit): the benchmark
  denominator is currently the legitimate-corpus guard verdicts only (one per
  run — LEG-002 is network-gated and emits no verdict); the statistically
  meaningful measurement is the R1 security test (100 honest sessions).
  Widening the benchmark denominator is the first item of the assurance-targets
  milestone (`PROMPTS/M10-assurance-targets-and-slos.md`).
- `withholdRate` — withheld / total responses.
- `leakWithholdPrecision` — leak withholds that contained a real canary.
- `guardLatencyP99` — guard must not blow the decision-latency budget
  (assurance target 9).

## 9. Implementation shape (when scheduled)

One module, `src/guard.ts` (~200 lines): `ResponseGuard` interface,
`GroundedResponseGuard` (D2–D5; D6 behind the same interface later), the
ladder, and the `GuardedResponse` types. `AgentSession.run()` gains one call
site. Tests: `tests/guard.test.ts` for D2–D5 and the ladder,
`security-tests/guard-invariants.test.ts` for R1–R3 structural checks, four
new attack-corpus cases (forged citation, action-claim mismatch, prose leak,
poisoned source). No new dependencies. No changes to the PDP, capability, or
policy modules — by design, and enforced by R3's dependency check.
