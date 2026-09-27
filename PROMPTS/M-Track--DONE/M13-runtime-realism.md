# M13 — Runtime realism: model provider adapters + verification pipeline + structured telemetry

Baseline: M10 complete (SLO gate exists); this milestone runs **in parallel
with M11** — disjoint module surfaces (see the map in
`PROMPTS/M10-assurance-targets-and-slos.md` and below). Zero new runtime
dependencies: Node 24's built-in `fetch` covers provider HTTP; provider SDKs
and the OTel SDK are ADR-gated and **out of scope**.

- **Model provider adapters** (ADR-005): real providers behind `ModelPort`.
- **Verification pipeline**: agent-produced artifacts pass configured checks
  (lint/SAST-style commands) before their results are trusted.
- **Structured telemetry (OTel row)**: observability without ad-hoc logs —
  zero-dep first.

## 1. Subagents + parallelization (explicit)

- **Subagent A — model provider adapters.** Owns `src/model.ts` + a new
  adapter module + tests.
- **Subagent B — verification pipeline.** Owns `src/verification.ts` + a new
  check module + tests.
- **Subagent C — structured telemetry.** Owns new `src/telemetry.ts` + its
  wiring points + tests.
- **A ∥ B ∥ C run in PARALLEL** — three disjoint module surfaces.
- **Coordination rules:** only the main session edits `src/cli.ts` (demo
  sections, benchmark additions). If both A and C need `src/runtime.ts` (C's
  session-start/end wiring is ~2 lines; A's adapter is constructed by the
  caller), **C waits for A's commit** rather than racing the file. B touches
  neither.

## 2. A — model provider adapters

1. `HttpModelAdapter implements ModelPort`: OpenAI-compatible
   chat-completions via `fetch`. Base URL + API key from config (the key comes
   from the secret broker; never logged, never in an error message). Timeout +
   bounded retry with backoff. Output ALWAYS flows through `parseModelOutput`
   (hostile-input rule); the adapter maps provider text to `ModelOutput`
   intent only.
2. **Classification egress gate (security measure — never simplify away):**
   sending ingested content to an external provider is a disclosure. Before
   sending, enforce a configured classification ceiling over the content being
   sent (reuse `deriveClassification` over the prompt/context) and consult the
   PDP for the provider call (a `model.invoke`-style action on a synthetic
   provider resource). Above the ceiling or denied → refuse, emit a
   `model.call` event with the deny, deliver nothing.
3. Record `model.call` events: model id, duration, token usage if returned,
   egress-gate decision — **never content, never keys**.
4. Tests: `fetch` mocked (no network in CI); malformed provider output → fail
   closed; egress-gate refusal above ceiling; deny recorded; no secret/canary
   in any error message; ScriptedModel tests unaffected.

Doctrine: the adapter is a transport, not a trust boundary. The compromised-
model assumption is unchanged.

## 3. B — verification pipeline

1. `CommandCheck implements Check`: runs a configured command (argv array,
   **no shell**) against produced artifacts inside the session sandbox;
   nonzero exit or timeout → verification `fail`; results flow through the
   existing `runVerifications` path (failed checks already mark steps errored —
   no new authority anywhere).
2. Command allowlist from config; a check naming a non-allowlisted command is
   refused at configuration time.
3. Tests: pass/fail/timeout; allowlist refusal; artifact content is never
   interpolated into a shell string (argument-array exec only); the check
   result is recorded in the step's verifications.

ponytail: one command per check; composite pipelines when a real deployment
needs them.

## 4. C — structured telemetry

1. `TelemetryPort.emit(name, attrs)`; the shipped implementation writes JSON
   lines to stdout (zero deps).
2. Emitted at: session run start/end (durations), model calls (A's adapter),
   per-session PDP deny-reason aggregates (computed from existing events — no
   re-entry into the PDP), optionally benchmark/demo.
3. Doctrine identical to the event log: **no secrets, no canaries, no unsealed
   model text**. A test scans emitted lines for canary values and model text.
4. Tests: lines are valid JSON; no canary/model-text leakage; emission
   failures never break the run (telemetry is not a control — swallow and
   count, never throw into the request path).

ponytail: an OTel SDK adapter later behind the same port; that dependency
requires its own ADR.

## 5. Demo (main session)

One section: a scripted `fetch` mock driving `HttpModelAdapter` end-to-end
(egress gate allow → `model.call` event + telemetry line; ceiling refusal →
deny event), plus one `CommandCheck` pass and one intentional fail.

## 6. Docs sweep (main session)

- ROADMAP rows Model provider adapters / Verification pipeline / Structured
  telemetry → `[DONE]` with milestone refs.
- CURRENT_STATE: counts; "What works" bullets for the three items.
- SECURITY_CLAIMS: the egress-gate claim (a provider receives nothing above
  the configured ceiling) with mechanism/tests/limitations; telemetry claim
  scoped honestly (it is observability, not a control).
- AGENT-SESSION entry.

## 7. Constraints

- Zero new runtime dependencies. SLO hard targets stay green. Default-deny on
  the egress gate — it is never bypassable by config default.
- Telemetry is not a control: the PDP must never read it (R3 spirit — add a
  dependency-direction check if wiring makes it plausible).

## 8. Acceptance + skip list

Acceptance: gate green; parallel subagent work merged without breaking either
milestone's tests; demo runs; docs updated.

skipped: streaming responses, multi-provider SDK matrix, cost tracking beyond
token counts, prompt caching, OTel SDK, sampling/batching.
add when: streaming when latency UX demands it; OTel when a collector exists
(ADR for the dep).
