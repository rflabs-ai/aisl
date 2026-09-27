# M10 — Assurance targets + SLOs (per ADR-014)

Baseline: M9 complete — 278 tests / 72 suites, `npm run typecheck && npm test`
green, `npm run benchmark` produces `benchmarks/results.json`
(`auditCompleteness 1.0`, `hashChainValid true`, `falseClaimRate 0` over 1
legitimate-corpus verdict). Read first: `DECISIONS.md` ADR-014 (the governing
decision), `ROADMAP.md` (the `[NEXT]` row + "Planned milestone prompts" note),
`RELIABILITY.md` §8, `CURRENT_STATE.md`, `SECURITY_CLAIMS.md` (claims list),
`src/cli.ts` (`benchmark()`), `src/attacks.ts`, `security-fixtures/`,
`security-attacks/`.

Why now: ADR-014 decided "no single security percentage; one measurable target
per control, each with a named measurement, reported on every `npm run
benchmark` run" — but the promised ROADMAP "Assurance targets" section does not
exist and the benchmark reports metrics with no targets and no gate. M9's audit
also left `falseClaimRate` with a denominator of 1 (RELIABILITY §8 note). M10
closes both. It also sets the SLO baseline that M11–M13 must not regress —
which is why it runs first.

## 1. Subagent allocation + parallelization

Two subagents, SEQUENTIAL (B implements A's catalog — they are not parallel):

- **Subagent A — target catalog** (docs/design, no code): enumerate controls,
  one measurable target each. Deliverable: the ROADMAP "Assurance targets"
  section.
- **Subagent B — measurement + gate** (`src/cli.ts`, new `src/slo.ts` if
  warranted, tests): implement the catalog as a gated `slo` block in benchmark
  output; widen the `falseClaimRate` denominator.

Main session: docs sweep, benchmark/demo verification.

### Cross-milestone parallelization map (explicit)

- **M10 runs FIRST and alone.** It owns the benchmark block in `src/cli.ts`
  and defines the baseline every later milestone gates against.
- **After M10: M11 (authz depth) ∥ M13 (runtime realism) in parallel** —
  disjoint module surfaces (M11: `policy/pdp/domain/registry/capability`;
  M13: `model/verification/telemetry`). Shared-file rule: `src/cli.ts`
  demo/benchmark edits are merged by the main session; neither milestone edits
  the other's modules.
- **M12 (platform shift) Phase 0** (ADR + schema design — docs only) can also
  run parallel with M11/M13; its implementation waits for M11 (RLS and
  per-tenant-key design build on RBAC and classification propagation).
- Within M11: A ∥ B, then C. Within M12: ADR → A → (B ∥ C). Within M13:
  A ∥ B ∥ C. Each prompt states its own map.

## 2. Subagent A — target catalog

Deliverable: a new ROADMAP.md section **"Assurance targets"** with one row per
control: `| Control | Metric (exact benchmark key) | Target | Gate |`.

Rules:

- Prefer metrics the benchmark already measures: `unauthorizedActionDenialRate`
  (= 1.0), `auditCompleteness` (= 1.0), `hashChainValid` (true),
  `falseClaimRate` (≤ 0.01), `falseDenialRate` (≤ 0.01),
  `legitimateTaskSuccessRate` (= 1.0), attack-corpus pass rate (= 1.0),
  `promptInjectionSuccesses` (= 0). Add the legitimate-corpus guard coverage
  (`totalLegitimateResponses` floor) as a supporting metric.
- Latency targets (`auditQueryLatencyP99Ms`, `auditExportLatencyP99Ms`,
  `policyDiffLatencyMs`, `guardLatencyP99Ms`) are **reported, not gated** — a
  noisy CI machine must not fail the build. ADR-014 wants honesty, not
  flakiness.
- Where no metric exists and one is cheap, name it; where none is cheap, list
  the control under "not yet measured" instead of inventing a number
  (ADR-014's honesty rule).
- Gate column: `hard` (benchmark exits nonzero on miss) or `advisory`.
- No composite score; no percentages without denominators (both forbidden by
  ADR-014).
- Targets come from documented budgets (≤ 1% false-denial, assurance targets),
  never from inverting a measured value.

## 3. Subagent B — measurement + gate

1. `src/slo.ts` (or inside `cli.ts` if it stays tiny): a const target table
   from A's catalog + `evaluateSlo(metrics, targets) → { results: [{ id,
   metric, target, measured, gate, pass }], hardFailures }`. No config-file
   machinery.
2. `benchmark()` emits `metrics.slo = { pass, hardFailures, targets: [...] }`
   (exact shape yours to choose — document it in the ROADMAP section).
3. Gate: `npm run benchmark` **exits 1** when any hard target misses; prints a
   readable table plus the JSON.
4. Widen `falseClaimRate`: run the R1-style honest corpus
   (`summarizeRepoModel` sessions, N=100) in the benchmark; count
   non-delivered. Per the M9 prompt §9 accounting rule, add those sessions'
   decision events to `expectedDecisions` (`src/cli.ts`) so
   `auditCompleteness` stays 1.0. Update the RELIABILITY §8 note (denominator
   widened; drop the M9-audit caveat).
5. Keep `guardLatencyP99Ms` measured via direct `guard.guard()` calls.
6. Tests (`tests/slo.test.ts` or similar): gate fails on a fabricated hard
   miss; passes when all met; an advisory miss does not fail; the
   honest-corpus sessions keep `auditCompleteness` at 1.0; the `slo` block
   shape is pinned.
7. The honest corpus adds ~6s to the benchmark — acceptable. Do not reduce N
   below 100; denominator credibility is the point.

## 4. Docs sweep (main session)

- ROADMAP `[NEXT]` row → `[DONE]` (M10: targets table + gated benchmark;
  reference the new section).
- CURRENT_STATE: test counts; "measured this run" gains the SLO pass line;
  "What M10 closed" section; watch-item #2 struck.
- RELIABILITY §8: replace the M9-audit caveat with the widened-denominator
  note.
- AGENT-SESSION: new entry.
- SECURITY_CLAIMS: only if a claim's evidence references benchmark values whose
  meaning changed (Claim 23's "on the current corpus `falseClaimRate = 0`"
  remains true — verify).

## 5. Constraints

- Zero new runtime dependencies.
- No behavior change to pdp/capability/policy/guard — this milestone measures
  controls, it does not change them.
- The gate is deterministic on rates; latency is advisory only.
- Benchmarks stay honest: never tune the corpus to pass a target.

## 6. Acceptance

- `npm run typecheck && npm test` green (278 prior + new).
- `npm run benchmark`: `results.json` contains the `slo` block; hard gate
  passes; exit code 0; `auditCompleteness` still 1.0; `falseClaimRate`
  measured over ≥ 100 honest sessions.
- A test proves the gate CAN fail (fabricated metrics flip it).
- The ROADMAP "Assurance targets" section exists and matches the implemented
  catalog exactly.
- Docs updated.

## 7. Skip list (do not do in this milestone)

- Benchmark history file / time-series store — release snapshot is a
  documented manual copy of `results.json`.
- Dashboards, OTel (M13), confidence intervals (DECISIONS.md names them as
  future), composite scores (forbidden), new attack-corpus cases.

skipped: release snapshot tooling; add when a release process exists.
add when: dashboards after OTel (M13) lands.
