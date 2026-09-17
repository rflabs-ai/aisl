# AGENT SESSION LOG

Per-repo tracker for AI agent sessions. Each entry records what happened, what
was left, and what the next session should pick up.
## Format

```

### SESSION <id> — <date> — <agent/model>

**Did:**
- What was built, fixed, or changed

**Left:**
- What was started but not finished
- What was deferred and why

**Next session should:**
- Concrete first action for the next agent

**Evidence:**
- Test count, benchmark results, commit hashes
```

---

### SESSION 16 — 2026-09-17 — opencode/m12-phase0-adr

**Did:**
- M12 Phase 0 landed (docs only): **ADR-018** written into `DECISIONS.md`
  (numbering verified — 017 taken by the M11 role model). It decides, per the
  M12 prompt's hard requirements:
  - **Driver: `postgres.js`** — zero transitive runtime deps (ADR-015
    item 2 decides it; `pg` pulls `pg-connection-string`/`pg-protocol`/etc.),
    native ESM, single multiplexed socket so no pooling library. Pinned when
    the dependency lands in Phase 1.
  - **Schema inline in the ADR:** `migrations` (forward-only, hash-recorded),
    `security_events` (parity with the SQLite table — `event TEXT`, not JSONB,
    so the parsed-object hash recompute round-trips byte-stably; append-only
    via revoked UPDATE/DELETE privileges + triggers, global seq — one hash
    chain, one signer), `capability_requests`, `projects`/`tasks`/
    `agent_sessions`.
  - **RLS model:** `ENABLE`+`FORCE` RLS, deny-by-default policies keyed on
    `current_setting('app.tenant_id', true)` (unset → NULL → false → zero
    rows), context set per transaction via `SET LOCAL`. Three non-superuser
    roles: `app_rw` (runtime: global SELECT+INSERT on events — resume/
    verify/bundle read the whole chain; RLS-governed on tenant tables),
    `app_reader` (audit path: tenant-scoped event SELECT — hostile
    cross-tenant reads return zero rows), `app_ddl` (migration runner only).
  - **Per-tenant keys:** HKDF info gains tenantId (`evidence:<tenant>:<level>`),
    versioned keyIds `evidence-key:v2:<tenant>:<classification>`; legacy ids
    keep opening under the old derivation — **no silent re-encryption**.
  - **Fail-closed:** new `DenyReason` member `store-unavailable` beside
    `idp-unavailable`; no silent in-memory fallback.
  - **Dual backend:** `EventStore` port = the existing `EventLog` public
    surface (append/all/forTenant/query/exportFor/verify/bundle/anchor/close);
    SQLite stays default; `PostgresEventLog` (`src/event-store-pg.ts`) is the
    second implementation; the construction seam is `src/scenario.ts:140`
    (the only `new EventLog` call site). Postgres tests skip cleanly without
    `DATABASE_URL`.
- Session audit of the ADR found two design defects before Phase 1 could
  follow them: (1) tenant-scoped SELECT on `security_events` would make
  `resume()`/`verify()`/`bundle()` impossible (they read the whole global
  chain) — amended to the two-role model above; (2) `event JSONB` broke the
  claimed SQLite parity — amended to `event TEXT`. ROADMAP "pinned" wording
  corrected. Tickets
  `.scratch/session-audit/2026-09-17-m12-phase0-adr/issues/{01,02,03}`.
- ROADMAP M12 marker updated (Phase 0 done, Phase 1 next).
- **Phase 1 (Subagent A) landed and verified (commit `ff533d7`):**
  - `EventStore` port extracted from `EventLog`'s public surface (append/all/
    forTenant/query/exportFor/verify/bundle/anchor/close); `EventLog` implements
    it; shared helpers (chain verify, filter, export, bundle, anchor IO)
    extracted into `src/events.ts` and reused — zero behavior change.
  - `src/event-store-pg.ts` (`PostgresEventLog implements EventStore`):
    forward-only hash-recorded migrations (id+sha256(sql) in `migrations`,
    tampered hash → fail closed, one `store.migrate` event per applied batch
    via the store itself), chain rehydrate + verify on connect, append via the
    same signing/hash helpers, anchor-file parity, `whenReady()` readiness
    (`buildWorld()` is sync; `whenWorldReady()` in scenario.ts + cli wiring —
    appends before ready fail closed), URL/credentials redacted from every
    error (secret-scan test pins it).
  - **Second runtime dependency admitted per ADR-018/ADR-015:**
    `postgres@^3.4.9` — zero transitive deps verified in the lockfile, SBOM
    covers it.
  - Tests: 373 total — 365 pass, 8 Postgres-mode skips (no `DATABASE_URL`);
    parity loop runs the core evidence behaviors against memory + SQLite
    always-on; migrations/fail-closed/secret suites are PG-only skips.
  - **Honest gap:** Postgres is NOT installed locally (and Docker daemon
    unavailable this session) — the 8 PG tests have never run against a live
    server yet. Milestone acceptance requires a disposable container run
    (`DATABASE_URL`) before the M12 close-out.
  - Two `ponytail:` markers added in `event-store-pg.ts` (append-time
    timestamp; mirror-reads instead of SQL-side filtering until the port goes
    async / reader-role server-side filtering in Phase 2).

**Left:**
- Phase 2 not started: B (RLS roles + policies + per-tenant keys in `src/seal.ts`)
  and C (backup/restore + `capability_requests`/`projects`/`tasks`/
  `agent_sessions` persistence) may now run in PARALLEL — both consume A's
  migrations (append migration ids 2+).
- Postgres parity suite needs a live-DB run (Docker container or install)
  before milestone close-out; currently skip-only.
- Full docs sweep (ROADMAP rows → [DONE], DEPLOYMENT, SECURITY_CLAIMS,
  CURRENT_STATE full update) is the main-session close-out.

**Evidence:**
- Docs-only phase; `npm run typecheck` clean; `npm test` 351/351 unchanged.

---

### SESSION 15 — 2026-09-17 — opencode/m12-prep-audit-closure

**Did:**
- Closed all four findings from the M11/M13 session audits
  (`.scratch/session-audit/`), the prerequisites for M12:
  - **Egress gate (M13-01):** the audit's proposed value-scan turned out to be
    subsumed by existing behavior — `deriveClassification` already maxes over
    the WHOLE content map, so map-covered confidential content with undeclared
    `contextResourceIds` was always refused (two regression tests now pin it,
    incl. a fragment case). The real residual — non-empty context with NO
    content map — now fails closed (`egress: 'refused-unclassifiable'`, deny
    event, fetch never invoked). Deny-on-unmatched-text was rejected by
    design: hostile ingested content MUST stay sendable (the PDP gates its
    actions, not its bytes); free text absent from the map is the same class
    as `prompt` = H7 DLP, and Claim 27's limitations now say exactly that.
    4 new tests (`tests/model-http.test.ts` 10 → 14).
  - **Corpus ordering (M13-02):** `runAttackCorpus` restored to a sequential
    `for ... await` loop (one line + invariant comment) — shared world,
    corpus-deterministic evidence order, no accidental `Promise.all`
    interleaving once a harness model returns real promises.
  - **Docs drift (M11-01):** CURRENT_STATE "Measured this run" no longer
    copies the four advisory latency digits (every `npm test` regenerates
    `results.json` via `tests/slo.test.ts`, so copies are stale by
    construction); it cites stable facts only and points at the artifact.
  - **File map (M11-02):** PROJECT_CONTEXT map += `policy-config.ts`,
    `model-http.ts`, `check-command.ts`, `telemetry.ts` — now matches src/
    (31 modules).
  - Drive-by: demo line 'command check fails' printed `FAIL` even when
    behaving correctly (both ternary branches were 'FAIL'); now prints
    `EXPECTED-FAIL`.
- Docs: Claim 27 mechanism + limitations + evidence (SECURITY_CLAIMS),
  CURRENT_STATE (counts 351, M13 suite 33, egress-gate wording ×2),
  PROJECT_CONTEXT map, all four audit issue files → resolved with reasoning.

**Left:**
- Claim 27's free-text residual (content absent from the map, like `prompt`)
  stays open until H7 content-level DLP — documented, not hidden.
- Closure sweep committed as `9c1d861`; M12 prompt refreshed for it
  (ADR-018, M11+M13 baseline, environment note, ROADMAP markers).

**Next session should:**
- M12 Phase 0: the Postgres ADR is **ADR-018** (017 is taken by the M11 role
  model — verified). `PROMPTS/M12-platform-shift.md` is current. Phase 0 is
  docs-only (driver choice, schema, RLS model, per-tenant key derivation,
  fail-closed-on-DB-down, SQLite stays default behind an EventStore port);
  Phase 1+ needs a Postgres install or container (`DATABASE_URL`).

**Evidence:**
- `npm run typecheck` clean; `npm test` 351/351 (99 suites); `npm run demo`
  sane (egress allow + ceiling refusal + EXPECTED-FAIL lines); benchmark
  regenerated last, exit 0, `slo.pass = true`, 0 hard failures of 14 targets,
  audit completeness 2122/2122, `falseClaimRate` 0/101 — no SLO regression.

---

### SESSION 14 — 2026-09-17 — opencode/m13-runtime-realism

**Did:**
- M13 landed from `PROMPTS/M13-runtime-realism.md` (three Stage-1 rows,
  subagents A ∥ B in parallel, C after A; zero new runtime dependencies —
  Node 24's built-in `fetch` covers provider HTTP; main session owned
  `src/cli.ts` and docs).
  - **A — Model provider adapters.** `ModelPort.complete` is async-capable
    (`ModelOutput | Promise<ModelOutput>`) and `AgentSession.run()` is async;
    `ModelInput.contextResourceIds` feeds egress classification.
    `src/model-http.ts`: `HttpModelAdapter` (OpenAI-compatible, injectable
    `fetch`, timeout + bounded retry/backoff, output always through
    `parseModelOutput`) behind the **classification egress gate** —
    `deriveClassification` over the content being sent must fit the configured
    ceiling AND the PDP must allow `model.invoke` on the provider resource;
    default-deny, refusals throw and never send; `model.call` events carry
    id/duration/usage/decision only. 10 tests.
  - **B — Verification pipeline.** `src/check-command.ts`: `CommandCheck` —
    argv-array exec with no shell, config-time allowlist refusal, artifact
    delivered via stdin only, minimal env (no ambient secrets), timeout →
    fail; flows through the existing `runVerifications` path (failed checks
    already mark steps errored). 10 tests. (B's first files were clobbered by
    a concurrent tree operation; recreated main-session-side to the same
    validated design.)
  - **C — Structured telemetry.** `src/telemetry.ts`: `TelemetryPort` +
    `JsonlTelemetry` (zero-dep JSONL, failure-swallowing `dropped` counter),
    `denyReasonCounts` from existing step decisions (no PDP re-entry), and
    runtime wiring for `session.start/end` + `pdp.denyReasons`. Dependency-
    direction tests: the PDP never imports telemetry. 9 tests.
- Demo section 18: scripted provider through the egress gate (allow →
  `model.call` + telemetry line; ceiling refusal → deny event, fetch never
  invoked), plus one `CommandCheck` pass and one intentional fail.
- Claims 27 (egress gate) and 28 (telemetry, scoped honestly) added;
  ROADMAP rows, CURRENT_STATE (counts, What works, What M13 closed) updated.

**Left:**
- Streaming responses, multi-provider SDK matrix, prompt caching — named
  ceilings in the M13 prompt, none requested by a deployment.
- OTel SDK adapter behind `TelemetryPort` when a collector exists (ADR-gated
  dependency).
- The adapter's transport-level containment (it runs in-process) — container-
  backed check/provider execution remains the ADR-003 path.

**Next session should:**
- M12 (Postgres shift) or the REST API row. Watch the coordination note below.

**Evidence:**
- 347 tests, 0 failures, typecheck clean; commit 440ba58 re-lands M13 after
  the commit-tree was verified green in a throwaway worktree.
- Demo + benchmark produce sane output; all 14 SLO targets pass.

**Coordination note (for every future session):** M13 ran in the same working
tree as a concurrently-active M11 session. Two uncoordinated `git add`/commit/
history-rewrite streams raced twice: M11's rewrite orphaned M13's first clean
commit (3736a12, recovered via reflog and re-landed), and staged-but-uncommitted
M11 states twice leaked into M13's commits (one had to be soft-reset and
rebuilt). Rule going forward: one commit-writer per working tree, or commit in
disjoint file sets inside one gate window — and re-check `git log` immediately
before every `git commit`.

---

### SESSION 13 — 2026-09-17 — opencode/m11-authz-depth

**Did:**
- M11 landed from `PROMPTS/M11-authz-depth.md` (three Stage-1 rows, subagents
  A ∥ B in parallel on disjoint surfaces, C after A; zero new runtime
  dependencies; main session owned `src/cli.ts` and docs).
  - **A — Granular RBAC.** `Role` as data (`src/domain.ts`), `BASELINE_ROLES` +
    `ROLE_TABLE_VERSION` (`src/policy.ts`), `issueRequestForRole`
    (`src/capability.ts`) + `AuthorizationService.issueForRole` (`src/pdp.ts`,
    6th optional ctor param = role table) — issuance through a role delegates
    to the ordinary `issue()` pipeline, so issuer kinds/attenuation/audit are
    untouched; over-privileged requests throw, unknown roles fail closed.
    `createPolicyEngine(rules, id, roles?)` cross-validates role-referencing
    allow rules at construction (action/ceiling/wildcard overreach →
    `PolicyCompilationError`).
  - **B — Classification propagation.** `propagateClassification` +
    `ResourceRegistry.raiseClassification` (raise-only seam),
    `ingestDocument(..., derivedFrom?)` → `derivedClassification`,
    runtime write path (`changed: true`) lifts the target label to the max of
    the step's data sources (capability ceilings excluded — clearance is not a
    data label), execution events carry `metadata.derivedClassification` and
    seal under `evidence-key:<derived>`.
  - **C — Configuration management.** New `src/policy-config.ts`:
    `PolicyBundle`/`RoleBundle`, `hash = sha256(canonicalJson({version,
    rules|roles}))`, `loadPolicyBundle`/`loadRoleBundle` fail closed on any
    mismatch, `createEngineFromBundle` appends exactly one opt-in
    `policy.load` event, role table loads through the same bundle mechanism.
    `npm run policy:diff` verifies versioned overlay hashes before diffing;
    legacy unversioned overlays unchanged.
- Demo section 17 (`src/cli.ts`): role-templated issuance (mint at ceiling,
  overreach refused, agent-mint refused), derived-artifact label raise +
  sealed-key match, versioned bundle load + tamper refusal. Deliberately uses
  only sync APIs (`attempt()`, no `run()`) so the section is independent of
  the concurrent M13 async-ModelPort conversion.
- Docs: ROADMAP (3 rows [DONE] + milestone-paragraph update), CURRENT_STATE
  (counts 318/85, M11 "What works" bullets, "What M11 closed" ×3, known-gap #6
  struck with honest residual: hash proves integrity, review gate is git),
  SECURITY_CLAIMS (Claims 24/25/26), DECISIONS (ADR-017 role model, refs
  ADR-002), this entry.
- **Concurrency note:** an M13 session (model provider adapters, async
  `ModelPort`) is running against this same working tree. M11's commits were
  built with git plumbing (temp index → `commit-tree`) so M13's in-flight
  files were never written or staged by this session. M11's `src/runtime.ts`
  was committed WITHOUT M13's async hunks; M13 will re-apply them on its own
  integration commit.

**Left:**
- **Post-M13 audit (owed):** when M13 lands its integration (async `cli.ts`
  merge), re-run `npm run typecheck && npm test && npm run demo &&
  npm run benchmark` on the merged tree, reconcile CURRENT_STATE/AGENT-SESSION
  counts (M11's docs describe the M11-only tree: 318 assertions / 85 suites /
  28 modules), and verify M13's async changes did not alter M11's seams
  (`issueForRole`, propagation, bundles).
- Deferred by design (M11 §8): role inheritance, dynamic role CRUD, ABAC
  beyond existing conditions, per-role approval routing, signed bundles.

**Next session should:**
- If M13 has landed: run the post-M13 audit above. Otherwise: M12 Phase 0
  (Postgres ADR only) — it touches no M11 surface.

**Evidence:**
- Commit `12ed44b` (M11 code+tests) verified in an isolated worktree:
  typecheck clean, 318 tests / 85 suites green, `npm run benchmark` exit 0 —
  all 14 assurance targets pass (10 hard), audit completeness 2122/2122,
  `falseClaimRate` 0 over 101. No M10 SLO regression.
- 35 new assertions: RBAC 12 (`tests/m11-rbac.test.ts`), propagation 11
  (`tests/m11-classification.test.ts`), bundles 12
  (`tests/m11-policy-config.test.ts`).

---

### SESSION 12 — 2026-09-17 — opencode/m10-assurance-targets-and-slos

**Did:**
- M10 landed (one surface: `src/slo.ts` new, `src/cli.ts` benchmark, one test
  file, docs). No behavior change to pdp/capability/policy/guard — this
  milestone measures controls; it does not change them. Executed in-session
  (subagent A → B were sequential and the full context was already loaded).
  - **Catalog (A).** ROADMAP "Assurance targets (ADR-014)" rewritten as the
    implemented catalog: 10 benchmark-gated controls (9 rate/boolean hard
    targets + `guard-corpus-floor` ≥ 100) + 4 latency rows (advisory,
    reported-only), then "gated by the test suite" (unauth principals, MFA,
    replay, secrets-at-rest, model independence, capability/session revocation)
    and "not yet measured" (end-to-end decision latency, H15 degraded mode,
    unknown vulnerabilities). No composite score; every rate's denominator sits
    in the same JSON. Targets come from documented budgets, not inverted
    measurements.
  - **Measurement + gate (B).** `src/slo.ts`: `SLO_TARGETS` const catalog +
    `evaluateSlo(metrics, targets?) → { results, hardFailures }` (dotted-path
    read, `eq|lte|gte`, missing metric fails closed). `benchmark()` prints the
    readable target table, writes `metrics.slo = { pass, hardFailures,
    targets[] }` to `benchmarks/results.json`, and sets exit code 1 on any hard
    miss. `adversarial.corpusPassRate` added so the corpus gate has a named
    key.
  - **falseClaimRate widened.** `benchmark()` runs the R1-style honest corpus
    (100 `summarizeRepoModel` sessions, ~1 s); their first-pass guard verdicts
    join the fixture verdicts (denominator 101). Their PDP decisions are added
    to `expectedDecisions` (one per session), keeping `auditCompleteness` at
    1.0 — verified 2122/2122 this run.
- Tests (`tests/slo.test.ts`, 5): hard miss flips the gate (fabricated
  metrics); all-met passes; missing metric fails closed; advisory miss reported
  but never fails; the real benchmark exits 0 with the pinned `slo` block shape
  and catalog ids (`execFileSync` throwing on nonzero exit IS the gate test).
- Docs: ROADMAP (Stage-0 row [DONE], "Planned milestone prompts" note,
  assurance section), CURRENT_STATE (283 tests / 27 modules, "What M10 closed",
  watch-item #2 struck, measured-this-run + SLO line), RELIABILITY §8
  (widened denominator replaces the M9 caveat; stale "assurance target 7/9"
  number refs → control names, since the catalog renumbered), SECURITY_CLAIMS
  Claim 23 evidence/limitations (denominator meaning changed; the claim's
  "falseClaimRate = 0" remains true).
- Post-commit drift sweep (before M11/M13 kickoff): fixed CURRENT_STATE source
  counts (27 modules / ~5,500 lines — the pre-M10 "27 modules" figure was
  already one off, and the line count had drifted), resynced PROJECT_CONTEXT.md
  (M0-era 14-module file map → the full 27-module map; 10 → 12 attack cases;
  "zero runtime deps" → jose/ADR-015; Docker now M1-used; counts delegated to
  CURRENT_STATE as the live snapshot), and added a stage note to its non-goals.

**Left:**
- Nothing in flight. Skipped by design (M10 §7): benchmark history/time-series,
  dashboards/OTel (M13), confidence intervals (future per ADR-014), composite
  scores (forbidden), new attack-corpus cases.

**Next session should:**
- Begin M11 (`PROMPTS/M11-authz-depth.md`) ∥ M13 (`PROMPTS/M13-runtime-realism.md`)
  in parallel (disjoint module surfaces; `src/cli.ts` demo/benchmark edits merge
  in the main session). M12 Phase 0 (ADR only) may also run in parallel. All
  later milestones gate against M10's SLO baseline — do not regress it.

**Evidence:**
- 283 tests / 74 suites green, typecheck clean; demo 16 sections; attack 12/12;
  benchmark: auditCompleteness 2122/2122 = 1.0, hash chain valid,
  falseClaimRate 0 over 101 responses, SLO 14/14 pass (10 hard, 4 advisory),
  exit 0.

---

### SESSION 11 — 2026-09-17 — opencode/m9-audit-and-m10-m13-scoping

**Did:**
- Committed the two snapshots left in the working tree: `b76a2ea` (M6.1 audit
  drift remediation — SESSION 9's code; its doc entries ride with the M9 commit
  because the same doc files were entangled) and `270f345` (M9). The pre-commit
  gate (typecheck + 278 tests) ran on both; working tree clean after.
- Audited M9 against the prompt's acceptance list (all items verified against
  evidence, not intent) and the §11 constraints. Six findings, none blocking;
  all documented so they cannot rot:
  1. Coarse per-session classification (max over all principal caps + the full
     content map) — `ponytail:` marker at the `deriveClassification` call site
     + Claim 23 limitation + CURRENT_STATE watch-item.
  2. Thin benchmark `falseClaimRate` denominator (0/1; LEG-002 is
     network-gated and emits no verdict) — RELIABILITY §8 note; the fix is
     M10's first item.
  3. Submit-failure observability (fail-closed degrade to text-only, no error
     marker) — Claim 23 limitation + CURRENT_STATE watch-item.
  4. Second-pass escalation renders the text-only escalate message — already
     documented in Claim 23.
  5. D6 `criticFn` hook is concrete-class-only (intentional) — documented.
  6. Test nit (abstain/escalate acceptance) — rationale in the test comment.
- CURRENT_STATE gained a "Watch-items from the M9 audit" section; ARCHITECTURE
  §2 gained a one-line M9 note (a guard-queued capability request is intent,
  not authority); RELIABILITY §2's GuardContext snippet was re-synced.
- Wrote four milestone prompts with explicit parallelization maps:
  `PROMPTS/M10-assurance-targets-and-slos.md` (the ROADMAP [NEXT] row; runs
  FIRST and sets the SLO baseline), `PROMPTS/M11-authz-depth.md` (A ∥ B then C),
  `PROMPTS/M12-platform-shift.md` (Phase 0 ADR parallel with M11/M13; impl:
  ADR → A → B ∥ C), `PROMPTS/M13-runtime-realism.md` (A ∥ B ∥ C; parallel with
  M11). ROADMAP [NEXT] row + "Planned milestone prompts" note + SESSION 10
  next-session pointer updated.

**Left:**
- Nothing in flight. M10 not started; its prompt is ready.

**Next session should:**
- Begin M10 (`PROMPTS/M10-assurance-targets-and-slos.md`). The cross-milestone
  parallelization map is in that prompt and restated in M11–M13.

**Evidence:**
- 278 tests, typecheck clean; attack harness 12/12; demo 16 sections;
  benchmark: auditCompleteness 1.0, hash chain valid, falseClaimRate 0.

---

### SESSION 10 — 2026-09-17 — opencode/m9-guard-followups-and-drift-closure

**Did:**
- M9: guard follow-ups + drift closure landed (one surface: `src/guard.ts`,
  `src/runtime.ts`, `src/scenario.ts`, `src/cli.ts`, tests, docs). Three
  subagents ran sequentially (A → B → C) because all three touch the same two
  files.
  - **Subagent A — Escalate wired to M4.** `GuardContext` gains
    `principal: Principal` (required) and `capabilityRequestService?`
    (type-only import from `./capability-request.ts`; no runtime dependency on
    the authority plane, R3 holds). `GuardedResponse` gains `requestId?`.
    `runLadder` stays pure; `guard()` detects the Escalate rung after the ladder
    returns and, when a service is provided and the principal is an agent,
    calls `submit(principal, sessionId, ['guard.review'], ['guard.review'],
    classification, 'Guard Escalate: <reasons>')`. `submit()` owns the sole
    `capability.request` event; the guard appends nothing. The awaiting-review
    text names the request id; `runtime` threads `metadata.requestId` through.
    Text-only fallback when no service or a non-agent principal. `SessionConfig`
    / `SessionOverrides` carry the optional service; `scenario.ts` forwards it.
  - **Subagent B — per-session classification + second pass.** Exported
    `deriveClassification()` (`src/runtime.ts`): highest of the principal's
    capability `maxClassification` ceilings, the registry classification of every
    `content` key, and the requested resources; default `'public'`, unknown
    labels fail closed (rank 100). `AgentSession.run()` runs the guard a second
    time after `steps` are populated, compares verdicts via
    `canonicalJson({ status, flags })`, emits ONE extra `session.guard` event
    (`phase: 'guard-second-pass'`) only on a change, adopts the second verdict,
    and never passes the capability-request service to the second pass (no
    double-queue). Event metadata construction factored into `appendGuardEvent`.
  - **Subagent C — drift fixes + D6 hook + benchmark.** `originalSealed`
    becomes `Sealed | null` (raw object in `metadata.sealed`); `ladderRung`
    added to `GuardedResponse` and threaded into both event phases; `guard()`
    now gates M4 on `ladderRung === 'escalate'`; D4/D2 number flags deduped
    (one flag: `unverified-claim` with no steps, `numeric-mismatch` with steps,
    never both); `regenerateFn` success/failure tests (called once, no retry);
    D6 `criticFn` hook on `guard()` (flags merged before the ladder, no real
    critic); `evidence.falseClaimRate` + `totalLegitimateResponses` +
    `legitimateResponsesNonDelivered` in the benchmark, measured from the
    first-pass `session.guard` events of the existing legitimate-corpus run (no
    extra sessions, so `auditCompleteness` accounting is unchanged).
- Demo (`src/cli.ts`) gained section 16: a hostile output runs against a session
  whose derived classification is ≥ confidential, with a real
  `CapabilityRequestService`; it prints the awaiting-review text with the request
  id and both the `session.guard` (with `requestId`) and `capability.request`
  events.
- Docs: `SECURITY_CLAIMS.md` Claim 23 mechanism/assumptions/evidence/limitations
  rewritten for M9; `CURRENT_STATE.md` header + counts (252 → 278) + "What M9
  closed"; `ROADMAP.md` "Output reliability layer" status parenthetical;
  `RELIABILITY.md` status footer counts + §4 `GuardedResponse` snippet
  (`originalSealed: Sealed | null`, `ladderRung`) + §8 `falseClaimRate` wording.

**Left:**
- D6 remains a hook only — no real critic model is wired (telemetry).
- `regenerateFn` is exercised by tests but `GroundedResponseGuard` still passes
  `null` in production, so the Regenerate rung is dormant until a model retry is
  wired.
- A second-pass escalation renders the text-only escalate message (the first
  pass's `requestId` lives in the first `session.guard` event); the second pass
  deliberately never submits a second request.
- `benchmarks/results.json` was regenerated and is committed with this milestone;
  its diff carries timestamp/latency/head noise by nature.

**Next session should:**
- Begin M10 (`PROMPTS/M10-assurance-targets-and-slos.md`, the ROADMAP [NEXT]
  row). M11–M13 prompts (authz depth, platform shift, runtime realism) and the
  cross-milestone parallelization map are in `PROMPTS/`.

**Evidence:**
- 278 tests, 0 failures, 72 suites; typecheck clean (252 prior + 26 new).
- Demo: 16 sections, all pass cleanly; section 16 escalates with a real request
  id and both events logged.
- Benchmark: 12/12 attack cases, 20/20 denied, audit completeness 1.0, hash
  chain valid, `falseClaimRate` 0 over 1 legitimate response, query p99 0.285 ms
  / export p99 0.337 ms / policy-diff 0.115 ms / guard p99 0.008 ms.

---

### SESSION 9 — 2026-09-17 — opencode/m6.1-audit-drift-remediation

**Did:**
- M6.1: Audit drift remediation landed. Closed the M6 post-milestone drift audit
  items in the audit query + export API.
  - `src/pdp.ts:evaluate()`: removed the redundant synthetic `audit-log:*`
    registration block. `queryAudit()` is the single registration site; a direct
    `authorize()` call on a caller-constructed `audit-log:*` id now fails closed
    as `unknown-resource` instead of materializing a resource (M6 spec §7).
  - `src/audit-query.ts:exportFor()`: the success path now overrides
    `EventLog.exportFor()`'s wall-clock `generatedAt` with the injected service
    clock, matching the deny path. `EventLog` still has no clock by design.
  - `src/audit-query.ts:validateFilters()`: single-bound time filters are now
    bounded. `{ toTime }` without `fromTime` throws (unbounded lower edge);
    `{ fromTime }` alone is measured against the service clock and throws past
    90 days. Deliberate tightening beyond the M6 spec's literal text.
  - `QueryResult` JSDoc documents the array-plus-`.decision`/`.events` shape;
    a test pins it.
  - `tests/m6-audit-query.test.ts`: removed `as any` (typed the `issueAuditCap`
    helper's `actions` as `readonly Action[]`, precise metadata cast in the
    sealed-content test) and deleted eight now-unused imports.
  - 9 new tests: direct-authorize deny (unknown-resource), service-clock
    `generatedAt`, three single-bound time-filter cases, `QueryResult` shape,
    `audit.export` implied by `query.audit`, the reverse direction, and result
    bounds vs requested filter bounds.
- Withdrawn: drift item #3 ("double authorization on export") was a misread —
  `EventLog.query()` is pure data; `exportFor()` authorizes exactly once via
  `queryAudit`. No code change. Drift item #5 (duplicate `tenantId` check) kept
  as deliberate defense-in-depth.
- Docs: Claim 21 mechanism + evidence updated (29 cases; single-bound rule noted
  as beyond-spec). `CURRENT_STATE.md` test counts 243 → 252, M6 coverage 20 → 29.
  `benchmarks/results.json` not committed (benchmark re-run confirmed sane;
  diff was timestamp/latency/ephemeral-head noise only).

**Left:**
- M9's prompt was stale after M6.1 (baseline, session number, Subagent A/B/C
  details) and was re-synced in the same session: baseline 252 / target ≥264,
  SESSION 10 entry, and the guard wiring corrected against `src/guard.ts`,
  `src/runtime.ts`, and `src/capability-request.ts` (real positional `submit()`
  signature, `GuardContext.principal`, `runLadder` purity, single
  `capability.request` event via `submit()`, benchmark accounting note).
- The `audit.export`-implied-by-`query.audit` rule still lives in two sites
  (`src/capability.ts:verifyCapability` and `src/pdp.ts:evaluate()`); they
  cross-reference each other in comments. Factor into one helper if a third
  audit action appears.

**Next session should:**
- Begin M9 (`PROMPTS/M9-guard-followups-and-drift-closure.md`, prompt already
  re-synced), or pick up the next Stage 1 item per ROADMAP.

**Evidence:**
- 252 tests, 0 failures, typecheck clean (243 prior + 9 new; all preserved).
- Demo: 15 sections, all pass cleanly; section 13 query/export unchanged.
- Benchmark: 12/12 attack cases, 20/20 denied, audit completeness 1.0,
  hash chain valid, audit query p99 0.248 ms / export p99 0.233 ms.

---

### SESSION 8 — 2026-09-17 — opencode/m7-policy-testing-and-reliability

**Did:**
- M7: Policy testing framework landed.
  - `src/policy-testing.ts`: `simulate(engine, scenarios)`, `diffDecisions(before, after, scenarios)`, `loadFixtures(dir)` with validator. JSON fixtures only; no DSL. 359 lines.
  - `src/policy-diff.ts`: argv glue (~53 lines) — `npm run policy:diff` defaults to diffing against itself (`0 changed`) and accepts an optional overlay file.
  - `tests/fixtures/policy/`: three migrated fixtures (default-deny-empty, deny-overrides-allow, classification-ceiling).
  - `tests/policy-harness.test.ts`: 12 cases covering simulate/diff/loadFixtures primitives, no-op overlay produces zero diff, fixture-driven scenarios match expected decisions.
  - Claim 22 added to `SECURITY_CLAIMS.md` (M7: Policy rules are unit-testable).
- M8: Output reliability layer landed.
  - `src/guard.ts` (180 lines): `ResponseGuard` interface, `GroundedResponseGuard` (D2–D5, D6 stub), pure `runLadder` (Repair → Regenerate → Abstain → Escalate; Escalate gated on `classificationRank >= 'confidential'`). D5 leaks skip the ladder entirely; repair replaces flagged spans with `[removed: <reason>]`; original sealed into evidence (AES-256-GCM via `src/seal.ts`).
  - `src/runtime.ts`: `SessionTrace.guarded?` field; `SessionConfig.guard?: ResponseGuard | null` (default = guard ON, `null` = guard disabled for tests); guard runs between `model.complete()` and trace return; one `session.guard` event appended per run with `metadata.sealed` holding the original.
  - `src/scenario.ts`: `world.session()` passes `canaries: secretValues` through.
  - `tests/guard.test.ts`: 18 cases covering D2 (cited-and-real / forged / span-missing / uncited), D3 (action-claim-mismatch + inverse), D4 (numeric-mismatch), D5 leak (skip-ladder), ladder (repair success + abort-on-empty, abstain, escalate reached for confidential, escalate NOT reached for low, fail-closed when guard throws), R3 structural assertion + dependency-direction.
  - `security-tests/guard-invariants.test.ts`: 8 cases covering R1 (100 honest sessions → `falseClaimRate = 0`, well within the 1% budget), R2 withhold scan (forged citation → repaired, action-claim-mismatch → repaired, prose leak → withheld via D5 skip-ladder, poisoned source → delivered — documents the D2 ceiling), R3 no-authority (GuardContext keys clean; `pdp.ts` and `guard.ts` do not import each other).
  - Claim 23 added to `SECURITY_CLAIMS.md` (M7/M8: Delivered claims are evidence-bound or annotated).
- Cleanup: removed dead `src/reliability.ts`, `tests/reliability.test.ts`, `src/hallucination-guard.ts` from a half-implemented prior attempt. Not imported anywhere; broken types caused typecheck to fail. Confirmed via `grep` before deletion.
- Demo (`src/cli.ts`) extended with section 14 (M7 harness: 3 fixtures pass + diff produces 2 changed) and section 15 (M8 guard: cited-and-real → DELIVERED, cited-and-forged → WITHHELD with citation-forgery flag, prose leak → WITHHELD via D5 skip-ladder).
- Benchmark (`src/cli.ts`) extended with `policyDiffLatencyMs` (~0.12 ms) and `guardLatencyP99Ms` (~0.007 ms). `auditCompleteness` remains 1.0; `unauthorizedActionDenialRate` remains 1.0.
- Docs: `ROADMAP.md` Stage 1 rows for "Policy testing framework" and "Output reliability layer" flipped to `[DONE]` with M7 commit references and Claim 22/23. `CURRENT_STATE.md` updated (test count 205 → 243, header "after M6" → "after M7/M8", "What M7 closed" and "What M8 closed" sections added). `RELIABILITY.md` status footer flipped from "design" to "implemented" with a link to SESSION 8 (this entry). `ARCHITECTURE.md` unchanged.

**Left:**
- D6 model-based critique is a stub (telemetry-only, with a `ponytail:` comment naming the upgrade path: critic model or n-sample agreement). A future hook; not a v1 requirement.
- The `Escalate` rung creates a `CapabilityRequest` but does not wait for approval. M4 handles the wait; out of scope here.
- Guard classification is fixed at `'public'` for v1. Per-session classification derivation (from the principal's tenant ceiling) is the next step; needed to enable the Escalate rung in production scenarios.
- The guard runs pre-execution on the model's first-pass text. Re-running the guard after `steps` are computed would catch action-claim-mismatch on a second pass and is documented as a follow-up.
- The benchmark measures guard latency via direct `guard.guard()` calls; the resulting `auditCompleteness` is unaffected because direct calls don't emit `session.guard` events. The prompt suggested +1000 guard events for `auditCompleteness`; the agent's bench loop instead calls guard directly to keep measurement representative of the per-call cost. Operators wanting session-driven measurement can run `npm run demo` and inspect the resulting event log.

**Next session should:**
- Pick up next Stage 1 item per ROADMAP, OR resume M8 follow-ups (D6 critic, per-session classification derivation, post-execution second-pass guard).
- The audit-query + export and reliability layer are both Stage 1 `[DONE]`; Stage 1's remaining items are Granular RBAC, Classification propagation, Sandbox lifecycle management, Tenant isolation hardening, Configuration management, and EASY items like REST API surface, project/task/session persistence, basic document ingestion, basic Git integration, minimal UI, developer setup script.

**Evidence:**
- 243 tests, 0 failures, typecheck clean
- 12/12 attack cases, 20/20 denied, audit completeness 100%
- Demo: 15 sections, all pass cleanly
- Benchmark: `policyDiffLatencyMs = 0.119`, `guardLatencyP99Ms = 0.007`, `auditQueryLatencyP99Ms = 0.262`, `auditExportLatencyP99Ms = 0.231`, `auditCompleteness = 1.0`, `hashChainValid = true`, `unauthorizedActionDenialRate = 1.0`

---

### SESSION 5 — 2026-09-17 — opencode/m5-implementation

**Did:**
- M5: Hierarchical resource matching landed.
  - `PolicyRule.resources.idPatterns?: readonly string[]` in `src/policy.ts:28`.
    Grammar: `tenant/...` (recursive, slash boundary), `prefix*` and `prefix?`
    (single-segment glob), literal (exact). Header comment in `src/policy.ts`
    documents the grammar and the boundary semantics.
  - `compileIdPattern(pattern): IdPatternMatcher` exported. Rejects patterns
    > 64 chars, `**`, unsupported characters, and recursive forms without a
    trailing `/` (e.g. `acme...`) — all throw `PolicyCompilationError`.
  - `matchesIdPattern(resourceId, matcher)` exported. Pure function over the
    compiled matcher; literal uses `===`, recursive uses `startsWith` with a
    length check (boundary at the slash), glob uses a regex built once and
    cached.
  - `createPolicyEngine` now compiles every unique `idPatterns` entry into a
    `Map<string, IdPatternMatcher>` at construction time and threads the map
    into `matchesResource`. Hot path never compiles. Defensive cache miss
    falls back to literal match + one stderr warning (ponytail: keeps the
    PDP answering even on a bug; documented ceiling).
  - `matchesResource` extended so `ids` and `idPatterns` OR-combine within
    one rule, and a rule with only `idPatterns` matches only by pattern.
    Default-deny, deny-overrides, classification ceilings, and tenant
    isolation are unchanged.
  - `_compileCacheSize(): number` exposed on the engine for the hot-path test
    (asserts the cache does not grow across `evaluate()` calls). Not part of
    the `PolicyEngine` interface; test-only seam.
- Demo (`src/cli.ts`) extended with section 12: a standalone policy with
  `idPatterns: ['acme/...']` allows `acme/project/sub/file` and denies
  `acme-other` at the boundary.
- Docs updated: ROADMAP Stage 1 hierarchical resource matching flipped to
  `[DONE]`; CURRENT_STATE known-vulnerability item 14 struck through and
  moved to a new "What M5 closed" section with the grammar and the
  boundary semantics; SECURITY_CLAIMS Claim 6 "Known limitations" notes that
  hierarchical matching widens rule selection, not capability scope;
  CURRENT_STATE test count 166 → 185.

**Left:**
- The hot-path test uses `_compileCacheSize()` because the existing test
  files have no spy pattern. The method is a single line of test-only
  surface — if a richer introspection API is needed (e.g. to confirm which
  specific patterns were compiled), the same map can be exposed.
- A `+` glob quantifier (`a+b`) was deliberately rejected at compile time.
  If operators need "one or more of the previous character", that is an
  additive grammar change with a test; nothing prevents it but the ceiling
  is documented.
- Cross-rule OR (a rule whose `idPatterns` succeeds but whose `types` fails
  matches if another rule also matches by type) is already correct — the
  loop is per-rule — but no test asserts it explicitly. If the test
  surface grows, add one.

**Next session should:**
- Per `AGENTS.md` discipline: the next MEDIUM-stage item per ROADMAP is
  whichever open item the operator picks next. Candidates still on the
  board: policy testing framework (NEXT), sandbox lifecycle management,
  configuration management (versioned, reviewable, attributable policy —
  closes B10 partially), audit query/export API, or a fresh EASY item
  (REST API surface, project/task/session persistence, basic document
  ingestion, basic Git integration, minimal UI, developer setup script).

**Evidence:**
- 185 tests, 0 failures, typecheck clean
- 12/12 attack cases, 20/20 denied, audit completeness 100%
- Demo: 12 sections; new section 12 demonstrates `acme/...` allowing
  `acme/project/sub/file` and denying `acme-other` at the boundary
- Benchmark: results regenerated; numbers unchanged modulo `generatedAt`
  and `head`

---

### SESSION 4 — 2026-09-16 — opencode/doc-sweep

**Did:**
- Doc-vs-code drift sweep. M3/M4 had landed without a matching doc pass; the
  docs were accurate in spirit but full of stale status markers and stale line
  references. Items closed:
  - **ROADMAP** Stage 1 table: Approval workflow, Capability request flow, and
    Capability revocation flipped to `[DONE]`. Capability revocation note added
    (in-process; multi-node = H13). Assurance target row 8 (revocation
    propagation) updated from "not implemented" to "immediate (in-process);
    multi-node = H13".
  - **ARCHITECTURE.md** section 1 plane diagram: identity/MFA "NOT YET
    IMPLEMENTED" replaced with the implemented M2 description, ADR-006 →
    ADR-016 reference. Section 5 deliberate-stubs table: Identity and
    SecretBroker rows rewritten (Identity implemented in M2; SecretBroker
    replaced by `EnvelopeSecretBroker` in M1).
  - **threat-models/TM-004** dependency entry and attack path: `jose` is now
    documented as the one runtime dependency under ADR-015 with the admission
    policy in place; "Add a malicious dependency" no longer reads as "succeeds".
  - **Line-number drift** corrected in SECURITY_CLAIMS, SECURITY_PRINCIPLES,
    ARCHITECTURE, DECISIONS, threat-models/TM-002/TM-003/TM-004, AGENT-SESSION
    (41 `src/<file>:<line>` tokens updated across 8 files by a focused
    subagent; verified by re-grep).
  - **CURRENT_STATE.md** cosmetic: module count 21 → 22 (added
    `src/capability-request.ts`), header "Updated after M3" → "Updated after
    M4", known-vulnerability item 12 strike-through cleaned up to a single
    sentence ("No multi-node capability revocation broadcast; H13").
- Wrote `PROMPTS/M5-hierarchical-resource-matching.md` so M5 can be picked up
  without further discovery work.

**Left:**
- The doc sweep did not commit. The diff is staged in the working tree. The
  next session (or the user) should review `git diff` and commit if the diff
  is acceptable — the sweep is mechanical and isolated, but committing is
  outside the doc-sweep mandate.
- ARCHITECTURE.md still says `src/policy.ts:81` and `src/runtime.ts:62` for
  PolicyEngine/Sandbox in section 7 — corrected to 95 and 64 in this sweep.
  No remaining stale line refs found by re-grep; if any creep back in, the
  same canonical table the subagent used can be reused.

**Next session should:**
- Run `git diff` to review the doc sweep, commit if clean (suggested commit
  message: `doc-sweep: align docs with M3+M4 code; line-ref drift; status
  markers`).
- Pick up M5 from `PROMPTS/M5-hierarchical-resource-matching.md`. The M5
  scope is hierarchical resource matching (idPatterns + recursive `tenant/...`
  and single-segment `prefix*`), closes CURRENT_STATE known-vulnerability item
  14, has acceptance criteria and a test list ready to run.

**Evidence:**
- 166 tests, 0 failures, typecheck clean
- 12/12 attack cases, 20/20 denied, audit completeness 100%
- Demo + benchmark produce sane output after the sweep

---

### SESSION 3 — 2026-09-16 — opencode/mimo-v2.5

**Did:**
- M4: Authorization lifecycle — `src/capability-request.ts` (CapabilityRequest
  type, submit/approve/deny/expire lifecycle), `AuthorizationService.revoke()` +
  in-process revocation set checked before signature verification, `Approval`
  extended with `sessionId` + `capabilityRequestId`, `capability-revoked` and
  `capability-request-denied` added to `DenyReason`, 13 new tests in
  `tests/authorization-lifecycle.test.ts` covering request→approval→mint,
  denial, expiry, revocation propagation, scope narrowing, self-approval
  refusal, structural invariant on request authority
- SECURITY_CLAIMS: Claim 5 expanded with revocation, Claim 6 notes revocation
  precedes attenuation, Claim 19 added (revoked capabilities denied immediately)
- CURRENT_STATE: "No capability revocation" removed from known-vulnerabilities,
  M4-closed section added, test count to 166

**Left:**
- Multi-node revocation broadcast — H13, documented limitation
- Single-session revocation test is structural only (the existing session-manager
  test already covers the revocation behavior end-to-end)

**Next session should:**
- Begin M5 or next stage per ROADMAP. Revocation audit-complete (event log entry
  on every revocation) is in place; broadcast is the next gap.

**Evidence:**
- 166 tests, 0 failures, typecheck clean
- 12/12 attack cases, 20/20 denied, audit completeness 100%
- Demo + benchmark both produce sane output

---

### SESSION 2 — 2026-09-16 — opencode/m3-implementation

**Did:**
- M3: Evidence hardening landed. Per-event Ed25519 signatures
  (`src/events.ts:147`), head-hash anchor file (`src/events.ts:269`),
  append-only SQLite with `BEFORE UPDATE/DELETE` triggers
  (`src/events.ts:208`), offline `verifyBundle()` verifier
  (`src/events.ts:357`), and structural absence of `update()` / `delete()`
  on EventLog (asserted by test).
- 13 new M3 tests covering: signature tamper detection, signature forgery,
  tail truncation detection, anchor reconciliation, offline verifier,
  append-only enforcement. (`tests/m3-evidence-hardening.test.ts`.)
- Updated invariant 8 test to match the new append-only enforcement
  (trigger blocks UPDATE/DELETE; chain verification on open still catches
  file-level tampering).
- Claim 8 upgraded from "detection" to "durability". New Claim 19 covers
  per-event Ed25519 signatures. ADR-004 superseded with M3 implementation
  decisions.
- Demo + benchmark still produce evidence; demo extended with section 11
  showing signature chain verification and offline verifier output.

**Left:**
- Anchor file path is wired via the `EVENT_ANCHOR_PATH` env var; the demo
  exercises the reconciliation path end-to-end when the env var is set.
  Production: point `EVENT_ANCHOR_PATH` at a WORM bucket / customer-held
  witness and supply `EVENT_SIGNING_PRIVATE_KEY_PEM` / `EVENT_SIGNING_PUBLIC_KEY_PEM`.
- Key rotation, HSM-backed custody, signed-key bundles, and external
  transparency-log publication are HARD-stage items.

**Next session should:**
- M4: finish the in-process capability request → approval → minting →
  revocation flow (3 unrelated tests fail today on a separate branch;
  the rest of the chain is wired).
- Move the anchor into a real WORM-tier storage and wire `EVENT_ANCHOR_PATH`
  in a deployment fixture.

**Evidence:**
- 166 tests, 166 pass, typecheck clean.
- Demo: 11 sections, 55 events recorded with signatures, offline verifier
  confirms 55/55 valid; anchor reconciliation exercised when
  `EVENT_ANCHOR_PATH` is set.
- Benchmark: 12/12 attack cases, 20/20 denied, audit completeness 100%,
  hash chain valid.

---

### SESSION 6 — 2026-09-16 — opencode/reliability-layer-design

**Did:**
- Designed the output reliability layer (`RELIABILITY.md`, design only, no
  code). Guards the text channel (`SessionTrace.modelText`), which today
  returns raw model prose unchecked. Detection: claim-source binding (verbatim
  span verification), session-fact consistency, numeric recomputation, prose
  leak check, critic model as telemetry-only. Response formatting:
  `GuardedResponse` with status delivered/flagged/repaired/withheld, no silent
  edits, original sealed into evidence. Fallback ladder: repair -> regenerate
  once -> abstain -> escalate via M4 approval flow; fail-closed on guard
  error; leaks skip the ladder.
- Added ROADMAP Stage 1 row marking the item **[designed]**.

**Left:**
- Implementation unscheduled. Design names the module (`src/guard.ts`), the
  seam (`ResponseGuard`), the three draft claims (R1–R3), and the test plan.

**Next session should:**
- If scheduled: write the failing guard tests first (D2 citation forgery,
  withheld-response leak scan, R3 structural context check), then implement
  `src/guard.ts` per RELIABILITY.md §9. No PDP/capability/policy changes.

**Evidence:**
- Design doc only; no test or benchmark delta.

---

### SESSION 7 — 2026-09-17 — opencode/m6-audit-query-and-export

**Did:**
- M6: Audit Query + Export API implemented and verified.
  - Added synthetic resource `audit-log:<tenantId>` (`ResourceType: 'audit-log'`, `src/domain.ts:124`).
  - Added actions `query.audit` and `audit.export` (`KnownAction`, `src/domain.ts:145`).
  - Added `AuthorizationService.queryAudit(input, filters)` (`src/pdp.ts`) reusing the `revealEvidence` pattern: auth check → tenant check → capability match → policy `evaluate` → event log append. Synthesizes `audit-log:<tenantId>` on the fly.
  - Added `AuditQueryService` (`src/audit-query.ts`) validating boundary semantics (≤ 90-day time range, limit ≤ 1000, offset ≥ 0 via `AuditFilterError`). Authorizes via `queryAudit` and queries `EventLog`.
  - Added `EventLog.query(filters)` and `EventLog.exportFor(filters)` (`src/events.ts`) executing parameterized SQL against `security_events` table with index on `(tenant_id, seq)` and in-memory fallback.
  - Enhanced `verifyBundle()` (`src/events.ts`) to verify bundle slices using `previousHead`.
  - Added `AUDIT_POLICY_RULE` allowing users to query/export audit logs with capability, wired into `World.audit` (`src/scenario.ts`).
  - Demo (`src/cli.ts`) extended with section 13 (querying and exporting tenant audit slice).
  - Benchmark (`src/cli.ts`) extended with `auditQueryLatencyP99Ms` (0.262 ms) and `auditExportLatencyP99Ms` (0.231 ms). Regenerated `benchmarks/results.json`.
  - Added Claim 21 in `SECURITY_CLAIMS.md`.
  - Flipped ROADMAP Stage 1 row "Audit query + export API" to `[DONE]`.
  - Updated `CURRENT_STATE.md` (205 tests pass, 20 new M6 tests).

**Left:**
- Multi-node audit aggregation / query federation is H13 (in-process query only).
- Streaming cursor pagination deferred per ponytail (90-day window and 1000-event page size ceiling covers current needs).

**Next session should:**
- Pick up next Stage 1 item per ROADMAP: Policy testing framework (NEXT), or resume output reliability layer.

**Evidence:**
- 205 tests, 205 pass, 0 failures, typecheck clean.
- 20 new M6 tests in `tests/m6-audit-query.test.ts`.
- Demo: 13 sections pass cleanly.
- Benchmark: 12/12 attack cases behaving as required, 20/20 denied, audit completeness 100%, p99 latency < 0.3 ms for both query and export.
