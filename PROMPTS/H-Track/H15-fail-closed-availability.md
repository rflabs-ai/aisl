# H15 — Fail-closed availability engineering (ROADMAP Stage 2)

Status: [x] **[DONE]** (ADR-027) — executed 2026-10-02; resolution record at the
bottom.

Spec of record: ROADMAP.md "H15" — attack surface: the failure modes of the
safety mechanisms themselves; failure modes: a broken policy engine, a full
disk, or a closed evidence store denies **everything, silently, per decision**
— no health signal, no degraded mode, no budget, no alerting; assumptions:
fail-closed stays the default, degradation must never widen authority; test
methodology: fault injection per dependency (engine throws, store unwritable,
clock stalled), assert deny + a distinct `denyReason` + an emitted health
signal, measure decision latency p99 with and without persistence, define and
test the degraded mode explicitly; residual: an adversary who can induce the
failure gets a DoS — make it loud, bounded, recoverable. Federation flag:
structurally necessary at federation (ADR-022) — M18's unattended raven runs
fail-closed with no operator watching (H13/H15).

Baseline: `idp-unavailable` + `IdPHealth` (M2); `store-unavailable` +
`StoreUnavailableError` mapping + per-deny `process.emitWarning` for typed
Postgres failures (M12); `GET /healthz` → `{ idp, store }` (M14, `storeHealth`
probe, default `'ok'`); `evaluation-error` deny catch-all in
`AuthorizationService.evaluate` (no health signal). Known gaps (CURRENT_STATE
#13): engine faults and non-typed store write failures are silent (no health
signal, no degraded-mode record); a stalled/non-monotonic clock is undetected
and silently stops expiry checks; no decision-latency budget; per-deny warning
spam instead of one loud event. Two ordering defects found at seam-mapping:
`issue()` registers authority before its issuance event (store outage ⇒
unaudited authority), and a store outage during `IncidentService.engage`
aborts the kill switch mid-way (`freeze`'s append throws before `revokeAll`).

Zero new runtime dependencies. `node:crypto` not needed; `performance.now`
(global) is the default monotonic reference for trend detection.

## Phase 0 — ADR-027 (docs only, landed first)

ADR-027 ("Fail-closed availability — loud degradation, observed health, clock
guard") decides:

- **Degraded mode is explicit, per-dependency, deny-only, loud, bounded,
  recoverable.** Matrix: IdP unreachable (M2, unchanged); store unavailable
  (`store-unavailable` typed / `evidence-write-failure` other write failures);
  engine broken (`evaluation-error` + health signal); clock fault
  (`clock-unavailable`, new `DenyReason` member). Degradation never widens
  authority.
- **`HealthState` (`src/health.ts`) is observed, not probed**: the PDP marks
  `store`/`engine`/`clock` `ok | unavailable` from what the decision path
  actually experiences; transitions emit one loud signal (default
  `process.emitWarning`), once per transition — the M12 per-deny warning
  becomes transition-based. IdP health stays probe-based in
  `IdentityProvider`.
- **`ClockGuard` (`src/health.ts`)**: lenient (default) catches throw /
  non-finite reads; trend detection (stall vs injected monotonic source,
  backward jump) is opt-in — deterministic test clocks freeze and travel
  backward by design. Production wiring:
  `new ClockGuard(Date.now, { monotonic: () => performance.now() })`.
- **Evidence before authority**: `issue()` appends the issuance event first,
  registers the capability only after the append succeeds.
- **The kill switch survives a store outage**: `engage` completes freeze +
  `revokeAll` + session revocation even when evidence appends fail;
  `revokeAll` continues past per-capability evidence failures;
  `evidenceRecorded: false` reports missed evidence honestly.
- **`GET /healthz` body → `{ idp, store, engine, clock }`** when a
  `HealthState` is wired (additive; M14 shape preserved otherwise).
- **Decision-latency budget measured** in the benchmark (p99 with persistence
  = SQLite-file `EventLog`, without = in-memory `EventLog`), two advisory SLO
  rows (ADR-014: latency never fails the build).
- **Rate limiting stays deployment territory** — the named M14 non-goal is
  resolved as such (reverse proxy owns it; DEPLOYMENT.md).

## Phase 1 — `src/health.ts` (primitives)

- `HealthState`: `mark(dep, status, detail?)`, `snapshot(): { store, engine,
  clock }`, transition callback (default `process.emitWarning`), emits only
  on change (down AND recovery). Detail strings carry no secrets.
- `ClockGuard`: `read(): { ok: true; at: number } | { ok: false; detail: string }`.
  Constructor `(wall: () => number, opts?: { monotonic?: () => number;
  stallAfterMs?: number })`. Trend detection only when `monotonic` is present.
- `AuthorizationService` keeps its constructor (existing positional callers
  unchanged); the H15 seams are installed with setters, matching the class's
  existing `setBroadcastSync` pattern: `setHealth(health)` + `healthState`
  getter and `setClockGuard(guard)`. Defaults: one owned `HealthState`, one
  lenient `ClockGuard(this.now)`. (The initially drafted trailing constructor
  params were not used — audit ticket 07.)

## Phase 2 — PDP fault mapping + safety-mechanism ordering (tests first)

- `authorize` / `queryAudit`: the clock read goes through the guard; a fault
  denies `clock-unavailable` + marks `clock` unavailable (deny event still
  appended when the store works).
- Store: append success marks `store` ok; append failure marks `store`
  unavailable + transition warning (replacing the per-deny warning);
  `store-unavailable` (typed) / `evidence-write-failure` mapping unchanged.
- Engine: `engine.evaluate` throw marks `engine` unavailable, denies
  `evaluation-error`; success marks `engine` ok. The broad outer catch stays
  for non-engine errors (no engine mark).
- `issue()`: guarded clock read; append-first ordering; a failed issuance
  append refuses the mint (no registration) with a refusal naming the store
  failure.
- `revokeAll()`: continues past per-capability evidence-write failures (the
  kill switch completes); failures counted and reported.
- `IncidentService.engage()`: local enforcement (freeze + revokeAll + session
  revokes) completes when evidence appends fail; the result carries
  `evidenceRecorded: boolean`; the channel outcome reporting is unchanged.

## Phase 3 — REST, world wiring, benchmark (tests first)

- `RestApiDeps.health?: HealthState` — when wired, `/healthz` body is
  `{ idp, store, engine, clock }`; otherwise the M14 shape is unchanged.
- `World` exposes `health` (the `HealthState` wired into its `AuthorizationService`).
- Benchmark: `evidence.decisionLatencyP99WithPersistenceMs` /
  `evidence.decisionLatencyP99WithoutPersistenceMs` (1000 `authorize()` calls
  per mode, dedicated mini stacks, tmpdir SQLite file), advisory SLO rows
  `decision-latency-p99-with-persistence` / `decision-latency-p99-without-persistence`.
- Demo: section 23 (`H15: fail-closed availability — fault injection,
  degraded mode, recovery`) — inject engine/store/clock faults against a
  world, show deny + distinct reason + health snapshot, show recovery;
  exits 0.

## Hard requirements (never simplify away)

- **Every fault class denies with its own reason AND emits a health signal on
  the transition**: `evaluation-error` (engine), `store-unavailable` /
  `evidence-write-failure` (store), `clock-unavailable` (clock). Degradation
  is deny-only — a fault must never produce an allow.
- **Recovery is automatic and loud**: the first successful call after a fault
  marks the dependency `ok` and emits the recovery transition.
- **No unaudited authority**: `issue()` registers a capability only after its
  issuance event is recorded.
- **The kill switch completes under a store outage**: local freeze +
  revocations apply even when their events cannot be recorded; missed
  evidence is reported (`evidenceRecorded: false`), never silent.
- **Trend detection cannot break deterministic clocks**: without an injected
  monotonic source, frozen/backward test clocks keep working (M10
  false-denial budget).
- **No secrets in health details, warnings, or refusals** (structural test).
- **No new authority path and no new runtime dependencies.**

## Tests / acceptance

- `tests/h15-fail-closed-availability.test.ts` written FIRST, red-confirmed
  before `src/health.ts` exists: per-fault matrix (engine throws, store
  unwritable typed + untyped, clock throw/NaN/stalled/backward) asserting deny
  + distinct `denyReason` + health snapshot transition + emitted transition
  signal; recovery per fault (next good call → `ok` + recovery signal); the
  degraded-mode "what still works" cases (IdP outage + system principals;
  store outage + fail-closed floor); `issue()` store-outage refusal leaves no
  registered authority; `revokeAll` completes under evidence failure;
  `engage` under store outage completes local enforcement and reports
  `evidenceRecorded: false`; `/healthz` with `HealthState` shows the four
  statuses and stays secret-free; strict clock guard does not fire on
  frozen/backward clocks without the monotonic source; structural invariant —
  health details and fault messages carry no secret values.
- Full gate green: `npm run typecheck && npm test`.
- `npm run demo` exits 0 with section 23 visible; `npm run benchmark` exits 0
  with the two latency rows reported (advisory).
- ROADMAP H15 → [DONE]; working order next: H14 / H-Track remainder.

## Docs sweep

- ROADMAP: H15 heading [DONE] (ADR-027) + mechanism paragraph; working order.
- CURRENT_STATE: counts, what-works entry, "What H15 closed", gap #13 (and the
  rate-limiting named non-goal resolved), header frontier.
- DECISIONS.md: ADR-027 (landed in Phase 0).
- SECURITY_CLAIMS.md: new claim — loud, bounded, recoverable fail-closed
  degradation + observed health + latency budget.
- THREAT_MODEL.md / TM-004: safety-mechanism failure row + controls.
- DEPLOYMENT.md: health/degraded-mode runbook (healthz statuses, warning
  stream, clock-guard wiring, rate limiting = reverse proxy).
- COMPLIANCE.md: availability/IR rows if present.
- AGENT-SESSION.md: session entry.
- This prompt: resolution record at the bottom.

## Constraints

- No `as any` / `as never`; fault messages typed narrowly — a malformed
  reading is a refusal (deny), not a cast.
- No runtime or dev dependency additions.
- No secrets in logs/events/errors/warnings.
- Every deliberate ceiling carries a `ponytail:` marker naming the ceiling
  and the upgrade path.

## Acceptance + skip list

Acceptance: ADR-027 first; tests red-then-green; gate green; demo exits 0 with
the section; benchmark exits 0 with the latency rows; ROADMAP row [DONE];
docs updated.

skipped: per-dependency deny reason for engine faults (reuses
`evaluation-error`; split `engine-unavailable` when an on-call rotation needs
it — `ponytail:` marker in ADR-027); health events inside the signed chain
(fault storms would flood the evidence chain; warnings + healthz are the live
signals); in-process rate limiting (deployment territory, named in ADR-027 +
DEPLOYMENT); health-state persistence across restart (in-memory, re-marked on
the next observed fault); alert routing/paging (operators wire alerts to the
warning stream + `/healthz`); circuit breaking / retry-until-allow (fail-closed
means deny, not retry — retry-until-allow is a fail-open behavior by another
name). add when: a real on-call rotation or a second node's health aggregator
asks for them.

---

## Resolution (executed 2026-10-02)

- ADR-027 landed in `DECISIONS.md` first (Phase 0, docs only). The prompt above
  was expanded to the full M4–M16 format before code. Tests were written
  before `src/health.ts` existed; the red signal (`ERR_MODULE_NOT_FOUND`
  without the module) was verified by the 2026-10-02 audit probe, not captured
  during the build (audit ticket 02).
- Shipped: `src/health.ts` (`HealthState` observed-health tracker with
  transition-only emission; `ClockGuard` lenient-by-default with opt-in
  stall/backward detection via an injected monotonic reference);
  `src/pdp.ts` (`readClock` + `clockFaultDeny`, engine/store health marks,
  evidence-before-authority `issue()`, evidence-before-lift `unfreeze`,
  resilient `revokeAll`, `setHealth`/`healthState`/`setClockGuard`);
  `src/domain.ts` (`clock-unavailable`); `src/incident.ts`
  (`evidenceRecorded`, optional `eventSeq`, engage/lift resilience);
  `src/rest-api.ts` (`health` dep → four-status `/healthz`);
  `src/scenario.ts` (`World.health`); `src/slo.ts` + `src/cli.ts` (decision
  p99 with/without persistence; demo section 23).
- Two ordering defects found while mapping seams and closed with tests:
  `issue()` registered authority before its issuance event (a store outage
  left unaudited authority live), and a store outage aborted `engage` mid-way
  (`freeze`'s evidence append threw before `revokeAll` ran). The symmetric
  rule now holds: **widening state changes (issue registration, unfreeze)
  record evidence first; narrowing changes (freeze, revoke) apply first and
  report missed evidence.**
- Contract detail from the tests: the M12 per-deny `process.emitWarning`
  became transition-based (one loud event per down/recovery); health details
  are fixed labels, never error messages (the structural invariant test pins
  it with a canary).
- Gate: `npm run typecheck` clean; `npm test` 622 tests / 603 pass / 19
  Postgres-mode skips / 0 fail (24 H15 tests; audit-follow-up run). `npm run
  demo` exits 0
  with section 23 visible (`store-unavailable` + health snapshot + recovery,
  `clock-unavailable`). `npm run benchmark` exits 0, 0 hard SLO failures,
  decision p99 advisory (latest run ~3.3 ms with persistence / ~0.1 ms
  without; run-to-run noise).
- Docs: ROADMAP (H15 [DONE] + mechanism, working order → H14/remaining),
  CURRENT_STATE (header, counts 46 modules / ~12,358 lines / 622 tests, what
  exists, What H15 closed + audit follow-up, gap #13, rate-limiting non-goal
  resolved),
  SECURITY_CLAIMS Claim 36, THREAT_MODEL (safety-mechanism + resource rows),
  DEPLOYMENT (degraded-mode runbook + clock wiring + rate limiting),
  AGENT-SESSION SESSION 34.
- Residuals (ADR-027/Claim 36): in-memory health resets to `ok` on restart
  (re-marked on the next observed fault); clock trend detection needs the
  embedder's monotonic wiring (DEPLOYMENT); the engine-fault reason stays
  shared (`evaluation-error`) with a `ponytail:` marker; alert routing and
  rate limiting are deployment concerns; an induced fault remains an accepted
  DoS — now loud, bounded, and recoverable.
- Branch: work landed in `main`'s working tree; audit follow-up below.

## Audit follow-up (2026-10-02)

The same-day session audit
(`.scratch/session-audit/2026-10-02-h15-fail-closed-availability/`) found
1 must-fix + 3 should-fix + 4 nits; all 8 tickets were fixed on branch
`fix/h15-audit-follow-ups`:

- **01 (must):** `syncBroadcast` ran before the guarded clock read and read
  the raw clock, so with the production broadcast hook installed
  (`IncidentService`) a faulted clock crashed `authorize`/`issue` instead of
  denying `clock-unavailable` (probe-proven on both paths). The sync body now
  try/catches its clock reads; `readClock` owns the fault. Regression test
  added.
- **02:** "red-confirmed" claims corrected at four sites — the red signal
  (`ERR_MODULE_NOT_FOUND` without `src/health.ts`) was verified by the audit
  probe, not captured during the build.
- **03:** `issue()`'s clock-fault refusal now appends its audited
  `capability.issue` deny event (mirrors the freeze/custody refusals).
- **04:** PROJECT_CONTEXT's module map gains the `health.ts` row.
- **05:** grant/consume/revoke/freeze use a fault-tolerant `bookkeepingNow()`
  — a clock fault cannot disable the kill switch or leave a single-use
  capability unconsumed (timestamps there are bookkeeping, never authority).
- **06:** `clockFaultDeny` marks store `ok` on its successful append.
- **07:** the prompt's Phase 1 constructor-param text is corrected to the
  shipped setters.
- **08:** `queryAudit`'s clock-fault branch gained its test.

Suite: 24 cases (19 + 5 regressions). Gate re-run green (622/603/0/19).