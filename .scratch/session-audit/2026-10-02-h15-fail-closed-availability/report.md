# Session audit — H15 fail-closed availability (uncommitted working tree)

## Verdict: needs-work — one must-fix: the production broadcast hook makes a faulted clock crash the decision path instead of denying `clock-unavailable` (probe-proven on both `authorize` and `issue`)

Target: current session's work — uncommitted H15 changes (`git status`: 15 M + 2 untracked; `git log --since=midnight` empty; the `PROMPTS/M18-federation-project-raven.md` deletion and ROADMAP M-Track path predate this session and are excluded per AGENT-SESSION SESSION 34 "Left").

Checks:
- `npm run typecheck` — pass (exit 0)
- `npm test` — pass: 617 tests / 598 pass / 0 fail / 19 Postgres-mode skips (fresh run)
- `npm run demo` — pass: exit 0, section 23 visible (fresh run)
- benchmark — pass via `npm test`'s slo gate (execFileSync) + fresh `benchmarks/results.json` with both new metrics (3.304 / 0.113 ms, advisory)

## Ticketed

- 01: `.scratch/session-audit/2026-10-02-h15-fail-closed-availability/issues/01-syncbroadcast-bypasses-clock-guard-crashes-decision-path.md` — faulted clock + installed broadcast hook → uncaught throw in `authorize`/`issue` (probe-proven)
- 02: `.../issues/02-red-confirmed-claims-not-backed-by-a-run.md` — "red-confirmed" claims at 4 sites; red verified only by this audit's probe, not during the build
- 03: `.../issues/03-issue-clock-fault-refusal-unrecorded.md` — `issue()` clock-fault refusal appends no evidence event (contrast freeze/custody refusals)
- 04: `.../issues/04-project-context-module-map-missing-healthts.md` — PROJECT_CONTEXT module map has no `health.ts` row

## Findings

### Must fix (ticketed)
- [high] `src/pdp.ts:556` / `:221` — `syncBroadcast()` runs before the guarded `readClock()` and reads `this.now()` unguarded (`src/pdp.ts:406-407`); with the production hook (`src/incident.ts:379`) a faulted clock makes both `authorize` and `issue` throw uncaught — probe: `PROBE authorize THREW -> clock source dead`. The REST dispatcher maps that to a 500 with no deny event or health transition. Fix: try/catch the clock reads inside `syncBroadcast`; add a hook-installed clock-fault test. — issues/01-…

### Should fix (ticketed)
- [medium] `tests/h15-fail-closed-availability.test.ts:13`, PROMPTS/H15:205, CURRENT_STATE, AGENT-SESSION — "red-confirmed"/"Tests first (red)" claims; no red run occurred during the build (audit probe `ERR_MODULE_NOT_FOUND` is the only red evidence). Amend wording to the probe-verified phrasing. — issues/02-…
- [medium] `src/pdp.ts:225` — clock-faulted `issue()` throws with no appended refusal event, unlike the freeze/custody refusals in the same function and `clockFaultDeny`. Append the audited refusal (try/catch). — issues/03-…
- [low] `PROJECT_CONTEXT.md:91` — module map lists `incident.ts` but not `health.ts`; map status still ends at H13. — issues/04-…

### Notes / nits (not ticketed)
- `consume()`/`freeze()`/`revoke()` read `this.now()` unguarded (`src/pdp.ts:342/357/364/434`): a faulted clock throws raw there (pre-existing pattern, not an H15 regression; `consume`'s throw after execution leaves a single-use capability unconsumed — worth a follow-up if a clock-fault window can span execute→consume).
- `clockFaultDeny` appends the deny event but never marks store `ok` on success — store health lags until the next normal decision. Cosmetic.
- Prompt/spec drift: PROMPTS/H15:79 says "constructor gains two optional trailing params" but setters shipped (`src/pdp.ts:150/155/160`); the Resolution section records the shipped API. Harmless once the Resolution is read.
- No test exercises `queryAudit` clock fault or `issue()` clock fault (03's fix adds the latter).
- Lenient `ClockGuard` writes `this.lastWall` that lenient mode never reads — dead state, harmless.

## Clean axes
- Correctness (beyond 01/03): clean — typecheck green; `new AuthorizationService(` grep → 7 call sites, all unchanged 4–5-arg form; `.eventSeq` grep → zero consumers (optional-typing broke nothing); no data-loss path introduced (fail-closed direction verified by the 19-test suite).
- Enum-exhaustive: clean — `DenyReason` gained `clock-unavailable`; grep over `denyReason ===` / switches in `src/` → only `cli.ts:701,712,790,809` demo comparisons, no exhaustive filter that could silently miss the new value.
- Spec adherence: clean — ADR-027's matrix, fault injection per dependency, health transitions, `/healthz` four-status body (`rest-api.ts:223`), latency budget (results.json:34-35), degraded-mode tests, demo section 23, docs sweep all present; the one deviation (constructor params → setters) is recorded in the prompt Resolution (nit above).
- Over-engineering: clean — `src/health.ts` is two small classes with default-bearing options; no interface-with-one-impl, no new dependencies (package.json untouched), no dead code beyond the noted `lastWall` write.
- Tests: convention honored — 19 new cases in `tests/h15-fail-closed-availability.test.ts`, red signal probe-verified (issues/02 records the caveat); full suite 617/598/0 fresh.
- Debt markers: clean — `git diff HEAD` marker grep → 5 hits, all in docs, each naming a ceiling and an upgrade path; no TODO/FIXME/HACK in code.
- Docs (beyond 04): clean — ROADMAP/CURRENT_STATE/DECISIONS/SECURITY_CLAIMS/THREAT_MODEL/DEPLOYMENT all updated; README and ARCHITECTURE enumerate no milestones (grep → no H13/H15/health matches), nothing to update there.

## Citation audit
| finding | command run | output line |
|---|---|---|
| pdp.ts:556 syncBroadcast-before-readClock | `Grep "syncBroadcast\(false\)\|const clock = this.readClock" src/pdp.ts` | `pdp.ts:556: this.syncBroadcast(false);` / `pdp.ts:559: const clock = this.readClock();` |
| pdp.ts:406-407 unguarded clock reads | `Grep "this\.now\(\)" src/pdp.ts` | `pdp.ts:407: this.lastSyncAt = this.now();` |
| incident.ts:379 production hook | `Grep "setBroadcastSync" src/incident.ts` | `incident.ts:379: this.authorization.setBroadcastSync((force) => {` |
| 01 crash behavior | `node --test tests/zz-audit-probe-clock.test.ts` (deleted after) | `PROBE authorize THREW -> clock source dead` / `PROBE issue THREW -> Error : clock source dead` |
| 02 red-claim site | `Grep "red-confirmed" tests` | `tests/h15-fail-closed-availability.test.ts:13: * These tests were written BEFORE src/health.ts existed (red-confirmed)` |
| 02 red probe | move health.ts aside → `node --test tests/h15-...` → restore | `Error [ERR_MODULE_NOT_FOUND]: Cannot find module '...\src\health.ts' imported from ...\src\pdp.ts` |
| 03 unrecorded refusal | `Select-String src\pdp.ts -Pattern "if \(!clock.ok\)" -Context 0,3` | `pdp.ts:225: throw new CapabilityIssuanceError(\`clock unavailable, capability issuance refused: ${clock.detail}\`);` (no `eventLog.append` in branch) |
| 04 stale map | `Grep "incident\.ts\|health\.ts" PROJECT_CONTEXT.md` | `PROJECT_CONTEXT.md:91:   incident.ts         kill switch + revocation channel + evidence preservation (H13, ADR-026)` |
| enum-exhaustive | `Grep "denyReason ===" src` | `cli.ts:701/712/790/809` comparisons only |
| checks | `npm run typecheck` / `npm test` / `npm run demo` | exit 0; `ℹ tests 617 / pass 598 / fail 0 / skipped 19`; `DEMO EXIT: 0` |
| latency metrics | `Select-String benchmarks\results.json -Pattern 'decisionLatencyP99'` | `results.json:34: "decisionLatencyP99WithPersistenceMs": 3.304,` / `:35: "decisionLatencyP99WithoutPersistenceMs": 0.113,` |

Self-falsification: all seven key quoted strings re-verified at their cited lines in this run (`Select-String -SimpleMatch` pass: pdp.ts:556/407/225, incident.ts:379, tests/h15:13, PROJECT_CONTEXT.md:91, results.json:34 — all hit). Probe files deleted after capture; raw outputs live in `evidence.md`.

Highest-leverage action: fix issues/01 — three lines inside `syncBroadcast` restore H15's core contract on the deployed path.

---

## Resolution (bae96bb, 2026-10-02)

All 8 tickets fixed on branch `fix/h15-audit-follow-ups` (commit `bae96bb`):
the must-fix `syncBroadcast` bypass, the `issue()` clock-fault evidence
event, `bookkeepingNow()` for grant/consume/revoke/freeze, `clockFaultDeny`
store-health recovery, the `queryAudit` clock-fault test, and the three doc
corrections (red-claim wording, prompt Phase 1 drift, PROJECT_CONTEXT map).
5 regression tests added (H15 suite now 24). Gate re-run green on the commit
(pre-commit hook): 622 tests / 603 pass / 0 fail / 19 Postgres-mode skips;
demo and benchmark exit 0. Ticket files carry `Status: resolved (bae96bb)`.
