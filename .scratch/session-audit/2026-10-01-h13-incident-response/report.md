# Session audit — 2026-10-01 H13 incident-response (uncommitted session work)

## Verdict: needs-work — 4 probe-proven must-fix findings in the new incident module (channel can be permanently stalled by one bad row; cross-process preserve fails on default signing keys; import-cycle TDZ crash; global-incident evidence unreadable), gate itself green.
Target: current session's work — uncommitted changes on `feat/h13-incident-response` (22 modified + 4 new files, `git diff HEAD --stat` = `22 files changed, 1352 insertions(+), 61 deletions(-)`); no commits on this branch's own work (`git log --since=midnight --oneline` = pre-existing main history only); no pre-existing H13 `.scratch` tickets.
Checks: `npm run typecheck` pass; `npm test` 588 tests / 570 pass / 0 fail / 18 skip; `npm run demo` exit 0 (section 22 all PASS/VERIFIED/DENIED); `npm run attack` exit 0; `npm run supply-chain` pass; `npm run benchmark` exit 0 (`slo.pass=true hardFailures=0 targets=14`). Live-DB checks not runnable (Docker service start refused — ledger row 35).

## Ticketed

- 01: .scratch/session-audit/2026-10-01-h13-incident-response/issues/01-channel-stall-on-malformed-row.md — one unknown-action row permanently stalls channel sync on every node (probe-proven), append-only table means no in-band recovery
- 02: .scratch/session-audit/2026-10-01-h13-incident-response/issues/02-preserve-cross-process-key-precondition.md — CLI `incident preserve` fails closed on the default ephemeral event-signing key (probe-proven); runbook step 5 + Claim 35 promise it without naming `EVENT_SIGNING_*_PEM`
- 03: .scratch/session-audit/2026-10-01-h13-incident-response/issues/03-incident-store-pg-import-cycle-tdz.md — `incident-store-pg.ts:18` inline-type import recreates the event-store cycle; entering the module first crashes at `event-store-pg.ts:73` (probe-proven; `import type` fix probe-proven)
- 04: .scratch/session-audit/2026-10-01-h13-incident-response/issues/04-global-incident-events-unreadable.md — global engage/freeze/lift events written with `tenantId: ''` are unreachable through every authorized read path (probe-proven), so the runbook's `engage global` → `report` flow cannot work
- 05: .scratch/session-audit/2026-10-01-h13-incident-response/issues/05-revoke-session-leaves-no-local-event.md — single-target session revocation publishes to the channel but appends no event to the signed log, contradicting ADR-026's evidence-of-record rule
- 06: .scratch/session-audit/2026-10-01-h13-incident-response/issues/06-cli-evidence-commands-use-fixture-world.md — `report`/`preserve` reconstruct a fresh fixture world in SQLite mode (probe: 5 bootstrap events reported as a reconstruction) and pollute the shared chain with 2 fixture `capability.issue` events per invocation in PG mode
- 07: .scratch/session-audit/2026-10-01-h13-incident-response/issues/07-cli-non-acme-tenant-raw-crash.md — `incident report|preserve <non-acme tenant>` dies with a raw `CapabilityIssuanceError` stack (probe-proven) instead of a diagnosable refusal
- 08: .scratch/session-audit/2026-10-01-h13-incident-response/issues/08-rest-incident-sync-unwired-claim.md — DEPLOYMENT.md:373 claims the server pulls per authorized request, but no in-repo `createRestApi` caller passes `incidentSync`
- 09: .scratch/session-audit/2026-10-01-h13-incident-response/issues/09-pdp-sync-failure-counter-dead.md — `broadcastSyncFailures()`/`pdp.syncFailures` is never read; its comment promises visibility `incident status` does not actually show

## Findings

### Must fix (ticketed)

- [high] src/incident-store-pg.ts:161 — `parseChannelRow` throws before `this.maxSeq = record.seq` (line 163) and the query is `WHERE seq > ${this.maxSeq}` (line 157); a hostile/unknown row stalls `load()` forever, so freeze/revoke propagation dies permanently on that node (probe: 3 loads, `mirror=[] cursor=-1`, good row never applied). Skip-and-count the bad row instead. — issues/01-channel-stall-on-malformed-row.md
- [high] src/incident.ts:547 — `const chain = this.eventLog.verify({ publicKey });` uses this process's key; with default ephemeral keys (src/events.ts:314) a fresh CLI process gets `signature mismatch` and `preserve` throws `incident bundle failed verification` (probe-proven), while DEPLOYMENT.md:396 and SECURITY_CLAIMS.md:1635 promise the flow without naming `EVENT_SIGNING_*_PEM`. Name the precondition + make the error actionable. — issues/02-preserve-cross-process-key-precondition.md
- [medium] src/incident-store-pg.ts:18 — `import { type StoreMigration } from './event-store-pg.ts'` keeps a runtime edge that combined with event-store-pg.ts:18's value import produces `ReferenceError: Cannot access 'INCIDENT_MIGRATION' before initialization` at event-store-pg.ts:73 when the channel module is imported first (probe-proven; only import order saves scenario/tests today). One-line fix: `import type { ... }` (fix form probe-proven). — issues/03-incident-store-pg-import-cycle-tdz.md
- [medium] src/incident.ts:356 / src/pdp.ts:342 — global-scope incident events carry `tenantId: ''` and `src/audit-query.ts:81: throw new AuditFilterError('tenantId is required');` blocks every authorized reader, so `engage global` evidence can never be reconstructed/preserved (probe-proven) — the runbook's own step 2 → step 6 flow. Add a global (`'*'`) read view over `tenantId === ''` events. — issues/04-global-incident-events-unreadable.md

### Should fix (ticketed)

- [medium] src/incident.ts:433 — `this.sessions.revoke(sessionId)` + publish, no `eventLog.append`; ADR-026 (DECISIONS.md:1628) says the signed log is the evidence of record, and `revokeCapability` (incident.ts:424-428 via pdp.ts:271) does audit. Append a local event in `revokeSession`. — issues/05-revoke-session-leaves-no-local-event.md
- [medium] src/cli.ts:1367 — every `incident` command builds the full scenario world: SQLite mode `incident report` printed `5 events ... actors: authz-root:acme, user:alice` (pure fixture, presented as reconstruction) and PG mode appends 2 bootstrap `capability.issue` events per invocation (+1 for report/preserve). Minimal assembly + mode warning. — issues/06-cli-evidence-commands-use-fixture-world.md
- [medium] src/cli.ts:1442 — minting operator audit authority through the acme-scoped root makes `incident report globex 0 5` throw an uncaught `CapabilityIssuanceError: issuer may not mint capabilities in another tenant` (raw stack, exit 1). Catch and print a refusal like `updateCommand` does. — issues/07-cli-non-acme-tenant-raw-crash.md
- [medium] DEPLOYMENT.md:373 — "running server also pulls once per authorized REST request" is claimed but nothing passes `incidentSync` (only rest-api dep + the audit's own spy; sole `createRestApi` caller is tests/m15-ui.test.ts:39). Wire it or soften the sentence. — issues/08-rest-incident-sync-unwired-claim.md
- [low] src/pdp.ts:303 — `broadcastSyncFailures()` has no reader anywhere; status shows `IncidentService`'s own counter (incident.ts:489), so the comment at pdp.ts:314-315 promises visibility that does not exist. Delete or surface. — issues/09-pdp-sync-failure-counter-dead.md

### Notes / nits (not ticketed)

- tests: cross-node `unfreeze` (Claim 35 lift path) and the `revoke-caps` issuance fence (SECURITY_CLAIMS.md:1661) have NO suite test — probes P1/P6 this run pass (`P1 after lift+sync: B.isFrozen = false`, `P6 cap registered at 2000 (>1000): revoked = false`), so behavior holds; add the two cases.
- PROMPTS/H-Track/H13-incident-response.md:84 spec'd `freeze(tenantId | '*', reason, actor)` but shipped `pdp.ts:334: freeze(scope: 'tenant' | 'global', tenantId: string | undefined, reason: string, actor: string): void {`; prompt:136 CLI list has 5 subs vs the shipped 7 (prompt:223 resolution matches shipped). Prompt internal drift only; ADR-026 + code agree.
- src/pdp.ts:426-429 — `revoke-cap` apply skips the `inScope` tenant check that `revoke-caps` has (line 420), so a tenant-scoped record revokes any tenant's target id. Fail-closed direction (removes authority); note only.
- src/rest-sessions.ts:99 — `deps.sessions.revoke(id)` (owner DELETE) does not publish to the channel; incident revocation must use `incident revoke-session`. Consistent with the single-node REST posture; note only.
- src/cli.ts (revoke-cap/revoke-session branch) prints `REVOKED` without the post-flush health check `engage` performs (`broadcastOk` asymmetry).
- src/incident.ts:211 `IncidentReport.actions` is computed but never consumed by the CLI; src/incident.ts:139 `IncidentStatus.freezes` re-declares `FreezeEntry` structurally instead of importing it from pdp.
- src/pdp.ts:238 `grant(cap: Capability)` has no sync/freeze check (callers grep → only tests/invariants.test.ts:480; `evaluate` still gates authorization).
- benchmarks/results.json in this diff = regenerated by `npm run benchmark` (artifact noise).
- src/incident-store-pg.ts:118 mirror grows unbounded — fine at incident volume.
- Live-DB probes unavailable this run (Docker start refused): migration-4 application against a real Postgres, a real-DB channel round trip, and PG-mode process-exit behavior remain covered only by the skip-clean suite (`tests/h13-revocation-pg.test.ts` 3 skipped).

## Clean axes

- Correctness (broken callers): clean — `npx tsc --noEmit` exit 0 with no diagnostics after widening `buildWorld`/`testWorld` to `WorldOptions` and `RestApiDeps.incidentSync?`; full suite 588/0 fail; `grant(` callers grep → only `invariants.test.ts:480`.
- Enum exhaustiveness: clean — `RevocationAction` (incident.ts:43-49, 6 values) traced through `incident.ts:467` switch (2 cases + default → pdp) and `pdp.ts:405` switch (4 cases + default no-op) and the PG parser allowlist (`incident-store-pg.ts:91`); unknown-value behavior probed (finding 01 is about the *stall*, not a miss). `DenyReason` addition has no exhaustive consumer (`Record<DenyReason` grep → only `REASON_PRIORITY` array).
- Secrets / deps: clean — `npm run supply-chain` `supply-chain gate passed.` (25 packages, no new dep); package.json diff adds only the `incident:status` script; H13 structural invariant test (key-material + secret-canary scan over channel/events/bundle) green in suite.
- Spec adherence (prompt hard requirements): clean — typecheck+tests green, demo section 22 output matches the prompt acceptance lines (`ENGAGED ... broadcast=ok`, `DENIED ... incident-frozen in 0.553 ms`, `node B at one interval ... 1000 ms`, `VERIFIED preserve ... 8 events`), skip-list claim holds (`Select-String src\rest-*.ts -Pattern incident` → no incident route), docs sweep present (ROADMAP H13 [DONE], Claim 35, DEPLOYMENT runbook, AGENT-SESSION.md:27 SESSION 31, prompt resolution). Doc-claim exceptions are findings 02/04/08.
- Tests: convention honored — `tests/h13-incident-response.test.ts:12: These tests were written BEFORE src/incident.ts existed (red-confirmed)`; H13 suites this run: 28 tests, 25 pass, 0 fail, 3 skip-clean; two coverage gaps noted above (not silent — probe-verified).
- Docs counts: clean — measured `modules=45 lines=11741` and 588/570/18 tests vs `CURRENT_STATE.md:20/:24/:371` claims.
- Debt markers: clean — new markers carry ceiling + upgrade: `incident.ts:275 // ponytail: 1000-event page size (the M6 boundary). upgrade: cursor/stream...` and DECISIONS.md ADR-026 residual ponytail (upgrade paths named).

## Citation audit

| finding | command run | output line |
|---|---|---|
| 01 stall | `node probe-p3-stall.mts` (primed, sql stub) | `P3 verdict: good row seq=2 applied? NO - cursor stuck behind the bad row` |
| 01 cite | `Select-String -Path src\incident-store-pg.ts` | `incident-store-pg.ts:161: const record = parseChannelRow(row);` (falsification re-check: OK at expected line) |
| 02 preserve key | `node probe-p4a/p4b` | `P4 cross-process preserve: THREW IncidentEvidenceError - incident bundle failed verification: ... signature verification failed` |
| 02 cite | `Select-String -Path src\incident.ts -Pattern "const chain = this.eventLog.verify"` | `incident.ts:547: const chain = this.eventLog.verify({ publicKey });` |
| 03 cycle | `node probe-p3-stall.mts` (un-primed) | `ReferenceError: Cannot access 'INCIDENT_MIGRATION' before initialization at .../src/event-store-pg.ts:73` |
| 03 fix probe | replica `node -e import('./.../mig-b.ts')` | `entry via mig-b: OK, no crash` (inline-type control: `THREW: ReferenceError - Cannot access 'B' before initialization`) |
| 04 global | `node probe-p5-global.mts` | `P5 reconstruct with tenantId "": THREW AuditFilterError - tenantId is required` |
| 05 revokeSession | `Select-String -Path src\incident.ts -Pattern "revokeSession"` | `incident.ts:433: this.sessions.revoke(sessionId);` (no append in body) |
| 06 fixture | `node probe-p2-bootstrap.mts` + `node src/cli.ts incident report acme 0 5` | `P2 bootstrap events on plain buildWorld: 2 {"capability.issue":2}` / `OK reconstruction 5 events ... actors: authz-root:acme, user:alice` |
| 07 non-acme | `node src/cli.ts incident report globex 0 5` | `CapabilityIssuanceError: issuer may not mint capabilities in another tenant` at `cli.ts:1442:27`, `exit=1` |
| 08 unwired | `Select-String -Pattern "incidentSync"` + `"createRestApi\("` | only `rest-api.ts:165/197/209/316` + test spy `:377`; callers = `rest-api.ts:182` (def), `m15-ui.test.ts:39` |
| 09 dead counter | `Select-String -Pattern "broadcastSyncFailures\|syncFailures"` | `pdp.ts:303: broadcastSyncFailures(): number {` — no reader; `incident.ts:489` reads a different counter |
| counts | `Get-ChildItem src -Filter *.ts` + counts | `modules=45 lines=11741` vs `CURRENT_STATE.md:20` |
| gate | `npm test` | `ℹ tests 588` `ℹ pass 570` `ℹ fail 0` `ℹ skipped 18` |

Self-falsification: every quoted line above re-checked against the working tree in this run (`Select-String` re-verification pass: 12/12 expected-line OK after correcting one reconstructed quote in ledger row 16 and ticket 02 — `incident.ts:547` verified as `this.eventLog.verify({ publicKey })`, not the reconstructed form). Probe files deleted after capture (ledger keeps raw output).

**Highest-leverage action:** fix ticket 01 (skip-and-count malformed channel rows) — it converts the kill-switch propagation channel from "permanently bricked by one bad row" back to a channel that degrades loudly instead.
