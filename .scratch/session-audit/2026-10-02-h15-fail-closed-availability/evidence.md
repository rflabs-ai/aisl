# Evidence ledger — session audit 2026-10-02 (H15 fail-closed availability, uncommitted working tree)

All commands run in this audit session, after the last source edit. Probe files deleted after capture.

| # | ref | command run | raw output (paste the exact line(s)) |
|---|---|---|---|
| 1 | target | `git status --short` | ` M AGENT-SESSION.md` … ` M src/slo.ts`, `?? src/health.ts`, `?? tests/h15-fail-closed-availability.test.ts`, ` D PROMPTS/M18-federation-project-raven.md` (M18 deletion pre-existing, excluded) |
| 2 | commits | `git log --since=midnight --oneline` | (empty — no commits today; target is the uncommitted tree) |
| 3 | scope | `git diff HEAD --stat` (tail) | `17 files changed, 1127 insertions(+), 299 deletions(-)` + 2 untracked (`src/health.ts`, `tests/h15-fail-closed-availability.test.ts`) |
| 4 | check | `npm run typecheck` | exit 0, no output beyond the tsc banner |
| 5 | check | `npm test` (fresh) | `ℹ tests 617` / `ℹ suites 175` / `ℹ pass 598` / `ℹ fail 0` / `ℹ skipped 19` |
| 6 | 01 cite | `Grep "syncBroadcast\(false\)\|syncBroadcast\(true\)\|const clock = this.readClock" src/pdp.ts` | `pdp.ts:556: this.syncBroadcast(false);` / `pdp.ts:559: const clock = this.readClock();` / `pdp.ts:221: this.syncBroadcast(true);` / `pdp.ts:223: const clock = this.readClock();` |
| 7 | 01 cite | `Grep "this\.now\(\)" src/pdp.ts` | `pdp.ts:406: if (!force && this.now() - this.lastSyncAt < this.syncIntervalMs) return;` / `pdp.ts:407: this.lastSyncAt = this.now();` |
| 8 | 01 cite | `Grep "setBroadcastSync" src/incident.ts` | `incident.ts:379: this.authorization.setBroadcastSync((force) => {` (production wiring installs the hook) |
| 9 | 01 probe | `node --test tests/zz-audit-probe-clock.test.ts` (deleted after) | `PROBE authorize THREW -> clock source dead` / `PROBE issue THREW -> Error : clock source dead` / `PROBE SUMMARY authorize=threw issue=threw` |
| 10 | 02 probe | `Move-Item src\health.ts $env:TEMP\...; node --test tests/h15-fail-closed-availability.test.ts; Move-Item back; Test-Path src\health.ts` | `Error [ERR_MODULE_NOT_FOUND]: Cannot find module '...\src\health.ts' imported from ...\src\pdp.ts` / restore: `True` |
| 11 | 02 cite | `Grep "red-confirmed\|red-first" tests PROMPTS CURRENT_STATE AGENT-SESSION` | `tests/h15-fail-closed-availability.test.ts:13: * These tests were written BEFORE src/health.ts existed (red-confirmed)` / `PROMPTS/H-Track/H15-fail-closed-availability.md:205: ... before `src/health.ts` existed (red-confirmed by `node --test`: the module` / CURRENT_STATE:1103 region + AGENT-SESSION:44 ("Tests first (red)") |
| 12 | 03 cite | `Select-String src\pdp.ts -Pattern "if \(!clock.ok\) \{" -Context 0,3` | `pdp.ts:224: if (!clock.ok) {` / `pdp.ts:225: throw new CapabilityIssuanceError(\`clock unavailable, capability issuance refused: ${clock.detail}\`);` / `pdp.ts:226: }` — no `eventLog.append` in the branch |
| 13 | enum-exh | `Grep "denyReason ===\|denyReason\?\.|switch \(.*denyReason" src` | only `cli.ts:701,712,790,809` demo comparisons; no exhaustive switch/filter over DenyReason |
| 14 | callers | `Grep "\.eventSeq" *.ts` | (no matches — `eventSeq` has zero consumers; optional-typing it broke nothing) |
| 15 | callers | `Grep "new AuthorizationService\(" src` | 7 sites, all 4–5-arg positional form (constructor signature unchanged; typecheck green) |
| 16 | debt | `git diff HEAD \| Select-String '^\+.*(ponytail:\|TODO\|FIXME\|HACK)'` | 5 hits, all in docs (DECISIONS/CURRENT_STATE/SECURITY_CLAIMS/PROMPTS), each naming a ceiling + upgrade path; no TODO/FIXME/HACK in code |
| 17 | docs | `Grep "incident\.ts\|health\.ts" PROJECT_CONTEXT.md` | `PROJECT_CONTEXT.md:91:   incident.ts         kill switch + revocation channel + evidence preservation (H13, ADR-026)` — module map has no `health.ts` row |
| 18 | docs | `Select-String README.md,ARCHITECTURE.md -Pattern 'H13\|H15\|health'` | (no matches — neither file enumerates milestones; nothing to update) |
| 19 | check | `npm run demo` (fresh) | `23. H15: fail-closed availability — fault injection, degraded mode, recovery` + 4 lines (ALLOW healthy / DENIED store-unavailable / ALLOW recovery / DENIED clock-unavailable); `DEMO EXIT: 0` |
| 20 | check | benchmark — re-run inside `npm test` (slo.test execFileSync gate) + read artifact | `benchmarks/results.json:34: "decisionLatencyP99WithPersistenceMs": 3.304,` / `:35: "decisionLatencyP99WithoutPersistenceMs": 0.113,` (fresh run; session-time values 1.635/0.226 were advisory samples) |
| 21 | note cite | `Select-String src\pdp.ts -Pattern "get healthState\|setHealth\|setClockGuard"` + `Select-String PROMPTS\...\H15... -Pattern "constructor gains"` | `pdp.ts:150 setHealth / :155 get healthState / :160 setClockGuard` vs `PROMPTS/H-Track/H15-fail-closed-availability.md:79: - \`AuthorizationService\` constructor gains two optional trailing params:` (API drift; Resolution records setters) |
| 22 | rest cite | `Grep "snapshot\(\)" src/rest-api.ts` | `rest-api.ts:223: ? { idp: this.idp.getIdPHealth().status, ...this.health.snapshot() }` |
