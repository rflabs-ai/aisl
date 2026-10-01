# Evidence ledger — session audit 2026-10-01, `feat/h12-secure-updates` (uncommitted working tree; no commits since midnight)

| # | ref | command run (this audit run) | raw output (exact line(s)) |
|---|---|---|---|
| F-01 | grant replay window | `node --test tests/z-probe-h12-grant-replay.test.ts` (throwaway probe, deleted; `Test-Path` → `False`) | `PROBE apply v1: true` / `PROBE apply v2: true` / `PROBE grantA first use: {"ok":true,"current":1,"mark":2}` / `PROBE apply v3: true` / `PROBE apply v4: true` / `PROBE grantB (4->2): {"ok":true,"current":2}` / `PROBE replay of used grantA: {"ok":true,"current":1,"mark":4}` / `✔ PROBE: old grant applies again after current returns to its fromVersion (1357.1079ms)` / `ℹ pass 1` / `ℹ fail 0` |
| F-01a | grant gate (code) | `Read src/updates.ts` (full file, this run) | `391:   if (grant.fromVersion !== state.current.releaseVersion) return { ok: false, reason: 'grant-mismatch', state };` |
| F-01b | single-use claim (code comment) | `Read src/updates.ts` (full file, this run) | `359:  * applied — after one use \`current\` changes and the same grant can never` / `360:  * apply again.` |
| F-01c | existing replay test (scope) | `Read tests/h12-secure-updates.test.ts` (full file, this run) | `383:       const replay = rollbackUpdate(grant, grantSig, { publicKeyPem: PUBLIC_PEM, statePath });` — immediate replay only |
| F-01d | claim in ADR-025 | `Read DECISIONS.md` offset 1506 | `1512:    replay fails \`grant-mismatch\` after first use. It never lowers` / `1514:    emergency path cannot itself become the replay path.` |
| F-01e | claim in Claim 34 | `Select-String -Path SECURITY_CLAIMS.md -Pattern "single-use\|replay\|grant-mismatch"` | `SECURITY_CLAIMS.md:1576: are signed with the same release key, single-use (from-version must equal` / `SECURITY_CLAIMS.md:1601: without lowering the mark and cannot be replayed; burned version stays` |
| F-01f | claim in ROADMAP | `Select-String ... "single-use"` | `ROADMAP.md:321: Emergency rollback is a **signed, single-use grant** naming the exact` / `ROADMAP.md:322: from-version (replay → \`grant-mismatch\`), backward-only, and it never lowers` |
| F-02 | promote display nit | `node src/cli.ts update promote ok` | `NONE   rollout                                        stage=0/-1` / `no rollout in flight — nothing to promote.` |
| F-02a | guarded sibling (status) | `Read src/cli.ts` offset 900 | `1161:       line('rollout', state.rollout.status.toUpperCase(), \`stage=${state.rollout.stageIndex}/${state.rollout.stages.length === 0 ? '-' : state.rollout.stages.length - 1}...` |
| F-03 | source-size doc claim | `node -e "...count src/*.ts lines..."` | `all lines: 11436 non-blank: 10417` / `src modules: 43 total lines: 11436` |
| F-03a | doc line | `Select-String -Path CURRENT_STATE.md -Pattern "9,900\|43 modules"` | `CURRENT_STATE.md:19: TypeScript foundation on Node 24, ~9,900 lines of source across 43 modules` |
| F-04 | sign accepts empty channel (code read) | `Read src/cli.ts` offset 900; `Read src/updates.ts` full | `cli.ts:1035:     const channel = process.argv[5] ?? 'stable';` / `updates.ts:149:   if (typeof d.channel !== 'string' || d.channel === '') return { reason: 'not-an-update' };` |
| F-05 | unused exports (grep) | `Select-String -Path src/*.ts,tests/*.ts -Pattern "initialState\|UpdateStateError"` | only `src/updates.ts` lines 111,118,232,237,241 — no external consumer |
| C-01 | typecheck | `npm run typecheck` | `> tsc --noEmit` / `TYPECHECK_EXIT=0` |
| C-02 | full test suite | `npm test` | `ℹ tests 559` / `ℹ pass 544` / `ℹ fail 0` / `ℹ skipped 15` |
| C-03 | H12 suite count | `node --test tests/h12-secure-updates.test.ts` | `ℹ tests 19` / `ℹ pass 19` / `ℹ fail 0` |
| C-04 | supply-chain gate | `npm run supply-chain` | `supply-chain gate passed.` / `SUPPLY_CHAIN_EXIT=0` |
| C-05 | demo section 21 | `npm run demo` | `21. H12: signed update channel — anti-rollback + canary halt` + six `PASS` lines + `ABSENT update state (artifacts/)` / `DEMO_EXIT=0` |
| C-06 | no banned casts in changed code | `Select-String -Path src/updates.ts,src/cli.ts,tests/h12-secure-updates.test.ts -Pattern "as any\|as never"` | (no matches) |
| C-07 | debt markers | `Select-String ... -Pattern "ponytail:\|TODO\|FIXME\|HACK"` | `updates.ts:24: * ponytail: the health signal is a caller-supplied boolean and canary cohort` |
| C-08 | rollout status enum exhaustiveness | `Select-String -Path src/updates.ts -Pattern "status === 'halted'\|status !== 'canary'\|'none' \| 'canary'"` | `89: readonly status: 'none' \| 'canary' \| 'promoted' \| 'halted';` / `218: if (!['none', 'canary', 'promoted', 'halted'].includes(String(r.status))) return null;` / `317: if (rollout.status === 'halted') return { ok: false, reason: 'halted', state };` / `318: if (rollout.status !== 'canary') return { ok: false, reason: 'no-pending-rollout', state };` |
| C-09 | callers of new exports | `Select-String -Path src/cli.ts,tests/h12-secure-updates.test.ts,src/updates.ts -Pattern "applyUpdate\(|...|loadState\("` | cli.ts:621,629,632,635,638,641,644,1087,1112,1121,1139,1158,1185,1213,1236 + tests — no broken callers |
| C-10 | stale line-count method check | `node -e "...all vs non-blank..."` | `all lines: 11436 non-blank: 10417` |
