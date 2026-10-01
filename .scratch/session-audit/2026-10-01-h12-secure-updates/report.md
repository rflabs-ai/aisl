## Verdict: needs-work  —  the "single-use" rollback grant replays after `current` returns to its from-version (probe-confirmed), falsifying the claim in five docs

Target: session audit 2026-10-01 — uncommitted working tree on `feat/h12-secure-updates` (no commits since midnight; `git log --since=midnight --oneline` empty)
Checks: typecheck pass · `npm test` 559 (544 pass, 15 PG skips, 0 fail) · H12 suite 19/19 · supply-chain gate pass · demo exits 0

## Ticketed
- 01: `.scratch/session-audit/2026-10-01-h12-secure-updates/issues/01-rollback-grant-replayable-after-rearrival.md` — used rollback grant re-applies once `current` returns to its `fromVersion` via another grant

## Findings
### Must fix (ticketed)
- [medium] `src/updates.ts:391` — a consumed grant's only freshness check is `grant.fromVersion !== state.current.releaseVersion`; nothing records a grant as used, so after apply v1→v2, grantA(2→1), apply v3→v4, grantB(4→2), replaying grantA re-applies (probe: `{"ok":true,"current":1,"mark":4}`). Falsifies `src/updates.ts:15-16/359-360`, `DECISIONS.md:1512-1514`, `SECURITY_CLAIMS.md:1576/1601`, `ROADMAP.md:321-322`. Minimal fix: monotonic `rollbackGeneration` on state + `generation` on grant, required and incremented in `rollbackUpdate`. → 01

### Should fix (ticketed)
- (none)

### Notes / nits (not ticketed)
- `src/cli.ts:1141` — promote prints `stage=0/-1` on the no-rollout path (`node src/cli.ts update promote ok` → `NONE   rollout   stage=0/-1`); the status command guards this (`src/cli.ts:1161`), promote doesn't.
- `CURRENT_STATE.md:19` — "~9,900 lines of source" vs measured 11,436 all / 10,417 non-blank (`node` count this run); counting method undocumented, prior value equally unverifiable.
- `src/cli.ts:1035` — `update sign` accepts `channel=''` (`?? 'stable'` catches only nullish); `src/updates.ts:149` then refuses that descriptor forever (`not-an-update`) — sign-time validation should reuse the structural check.
- `src/updates.ts:111,118` — `UpdateStateError` / `initialState` are exported with no external consumers (grep this run: only updates.ts references); could be module-private.
- `src/cli.ts:58` — `createPublicKey` import placed after local imports (style).
- `tests/h12-secure-updates.test.ts:412` — `assert.ok(v1.releaseVersion === 1 && v1sig.length > 0, 'v1 fixture was used')` is filler to consume destructured vars; fold into the helper or drop.
- Docs claim "single-use" in six places (updates.ts header/doc, ADR-025, Claim 34, ROADMAP, THREAT_MODEL, CURRENT_STATE); all become true when ticket 01 lands — do not soften them instead.

## Clean axes
- Correctness (rest): clean — callers of every new export traced (`Select-String` across cli.ts/tests/updates.ts, C-09); rollout enum exhaustive (`src/updates.ts:89` union vs `:218` validation vs `:317-318` gates, C-08); no `as any`/`as never` in changed files (C-06); anti-rollback, sticky halt, malformed-state refusals all exercised by tests.
- Spec adherence: clean except the single-use claim above — prompt deliverables present: CLI 7 subcommands (`src/cli.ts:1246`), npm scripts (`package.json` diff +2), gitignored state (`.gitignore` diff), demo section 21 exits 0 (C-05), docs sweep landed (ROADMAP/Claim 34/SESSION 28).
- Over-engineering: clean — no dependency changes (`package.json` diff is two scripts only; supply-chain gate pass C-04); notes F-04/F-05 are removals, not additions.
- Tests: clean — 19 cases green; red-first is historical and cannot be re-run (module exists); the replay gap is the ticket's required regression test; probe deleted (`Test-Path` → `False`).
- Docs & breadcrumbs: one stale metric (note above); ticket tracker updated this run (this report + issue 01).
- Debt markers: clean — one `ponytail:` marker, ceiling + upgrade path (`src/updates.ts:24-27`).

## Citation audit
| finding | command run | output line |
|---|---|---|
| src/updates.ts:391 | `Select-String -Path src/updates.ts -SimpleMatch "if (grant.fromVersion !== state.current.releaseVersion)"` | `391: if (grant.fromVersion !== state.current.releaseVersion) return { ok: false, reason: 'grant-mismatch', state };` |
| src/updates.ts:359 | `Select-String -Path src/updates.ts -SimpleMatch "after one use"` | `359: * applied — after one use \`current\` changes and the same grant can never` |
| DECISIONS.md:1512/1514 | `Select-String -Path DECISIONS.md -SimpleMatch "replay fails","emergency path cannot itself become the replay path"` | `1512: replay fails \`grant-mismatch\` after first use. It never lowers` / `1514: emergency path cannot itself become the replay path.` |
| SECURITY_CLAIMS.md:1576/1601 | `Select-String -Path SECURITY_CLAIMS.md -SimpleMatch "single-use (from-version must equal","without lowering the mark and cannot be replayed"` | `1576: are signed with the same release key, single-use (from-version must equal` / `1601: without lowering the mark and cannot be replayed; burned version stays` |
| ROADMAP.md:321-322 | `Select-String -Path ROADMAP.md -SimpleMatch "signed, single-use grant"` | `321: Emergency rollback is a **signed, single-use grant** naming the exact` |
| tests/h12-secure-updates.test.ts:383 | `Select-String -SimpleMatch "const replay = rollbackUpdate(grant, grantSig"` | `383: const replay = rollbackUpdate(grant, grantSig, { publicKeyPem: PUBLIC_PEM, statePath });` |
| src/cli.ts:1141 | `Select-String -SimpleMatch "result.state.rollout.stages.length - 1"` | `1141: line('rollout', result.state.rollout.status.toUpperCase(), \`stage=${result.state.rollout.stageIndex}/${result.state.rollout.stages.length - 1}...` |
| F-01 probe | `node --test tests/z-probe-h12-grant-replay.test.ts` | `PROBE replay of used grantA: {"ok":true,"current":1,"mark":4}` |
| CURRENT_STATE.md:19 | `Select-String -Path CURRENT_STATE.md -Pattern "9,900\|43 modules"` | `19: TypeScript foundation on Node 24, ~9,900 lines of source across 43 modules` |

Highest-leverage action: land ticket 01's generation counter + regression test before this branch merges — the code is the only thing that must change; the docs are already right.
