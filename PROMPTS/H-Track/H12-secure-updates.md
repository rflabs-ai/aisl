# H12 — Secure updates (ROADMAP Stage 2)

Status: [x] **[DONE]** (ADR-025) — executed in this session; resolution record
at the bottom.

Spec of record: ROADMAP.md "H12" — attack surface: update channel, signing
keys, rollback behaviour; failure modes: rollback to a vulnerable version,
unsigned update, update as remote code execution with high privilege;
assumptions: versioned, signed, staged rollout, emergency rollback exists;
test methodology: signature verification tests, rollback prevention tests,
staged rollout with automated canary and auto-halt; residual: a signed but
malicious release.

Baseline: H10 (ADR-024) landed — `src/supply-chain.ts` signs/verifies an
Ed25519 build manifest binding `treeDigest`/`sbomDigest`/gate result, and
DECISIONS.md:1471 makes it the update-verification primitive ("signed updates
verify the manifest signature, not a hash somebody pasted in a chat"). M11
policy/role bundles are hash-verified integer-versioned bundles
(`src/policy-config.ts`) — the versioning pattern to extend. 527 tests. What
does not exist: no update descriptor or signed release channel, no
anti-rollback (nothing persists a high-water mark — an old, still-valid
artifact replays cleanly), no rollout state machine, no canary/halt, no
app-level version identity outside `package.json` `0.1.0`.

Zero new runtime dependencies. `node:crypto` (Ed25519, same posture as
`signManifest`), `node:fs`, `canonicalJson` from `src/domain.ts`. A
supply-chain module that added a dependency to defend the update channel
would be the same self-defeating joke ADR-024 refused.

## Phase 0 — ADR-025 (docs only)

ADR-025 must decide:

- **The update artifact of record.** A signed **update descriptor** binding a
  release: `{ type: 'asl-update', version: 1, releaseVersion, channel,
  stages, manifest, manifestSignature, issuedAt, issuedBy }`, Ed25519 over
  `canonicalJson(descriptor)` with the H10 release key. The descriptor embeds
  the build manifest + its H10 signature — verification chains to
  `verifyManifest` (recomputes live tree/SBOM digests), so an update is only
  as trustworthy as the H10 gate it carries. `releaseVersion` is a monotonic
  integer (the M11 bundle pattern), not semver: ordering must be decidable
  without a registry.
- **Rollback prevention.** A persisted `UpdateState` file with a
  `highWaterMark`. `apply` requires `releaseVersion > highWaterMark` and
  raises it; the mark never lowers. Replaying any descriptor whose version is
  at or below the mark is refused (`rollback-blocked`) even when its
  signature and manifest are perfectly valid — that refusal is H12's core
  control. State is code-written only, atomic (temp file + rename so a crash
  cannot truncate the mark), contains no key material.
- **Emergency rollback exists, signed and single-use.** A **rollback grant**
  `{ type: 'asl-rollback-grant', version: 1, targetVersion, fromVersion,
  reason, issuedAt, issuedBy }`, signed with the release key. Applied only
  when `fromVersion` equals the current version (a replayed grant fails
  `grant-mismatch` after the first use) and it moves `current` back — but it
  never lowers `highWaterMark`: the burned version stays burned.
- **Staged rollout with canary and auto-halt.** The descriptor declares
  `stages` (ascending rollout percentages, first = canary). `apply` installs
  and lands at canary; `promote` advances one stage per explicit passing
  health signal; a failing health signal marks the rollout `halted`, which is
  sticky — promotion refuses until a new signed descriptor or a rollback
  grant resolves it. No path reaches `promoted` without an explicit pass.
  Cohort selection (which instances are the canary) belongs to the deployer,
  not this module.
- **Verification chain and reasons.** One fail-closed chain: descriptor
  structure → descriptor signature → inner manifest (`verifyManifest`) →
  anti-rollback → state write. Each refusal has a distinct reason
  (`not-an-update`, `bad-stages`, `bad-version`, `bad-signature`,
  `no-verification-key`, `manifest-rejected:<inner>`, `rollback-blocked`,
  `grant-mismatch`, `not-a-rollback-grant`, `bad-grant-signature`,
  `halted`). No path prints applied/promoted without the verified chain.
- **Keys.** Same `BUILD_SIGNING_PRIVATE_PEM` / `BUILD_SIGNING_PUBLIC_PEM`
  env vars as H10 — one release key signs builds and updates; splitting keys
  is a ceremony decision (ADR-008 posture), not a code decision.

Phase 0 is the ADR. Nothing else ships until ADR-025 lands.

## Phase 1 — `src/updates.ts` + `update` CLI

One module, no framework:

- `signUpdate(descriptor, privateKeyPem)` / `verifyDescriptor(raw, sig,
  publicKeyPem)` — structure (`not-an-update`, `bad-stages`, `bad-version`)
  then Ed25519 (`bad-signature`, `no-verification-key`).
- `verifyUpdate(raw, sig, { publicKeyPem, repoRoot })` — descriptor checks +
  `verifyManifest` on the embedded manifest (failure →
  `manifest-rejected:<reason>`).
- `loadState(path)` / `saveState(path, state)` — initial state on first use;
  atomic write; malformed state is a refusal, not a default.
- `applyUpdate(raw, sig, { publicKeyPem, repoRoot, statePath })` — full
  chain + `releaseVersion > highWaterMark` + lands rollout at canary.
- `promoteUpdate({ statePath, healthOk })` — advance one stage, or halt.
- `signRollbackGrant(grant, privateKeyPem)` / `rollbackUpdate(grantRaw,
  grantSig, { publicKeyPem, statePath })` — single-use, `fromVersion` must
  equal current, `highWaterMark` untouched.

CLI: `node src/cli.ts update sign|verify|apply|promote|status|grant|rollback`.
npm scripts: `update:verify` (the deploy-time check), `update:status`.
State at `artifacts/update-state.json` (gitignored — per-instance runtime
state, never committed).

## Phase 2 — tests first (red) + demo

- `tests/h12-secure-updates.test.ts` written FIRST, red-confirmed before
  `src/updates.ts` exists: sign/verify round trip; tampered descriptor and
  wrong key refused; bad structure/stages/version refused; missing key env
  refused; inner manifest rejection surfaces as `manifest-rejected` (temp git
  repo, the H10 pattern); apply→apply-replay refused with `rollback-blocked`
  and the mark holds; state persists across loads and is atomic; canary lands
  on apply; failed health → `halted` (sticky); passing health advances stage
  by stage to `promoted`; rollback grant round trip moves `current` without
  lowering the mark; replayed/foreign grant → `grant-mismatch`; burned version
  still refused after rollback. One structural invariant test: state file,
  descriptor, and grant carry no key material (no PEM headers), and no
  refusal message echoes secret bytes.
- Demo: one new section (`21. H12: signed update channel — anti-rollback +
  canary halt`), self-contained on ephemeral demo keys with an honest `not
  issued` line for real state. Exits 0.

## Hard requirements (never simplify away)

- **Fail-closed verification:** no path prints verified/applied/promoted/
  rolled-back without the full signature chain + monotonic check passing;
  every refusal has a distinct reason; missing key env refuses both sign and
  verify.
- **The high-water mark never lowers**, including under emergency rollback;
  replay of a valid signed descriptor at or below the mark is refused.
- **Rollback is signed and single-use:** unsigned rollback does not exist;
  a grant works exactly once against the exact `fromVersion`.
- **Halt is sticky; promotion needs an explicit pass.** No default-healthy
  shortcut, no auto-promote.
- **No new runtime dependencies** (`ADMITTED_RUNTIME_DEPS` gate stays
  green); no dev dependency additions; no shell (argv-array posture).
- **No secrets in output:** key material never reaches stdout, state files,
  descriptors, grants, logs, or error messages.

## Tests / acceptance

- `tests/h12-secure-updates.test.ts` green (~15+ cases, written red first).
- Full gate green: `npm run typecheck && npm test` (527 existing + new;
  15 PG-mode skips unchanged).
- `npm run demo` exits 0 with section 21 visible; `npm run benchmark`
  unchanged (update verification is a deploy-time gate, not a benchmark
  metric — same call as H10/M16).
- ROADMAP H12 → [DONE]; working order (next: H13/H15); M18 gate column notes
  H12 closed.

## Docs sweep

- ROADMAP: H12 heading [DONE] (ADR-025) + mechanism line; working order;
  M18 row gate note.
- CURRENT_STATE: counts, what-works entry, "What H12 closed".
- DECISIONS.md: ADR-025.
- SECURITY_CLAIMS.md: new claim — the update channel refuses unsigned,
  stale-tree, and rolled-back updates fail-closed, and the high-water mark
  survives emergency rollback.
- COMPLIANCE.md: update/config-management rows (CM-2/CM-3 or current
  equivalents) if present.
- THREAT_MODEL.md / TM-004: update-channel attack-path row + controls.
- DEPLOYMENT.md: update-runbook subsection (sign → verify → apply → promote
  → grant/rollback; state custody).
- AGENT-SESSION.md: session entry.
- This prompt: resolution record at the bottom.

## Constraints

- No `as any` / `as never`; descriptor/grant/state parsing typed narrowly —
  malformed input is a refusal, not a cast.
- No runtime or dev dependency additions.
- No secrets in logs/events/errors; no key material outside env/files.
- Every deliberate ceiling carries a `ponytail:` marker naming the ceiling
  and the upgrade path.

## Acceptance + skip list

Acceptance: tests red-then-green; gate green; demo exits 0 with the section;
ROADMAP row [DONE]; docs updated; merged to trunk with the gate run on it.

skipped: remote channel transport (fetching artifacts over a network — this
repo verifies updates, it does not host them; add when there is a release
endpoint). skipped: transparency-log publication of descriptors (H11/Stage-3).
skipped: separate update-signing key + ceremony (ADR-008 path — one release
key now). skipped: cohort scheduling/multi-instance canary selection (the
deployer's job; the state machine only gates promotion). add when: M18's
raven updater consumes this seam and needs a transport or per-key custody.

---

## Resolution (executed 2026-10-01)

- ADR-025 landed in `DECISIONS.md` (Phase 0, docs only, before code).
- Tests written first; red confirmed (`ERR_MODULE_NOT_FOUND` from the missing
  `src/updates.ts`) before the module existed. The red-then-green cycle
  surfaced two contract defects: stages must end at 100 (a rollout finishing
  short is not a promotion — `[50]` had been written as a valid fixture), and
  semantically-invalid rollback grants must be *signed* in tests to reach the
  semantic check, because structure verification correctly runs before
  signature verification.
- Shipped: `src/updates.ts` (descriptor sign/verify, chain verify vs live
  tree, high-water mark, canary/promote/halt, signed single-use rollback);
  CLI `update sign|verify|apply|promote|status|grant|rollback`; npm scripts
  `update:verify`, `update:status`; `.gitignore` gains
  `artifacts/update-state.json`; demo section 21.
- Gate: 559 tests (544 pass, 15 PG-mode skips, 0 fail), typecheck clean,
  supply-chain gate green, demo exits 0 with the new section, benchmark
  exits 0.
- Docs: ROADMAP (H12 [DONE] + mechanism, working order → H13/H15, M18 gate
  cleared), CURRENT_STATE (header, counts, module 43, what-works, What H12
  closed), SECURITY_CLAIMS Claim 34, COMPLIANCE (CM-3 absent→partial, SI-7,
  RS-MA-02), THREAT_MODEL (Update-channel + Replay rows), TM-004 (two attack
  paths + control + test methodology), DEPLOYMENT (Updates runbook),
  AGENT-SESSION SESSION 28.
- Residuals (Claim 34): caller-supplied health signal, one release key
  (ADR-008), no transport, no descriptor transparency log, state-file
  custody is the deployment's job, and the H10 trusted-maintainer residual
  is unchanged — a signed-but-malicious release remains the named H12
  residual.
- Branch `feat/h12-secure-updates` (off `main`); not committed — no commit
  was requested this session.

## Audit follow-up (2026-10-01, ticket 01)

The same-day session audit
(`.scratch/session-audit/2026-10-01-h12-secure-updates/`) found one must-fix:
a used rollback grant re-applied after `current` independently returned to
its `fromVersion` — the version match alone was not single-use. Fixed
test-first: `UpdateState.rollbackGeneration` + `RollbackGrant.generation`,
required equal (else `grant-mismatch`) and incremented in `rollbackUpdate`;
CLI `update grant` embeds the current generation. H12 suite 19 → 20
(regression: "a used grant stays used: re-arriving at its from-version does
not revive it"). Counts after the fix: 560 tests (545 pass, 15 PG skips,
0 fail). Remaining audit nits (not ticketed) are listed in the audit report.