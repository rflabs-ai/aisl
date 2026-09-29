# H10 — Signed builds and supply-chain security (ROADMAP Stage 2)

Status: [x] **[DONE]** (ADR-024) — executed in this session; resolution record
at the bottom.

Spec of record: ROADMAP.md "H10" (attack surface: dependencies, build pipeline,
registry, developer laptops; test methodology: SBOM generation and diff on every
build, pinning with hash verification, SLSA-style provenance verified at deploy,
dependency update review gate).

Baseline: H1 (signed delegation, ADR-023) landed; Stage 0 and Stage 1 fully
[DONE]; 507 tests (492 pass, 15 PG-mode skips). The dependency admission policy
exists (ADR-015 — named-in-ADR, zero-transitive rule, lockfile pinning, review
gate, SBOM-on-build item 5, no native compilation item 6) and is admitted for
two runtime deps (`jose` ADR-015, `postgres` ADR-018). What does not exist: no
SBOM artifact or diff gate (the M12 checks were session-eyeball, not enforced),
no hash verification of the dependency set, no build signing, no provenance
attestation, no lockfile-drift gate, and `package.json` still carries `^`
ranges — the lockfile pins, the manifest does not.

Zero new runtime dependencies. Everything H10 needs is `node:crypto`
(Ed25519 sign/verify, sha256), `node:fs`, and argv-array child processes
(`git ls-files -s`, `npm run` — the `CommandCheck` posture: no shell). The
admission rule holds: a supply-chain module that adds a dependency to defend
the supply chain is a self-defeating joke (ADR-024).

## Phase 0 — ADR-024 (docs only)

ADR-024 must decide:

- **The artifact of record.** There is no compiled binary: TypeScript ships as
  source and the runtime is the artifact. "The build" is therefore a defined
  input set — every git-tracked file except `artifacts/*` (outputs), bound by
  a tree digest over `git ls-files -s` blob SHAs (platform-independent: blob
  SHAs hash committed content, so CRLF checkout differences cannot forge or
  break a manifest across machines).
- **SBOM as a review artifact.** A deterministic `ASL-SBOM v1` generated from
  `package-lock.json` (every package: name, version, resolved URL, integrity
  hash, direct/dev flags; canonical ordering), committed at
  `artifacts/sbom.json`. The gate regenerates and byte-compares: any drift
  fails with the added/removed/changed list and instructions to regenerate the
  baseline and name the admission ADR in the same PR — the SBOM diff IS the
  dependency review gate.
- **Pinning with hash verification.** Exact versions only in
  `package.json` (no `^`, `~`, `*`, comparison ranges — every version change
  becomes a visible one-character diff instead of a silent minor bump); every
  lockfile package entry must carry a `sha512-` integrity value; `resolved`
  must be `https://registry.npmjs.org/...`; the runtime dependency set must
  match the code-enforced allowlist `ADMITTED_RUNTIME_DEPS` (jose, postgres,
  with their ADRs) — a new runtime dep fails the gate until an admission ADR
  and the allowlist change land in the same reviewed PR.
- **Signed builds (provenance attestation).** An Ed25519-signed build
  manifest binding `{ treeDigest, sbomDigest, gitHead, gate result, admitted
  runtime deps }` — SLSA-shaped provenance for a source-artifact project:
  `build sign` runs the full gate (typecheck + tests + supply-chain gate) and
  refuses to sign on any failure; the signature covers the canonical manifest;
  `build verify` recomputes both digests and the gate fields and verifies the
  signature fail-closed with distinct reasons (tampered payload, stale tree,
  wrong key, gate not passed, missing manifest). Deploy discipline
  (DEPLOYMENT.md): verify before start.
- **Keys.** `BUILD_SIGNING_PRIVATE_PEM` / `BUILD_SIGNING_PUBLIC_PEM` env vars —
  the ADR-008 posture; `build keygen` writes dev keys to gitignored
  `.build-keys/` (paths only, never key material to stdout). Production key
  custody (HSM/CI secret, ceremony) is documented, not implemented — the
  residual joins the known-gap #4 family. A committed signing key would make
  signing theater; one does not ship.

Phase 0 is the ADR. Nothing else ships until ADR-024 lands.

## Phase 1 — `src/supply-chain.ts` + gate surface

One module, no framework:

- `computeSbom(repoRoot)` — deterministic `AslSbom` from the lockfile.
- `sbomDigest(sbom)` — `sha256(canonicalJson(sbom))` (`canonicalJson` from
  `src/domain.ts`, same primitive as policy bundles, Claim 26).
- `checkPins(manifest)` / `checkLockfileIntegrity(lockfile, manifest)` — the
  pin, integrity, registry, and allowlist checks; each violation names the dep
  and the rule.
- `runSupplyChainGate({ repoRoot, baselineSbomPath })` — regenerate + diff vs
  the committed baseline + all checks; `{ ok, violations, drift, sbom, digest }`.
- `computeTreeDigest(repoRoot, files?)` — canonical `[path, blobSha]` pairs
  from `git ls-files -s` (argv array, no shell, cwd pinned), `artifacts/`
  excluded; the `files?` override exists for tests.
- `signManifest(manifest, privateKeyPem)` / `verifyManifest(manifest, sig,
  publicKeyPem, opts)` — Ed25519 over `canonicalJson(manifest)`.

CLI: `node src/cli.ts build gate|sbom|keygen|sign|verify`. npm scripts:
`supply-chain` (the gate), `sbom`, `build:sign`, `build:verify`, `build:keygen`.
The local pre-commit hook gains the gate step (hooks are untracked; setup
scripts and DEPLOYMENT document the wiring).

`package.json` pins move from `^x.y.z` to exact `x.y.z` in the same change
(the first thing the new pin rule enforces).

## Phase 2 — CLI demo + tests

- `tests/h10-supply-chain.test.ts` (written FIRST, red-confirmed before the
  module exists): SBOM deterministic and complete (direct + transitive, dev
  flags, integrity hashes); pins pass on the real manifest and refuse
  ranges; lockfile integrity refuses a stripped `integrity` field; drift gate
  catches an injected dependency and clears on baseline regeneration; the
  runtime allowlist refuses an unadmitted dep; tree digest deterministic and
  stale-detecting (temp git repos); sign/verify round trip; verify refuses
  tampered payload / wrong key / stale tree / gate-not-passed / missing
  files. Fail-closed structural checks throughout (the new trust boundary's
  invariant test).
- CLI demo: one new section (`build gate` output + verify status, honest
  `not issued` when no release manifest exists). Demo exits 0.

## Hard requirements (never simplify away)

- **Fail-closed verification:** `build verify` refuses missing manifest,
  missing signature, missing key env, bad signature, digest mismatch, and
  gate-not-passed — each with a distinct reason; no path prints
  "verified" without a verified signature over a matching recomputed state.
- **The gate is code, not convention:** the SBOM diff, pins, integrity,
  registry, and allowlist checks run in the gate; failure messages carry the
  remediation (regenerate baseline, write the admission ADR).
- **No new runtime dependencies:** `node:crypto` + `node:fs` + argv-array
  `child_process` only. Dev dependencies unchanged.
- **No secrets in output:** key material never reaches stdout, logs, or error
  messages; `build keygen` prints file paths only.
- **No shell:** every child process is argv-array (`CommandCheck` posture);
  git/npm invocations pin `cwd` to the repo root.
- **Platform-independent digests:** blob SHAs from the git index, never raw
  working-tree bytes — the same commit must verify identically on any OS.

## Tests / acceptance

- `tests/h10-supply-chain.test.ts` green (~15 cases).
- The full gate stays green: `npm run typecheck && npm test` (507 existing +
  new; 15 PG-mode skips unchanged).
- `npm run supply-chain` exits 0 on the committed state and exits nonzero on
  an injected dependency drift (proven by test, not by manual tampering).
- `npm run demo` exits 0 with the new section visible; `npm run benchmark`
  unchanged (the supply-chain gate is a build gate, not a benchmark metric —
  no SLO row, same as M16).
- ROADMAP H10 → [DONE]; M18 gate column notes H10 closed (H12 remains).

## Docs sweep

- ROADMAP: H10 heading [DONE] (ADR-024) + mechanism line; working order
  (next: H12/H13/H15); M18 row gate note.
- CURRENT_STATE: counts, what-works entry, "What H10 closed", runtime-deps
  paragraph (pins now exact).
- DECISIONS.md: ADR-024.
- SECURITY_CLAIMS.md: Claim 32 — the supply-chain gate fails closed and the
  build manifest binds source, dependencies, and gate result under a
  verifiable signature.
- COMPLIANCE.md: LLM05 (weak → partial), SI-7 (absent → partial), RS-MA-02
  evidence column.
- THREAT_MODEL.md supply-chain row; TM-004 attack-path row + controls.
- DEPLOYMENT.md: build-and-release subsection (gate → sign → verify-before-
  start; key ceremony; the hook wiring).
- AGENT-SESSION.md: session entry.
- This prompt: resolution record at the bottom.

## Constraints

- No `as any` / `as never`; lockfile parsing typed narrowly (a malformed
  lockfile is a gate failure, not a cast).
- No runtime dependency additions; no dev dependency additions.
- No secrets in logs/events/errors; no key material outside env/files.
- No comments-only debt: every deliberate ceiling carries a `ponytail:`
  marker naming the ceiling and the upgrade path.

## Acceptance + skip list

Acceptance: tests red-then-green; gate green; demo exits 0 with the section;
ROADMAP row [DONE]; docs updated; merged to trunk with the gate run on it.

skipped: real CI enforcement (no CI in-repo — the gate is wired to the local
pre-commit hook + release sign + documented CI snippet; add when a CI
pipeline exists). skipped: transparency-log publication of SBOM/manifest
(H11/Stage-3 territory). skipped: hardware/HSM signing key (ADR-008 portability
path). skipped: reproducible builds (Stage 3 row — the manifest binds inputs,
not a byte-reproducible output). add when: a release pipeline or a second
maintainer makes the process control real.

---

## Resolution (executed 2026-09-28)

- ADR-024 landed in `DECISIONS.md` (Phase 0, docs only, before code).
- Tests written first; red confirmed (`ERR_MODULE_NOT_FOUND` from the missing
  module) before `src/supply-chain.ts` existed. Two contract defects were
  caught by the red tests, not by review: the direct-dep pin/lockfile version
  mismatch check, and stale-reason precedence (dependencies checked before
  source, because a lockfile edit changes both digests).
- Shipped: `src/supply-chain.ts` (SBOM + pins + integrity + allowlist + drift
  gate + tree digest + sign/verify + release gate); CLI
  `build gate|sbom|keygen|sign|verify`; npm scripts `supply-chain`, `sbom`,
  `build:keygen`, `build:sign`, `build:verify`; exact pins in `package.json`
  (`^` ranges removed); `artifacts/sbom.json` committed baseline; pre-commit
  hook runs the gate; `.gitignore` gains `.build-keys/`.
- Gate: 527 tests (512 pass, 15 PG-mode skips, 0 fail), typecheck clean,
  supply-chain gate green on the committed state.
- Docs: ROADMAP (H10 [DONE], working order, M18 gate), CURRENT_STATE (counts,
  what-works, What H10 closed, reproduce steps), COMPLIANCE (LLM05/SI-7/
  RS-MA-02), THREAT_MODEL + TM-004, DEPLOYMENT (build-and-release),
  SECURITY_CLAIMS Claim 32, AGENT-SESSION SESSION 25.
- First manifest issued 2026-09-29 after the dev-key ceremony (fingerprint
  `sha256-caa343b2a11a22e941727013950c6b95d402fb0f05776848d61fd43ec1518cb7`;
  identity `dev key 2026-09-29`; custody model + operator runbook in
  DEPLOYMENT.md — durable copy pending SSD arrival, passphrase + fingerprint
  go to a password manager). Re-sign
  at release points — everyday commits make a manifest stale by design
  (`stale-source`). Residuals per Claim 32: dev-key custody (HSM/CI is the
  upgrade), no CI enforcement, no transparency log, trusted-maintainer risk
  unchanged.
