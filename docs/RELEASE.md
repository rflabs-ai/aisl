# Release readiness

Three different releases. They have different bars, and conflating them is how
projects ship something they cannot support.

| Release | Meaning | Status |
| --- | --- | --- |
| **Source** | someone can clone, read, build and run it | **ready** |
| **Package** | `npm i aisl` works | **ready** (ships compiled `dist/`; `aisl demo` wants a git checkout) |
| **Service** | someone else runs it exposed to a network | **ready** (TLS at the edge; rate limits are the proxy's job) |

---

## Source release — ready

- [x] `npm run typecheck && npm test`: 850 pass, 0 fail, 21 Postgres skips (871 tests)
- [x] `npm run demo` and `npm run benchmark` run clean; SLO block passes
- [x] `LICENSE` — Apache-2.0 with the patent grant
- [x] `SECURITY.md` — private reporting, scope, and an explicit out-of-scope list
- [x] `README.md` — opens with what this is *and is not*, before any capability claim
- [x] `BRAND.md` — name, copy hierarchy, and why every other name was rejected
- [x] `docs/PILOT.md` + `docs/pilot.html` — the design-partner offer
- [x] `docs/PILOT-TARGETS.md` — 50 organizations, ranked by reply likelihood
- [x] Safety gates 1, 2, 3 — evidence in `docs/SAFETY-2026-11-01.md`,
      tickets in `docs/safety/`
- [x] `node scripts/pack-release.mjs` - 265 entries, 2.9 MB, forbidden: none.
      Refuses on a token-shaped string or a local absolute path, and packs with
      `git archive`, so gitignored files cannot leak in
- [ ] **Push to the org remote (not chosen yet)** — the only remaining step for this release

## Package release — ready

The tarball is correct and the installed CLI runs from it.

- [x] `files` allowlist: 153 files, 371,835 bytes packed (1,420,850 unpacked).
      Ships `dist`, `src`, `bin`, `tools/manifests`, `security-attacks`,
      `security-fixtures`, `tests/fixtures/policy`, `artifacts/sbom.json`, and
      `npm-shrinkwrap.json` (npm never publishes `package-lock.json`, so the
      shrinkwrap is the lockfile that ships). Ships `LICENSE`, `NOTICE`,
      `README.md`, `SECURITY.md`. No `docs/`, `PROMPTS/`, `security-tests/`,
      `.build-keys/`, or `.scratch/`. `dist/` is gitignored and generated.
- [x] Extracted tarball runs: `node node_modules/aisl/bin/aisl.mjs demo` exits
      0 from the installed layout (also asserted offline in
      `tests/packaging-installed-cli.test.ts`).
- [x] **Compiled output.** `tsconfig.build.json` emits `dist/` with
      `tsc`, which rewrites the source tree's `.ts` import specifiers to `.js`;
      `bin/aisl.mjs` launches `../dist/cli.js`. Development stays buildless
      (`node src/cli.ts demo`). No new runtime dependency: `typescript` was
      already a devDependency. See ADR-044.
- [ ] `npm publish` under the name `aisl` (unscoped name is free; a scoped
      `@<org>/aisl` also works once the org exists)
- [ ] Tag `v0.1.0`

Known, and not a packaging defect: `aisl demo` sections 20-21 digest the
committed tree (`git ls-files`, ADR-024), so a `node_modules` copy with no
`.git` around it starts the CLI but ends the demo with exit 1. Give it a
repository, or use a command that does not run the supply-chain gate.

Not a blocker for outreach. It *is* the blocker for wiring raven, because the
Pi needs a way to run `verifyUpdate` (see `PROMPTS/M18-federation-project-raven.md`).

## Service release — ready

From safety ticket 04. Both items are closed in code:

- [x] **Fail closed on missing keys in production.** `src/key-policy.ts` refuses
      to start the REST server or open a persistent event store without the
      durable keys the evidence plane needs, and names each missing variable
      plus how to produce it. `AISL_ALLOW_EPHEMERAL_KEYS=1` is the explicit,
      warned override for a throwaway instance. The demo still runs with zero
      environment variables.
- [x] **TLS at the edge.** `RestApi` terminates TLS when given `tls: { key, cert }`, and refuses a non-loopback bind without it, before a socket exists. `localhost` is not treated as loopback: the OS resolves it, so it can point anywhere.

The honest sentence is: *safe to run locally; exposing it needs TLS material and
a reverse proxy that owns rate limits.*

---

## When you flip it

The order matters, and the last step is the least urgent.

1. `npm publish` (the tarball is verified: 153 files, 371,835 bytes, and the
   extracted CLI runs). `prepublishOnly` runs typecheck, tests, and the build,
   so a publish cannot ship a `dist` older than the source.
2. `git tag v0.1.0`.
3. `git push` to the org remote.
4. Clean-clone test in a temp directory: clone, install, `npm run demo`,
   `npm test`. This is the closest thing to a stranger who will not read the
   docs.
5. Announce, then send five pilot messages the same day.

If the week gets tight, the order of importance is: publish the tarball, tag the
repo, write the announcement, push. Nothing about the release depends on the
push.

## What "done" means here

A release is not done when the code works. It is done when a stranger can tell
what it does, what it does not do, how to report a problem, and why they should
not trust it more than the evidence supports. Most of the work above is that
last part, and it is the part that gets skipped.
