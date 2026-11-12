# Release readiness

Three different releases. They have different bars, and conflating them is how
projects ship something they cannot support.

| Release | Meaning | Status |
| --- | --- | --- |
| **Source** | someone can clone, read, build and run it | **ready** |
| **Package** | `npm i aisl` works | **blocked: compiled output** |
| **Service** | someone else runs it exposed to a network | **ready** (TLS at the edge; rate limits are the proxy's job) |

---

## Source release — ready

- [x] `npm run typecheck && npm test`: 838 pass, 0 fail, 21 Postgres skips
- [x] `npm run demo` and `npm run benchmark` run clean; SLO block passes
- [x] `LICENSE` — Apache-2.0 with the patent grant
- [x] `SECURITY.md` — private reporting, scope, and an explicit out-of-scope list
- [x] `README.md` — opens with what this is *and is not*, before any capability claim
- [x] `BRAND.md` — name, copy hierarchy, and why every other name was rejected
- [x] `docs/PILOT.md` + `docs/pilot.html` — the design-partner offer
- [x] `docs/PILOT-TARGETS.md` — 50 organizations, ranked by reply likelihood
- [x] Safety gates 1, 2, 3 — evidence in `docs/SAFETY-2026-11-01.md`,
      tickets in `docs/safety/`
- [x] `node scripts/pack-release.mjs` — 235 entries, 2.7 MB, forbidden: none.
      Refuses on a token-shaped string or a local absolute path, and packs with
      `git archive`, so gitignored files cannot leak in
- [ ] **Push to the org remote (not chosen yet)** — the only remaining step for this release

## Package release — blocked on one thing

The tarball is correct. The installed CLI is not runnable yet.

- [x] `files` allowlist: 90 files, 207 kB packed. Ships `src`, `bin`,
      `tools/manifests`, `security-attacks`, `security-fixtures`,
      `tests/fixtures/policy`, `artifacts/sbom.json`, and
      `npm-shrinkwrap.json` (npm never publishes `package-lock.json`, so the
      shrinkwrap is the lockfile that ships). No `docs/`, `PROMPTS/`,
      `security-tests/`, `.build-keys/`, `.scratch/`, or `dist/`.
- [x] Extracted tarball runs: `node package/bin/aisl.mjs demo` exits 0.
- [ ] **Compiled output.** `bin/aisl.mjs` imports `src/cli.ts`. Node refuses
      type stripping under `node_modules`
      (`ERR_UNSUPPORTED_NODE_MODULES_TYPE_STRIPPING`), so `npm i aisl` installs
      a CLI that cannot start. Fix: `tsc` to `dist/`, point `bin` at
      `dist/cli.js`, and keep the source tree as the review artifact.
- [ ] `npm publish` under the name `aisl` (unscoped name is free; a scoped
      `@<org>/aisl` also works once the org exists)
- [ ] Tag `v0.1.0`

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

1. Land the compiled-output step, then `npm publish` (the tarball is verified:
   90 files, 207 kB, and the extracted CLI runs).
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
