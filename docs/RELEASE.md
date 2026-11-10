# Release readiness

Three different releases. They have different bars, and conflating them is how
projects ship something they cannot support.

| Release | Meaning | Status |
| --- | --- | --- |
| **Source** | someone can clone, read, build and run it | **ready** |
| **Package** | `npm i aisl` works | blocked on publish |
| **Service** | someone else runs it exposed to a network | one item open |

---

## Source release — ready

- [x] `npm run typecheck && npm test`: 828 pass, 0 fail, 21 Postgres skips
- [x] `npm run demo` and `npm run benchmark` run clean; SLO block passes
- [x] `LICENSE` — Apache-2.0 with the patent grant
- [x] `SECURITY.md` — private reporting, scope, and an explicit out-of-scope list
- [x] `README.md` — opens with what this is *and is not*, before any capability claim
- [x] `BRAND.md` — name, copy hierarchy, and why every other name was rejected
- [x] `docs/PILOT.md` + `docs/pilot.html` — the design-partner offer
- [x] `docs/PILOT-TARGETS.md` — 50 organizations, ranked by reply likelihood
- [x] Safety gates 1, 2, 3 — evidence in `docs/SAFETY-2026-11-01.md`,
      tickets in `docs/safety/`
- [x] `node scripts/pack-release.mjs` — 221 entries, 2.6 MB, forbidden: none.
      Refuses on a token-shaped string or a local absolute path, and packs with
      `git archive`, so gitignored files cannot leak in
- [ ] **Push to `kepthqdev/aisl`** — the only remaining step for this release

## Package release — one step

- [ ] `npm publish` under the name `aisl` (unscoped name is free; `@kepthqdev/aisl`
      also works and is safer against squatters)
- [ ] Add a `files` allowlist to `package.json` so the tarball does not ship
      `docs/`, `PROMPTS/`, `security-attacks/` and the rest of the repo
- [ ] Tag `v0.1.0`

Not a blocker for outreach. It *is* the blocker for wiring raven, because the
Pi needs a way to run `verifyUpdate` (see `PROMPTS/M18-federation-project-raven.md`).

## Service release (one item)

From safety ticket 04. The key item is closed in code; TLS remains a deployment
concern:

- [x] **Fail closed on missing keys in production.** `src/key-policy.ts` refuses
      to start the REST server or open a persistent event store without the
      durable keys the evidence plane needs, and names each missing variable
      plus how to produce it. `AISL_ALLOW_EPHEMERAL_KEYS=1` is the explicit,
      warned override for a throwaway instance. The demo still runs with zero
      environment variables.
- [x] **TLS at the edge.** `RestApi` terminates TLS when given `tls: { key, cert }`, and refuses a non-loopback bind without it, before a socket exists.

Until TLS is done, the honest sentence is: *safe to run locally, not safe to
expose on a public interface.*

---

## What "done" means here

A release is not done when the code works. It is done when a stranger can tell
what it does, what it does not do, how to report a problem, and why they should
not trust it more than the evidence supports. Most of the work above is that
last part, and it is the part that gets skipped.
