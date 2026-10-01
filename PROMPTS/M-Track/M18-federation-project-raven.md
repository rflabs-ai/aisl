# M18 — Federation: project-raven as a client (ADR-022)

Status: [ ] — kickoff written 2026-10-01 (discovery session). Gate cleared:
H10 (ADR-024) and H12 (ADR-025) landed, so raven's self-update has a
verification primitive to adopt. Like M17, M18 is implemented ~90% in the
client repo; the ASL side is consume-only — REST gaps come back as tickets,
never as silent scope growth.

Baseline: M14 REST (`/v1/authorize`, `/v1/sessions`,
`/v1/capability-requests`, `/v1/audit`, `/v1/tasks`, `POST /v1/anchors`) and
the M16 sandbox lifecycle exist. H2 (short-lived creds) and H8 (cross-tenant)
are **not** done; ADR-022 gates non-personal tenants on H8. H13/H15 (kill
switch, fail-closed availability) are open and are stated dependencies of an
unattended always-on agent.

## Discovered (2026-10-01, read-only)

`C:\Users\<user>\projects\project-raven` — always-on Pi agent, systemd
user-level units, bash entry scripts, swappable brain. Relevant facts:

- **Self-build:** `raven-builder.path` (repo change) triggers
  `raven-builder.service` → `bin/run-builder.sh` runs **headless OpenCode**
  with `RAVEN_BUILDER_TASK` contents as the prompt, rewriting the repo
  (`docs/ARCHITECTURE.md` unit graph; ticket 21 builder lane). No sandbox
  beyond "VM/container, non-root".
- **Self-update:** there is **no git remote**; hosts are synced by copying
  the Windows checkout (`docs/OPERATIONS.md` "Upgrade raven"; raven ticket 14
  resolved by documenting the copy procedure). Nothing verifies what is
  copied — the exact RCE path ADR-022 names.
- **No ASL contact points exist in raven today** (grep for `ai-security`,
  `ASL`, sandbox: none).
- Raven's own tracker frontier: 19 (voice), 20 (brain-switch, shipped), 21
  (builder headless), 22 (resilience drill).

## Phase 0 — ADR-027 (docs only, to be written at execution)

Note: H13 landed first (ADR-026), so M18's ADR number shifted from the kickoff
note's 026 to 027.

M18 needs decisions the current code cannot settle:

1. **Where the update tree check runs.** A build manifest binds a *tree
   digest* and `verifyManifest` recomputes it from the live repo — that
   recompute must happen **on raven's host**, against raven's checkout. Decide
   the split: ASL verifies the descriptor + embedded manifest signature and
   gate fields over REST (release-key trust stays in the enforcement plane),
   while raven does the local `treeDigest`/`sbomDigest` comparison; or raven
   verifies signatures itself with `node:crypto`. The first keeps one trust
   anchor; the second keeps raven usable offline.
2. **How the builder runs "through the M16 sandbox lifecycle."** `POST
   /v1/tasks` executes an `AgentSession.run()` (model-driven), not an
   arbitrary builder command; `SandboxRegistry` is in-process with no REST
   route. Decide: a new sandbox-exec REST seam, or raven enforces the M16
   constraints locally (container, non-root, limits) and this milestone
   adopts only the *evidence* half. Do not build a REST route before raven's
   client calls one (YAGNI; M17 closed gaps the client surfaced).
3. **Raven's principal and credentials.** One tenant for raven, an M4
   capability-request flow for anything that acts on the repo. ADR-022 gates
   non-personal tenants on H8; H2 (short-lived credentials) is the stated
   dependency for a device key.
4. **Availability coupling.** Raven is unattended and must run when ASL is
   unreachable. ADR-022's fail-closed direction means: refuse to *update*
   (or to self-build with new authority) when verification is unavailable,
   but do not brick the agent. H15 owns the degraded-mode shape.

## Phase 1 — Verified self-update (raven-side, ASL consume-only)

- A signed update descriptor (`src/updates.ts` format: descriptor embedding
  the H10 build manifest) is issued for raven's source tree at release points.
- The copy-sync upgrade path gains a verification step **before** the copy
  (`update verify`-equivalent): descriptor signature + embedded manifest vs
  the local checkout; a mismatch or missing descriptor refuses the upgrade and
  keeps the running version (rollback safety already in H12's high-water mark
  if raven carries state).
- No ASL code changes expected. A missing route/filter is filed as an M18
  ticket.

## Phase 2 — Sandboxed self-build (decision-gated on Phase 0.2)

- The headless builder either runs as an ASL sandboxed task (if the REST seam
  is chosen and justified) or under raven-local M16-equivalent constraints,
  with the execution attested into ASL's signed EventLog (M17 anchor pattern)
  so a self-build is reviewable evidence, not just a log line.

## Hard requirements (never simplify away)

- **No code merge:** config + a thin client in raven (plain `fetch`); no new
  dependency on either side.
- **No unsigned update, ever:** an update that cannot be verified does not
  apply — the fail-closed direction of H12/ADR-025.
- **No authority without a human:** self-build that changes authority or
  scope goes through the M4 capability-request flow; ASL never mints for a
  non-user approver.
- **No plaintext project content in ASL events:** digests only (Claim 13/33
  posture).
- **Secrets stay in raven's gitignored `conf/env` / `secrets/`**; no token in
  logs or events.
- **Offline survival:** verification unavailability stops updates, not the
  agent (H15 degraded mode; named, not hand-waved).

## Tests / acceptance

- raven side: an unverified/unsigned/stale update refuses and the running
  tree is untouched; a verified update applies; the builder lane's failure
  path is loud and observable.
- ASL side: existing suites stay green; any REST gap gets its own tests
  (M17 precedent — 13 federation tests).
- Both repos' gates green.

## Docs sweep

- ROADMAP: M18 row → [DONE] as phases land; CURRENT_STATE what-works.
- SECURITY_CLAIMS: new claim for verified self-update (+ limitations:
  signed-but-malicious release, caller-side bypass out of scope).
- DEPLOYMENT: the update channel runbook applies to a second consumer.
- raven repo: `docs/OPERATIONS.md` upgrade path, `docs/ARCHITECTURE.md`
  sandbox/self-build, `tasks/00-index.md`, its own session log.

## Constraints

- Zero new ASL runtime dependencies; raven adds only its thin client.
- No `as any` / `as never` at the REST boundary.
- No secrets in logs, events, or error messages on either side.

## Acceptance + skip list

Acceptance: both gates green; unsigned/stale update refused on the raven
side demonstrated; a verified update applied; ROADMAP/claims/docs swept in
both repos.

skipped: an ASL REST sandbox-exec route until raven's client actually calls
one; raven-side code in this discovery session (the prompt is the artifact —
Phase 0 is an ADR and raven-side tickets). skipped: H2/H8-dependent pieces
(device key, non-personal tenants). skipped: M19/M20 (own prompts). add when:
raven's upgrade/builder path is ready to call ASL, and H8 closes for a
non-personal tenant.
