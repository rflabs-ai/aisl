# M17 — Federation: control-plane as first client (ADR-022)

Baseline: M16 merged (Stage 1 closed, ROADMAP row 61 [DONE]); H1 signed
delegation landed (ADR-023); 507 tests (492 pass, 15 PG-mode skips). ADR-022
landed: federation — one enforcement
plane, five state planes, no code merges. This milestone makes control-plane
(`C:\Users\<user>\projects\control-plane`) the first federation client.

**Independent of Stage 2 H1** (H1 is now [DONE] — M17 never waited on it).
Disjoint surfaces (M17 is integration +
config across repos; H1 was `src/capability.ts` issuance). M17's dispatch
authorization uses the human-gated M4 capability-request flow over the M14
REST API and does NOT depend on signed delegation. The sibling agent-arch
audit found: control-plane orchestrates agent workers with zero sandboxing
and a plain writable JSONL event log — its "external verification decides"
thesis is enforced by nothing today. M17 closes both holes without changing
its semantics.

Phase 0 — done: ADR-022 (landed with this prompt; see DECISIONS.md).

## Phase 1 — Evidence anchoring (no dispatch changes)

control-plane's event log (`src/state/`, plain JSONL) gains an anchor export:
- After each run batch, control-plane exports its log head-hash and registers
  it with ASL — one anchor event per batch via an authorized ASL client
  principal (the M3 anchor pattern applied across repos; same posture as the
  head-hash anchor file).
- Tamper detection: a control-plane log edited after an anchor cycle is
  detected when the next anchor's head-hash mismatch is recorded.
- Audit reads move to `GET /v1/audit` with control-plane authenticated as its
  own principal; one tenant per project (per-tenant resource scoping follows
  the M6 synthetic-id pattern, `audit-log:<tenantId>`).

No ASL code changes expected. If a REST gap appears (missing route, missing
filter), file it as an M17 ticket instead of expanding scope silently.

## Phase 2 — Capability-gated dispatch

control-plane's dispatch path becomes a client of the ordinary M4 flow:
- Before spawning a worker on a registered project, control-plane submits a
  `POST /v1/capability-requests` for the worker's scope (repo resources,
  bounded actions, project classification ceiling).
- The human operator approves through the existing flow (MFA enforced at the
  ASL boundary; narrowing allowed; self-approval structurally refused —
  invariant 2/3 hold across the repo boundary: ASL never mints authority
  itself, and control-plane cannot approve its own requests).
- The minted single-use capability scopes the worker to exactly the approved
  resources. control-plane's budget gates and its own verification semantics
  are unchanged — ASL adds authorization and evidence, never verdicts.
- Worker execution MAY run inside the M16 `SandboxRegistry` when a container
  backend is available; the fallback path is documented honestly (same
  posture as `LocalSandbox`).

## Hard requirements (never simplify away)

- **No code merge:** integration is config + a thin client module in
  control-plane (plain `fetch` against the M14 surface — no new dependency on
  either side).
- **No authority without a human:** every cross-repo capability mint is
  operator-approved; ASL refuses issuance to non-user approvers (M4).
- **No plaintext project content in ASL events:** sealed per ADR-018
  per-tenant keys; digests only in the plaintext log (Claim 13 posture).
- **Fail-closed:** ASL unreachable → control-plane dispatch fails closed with
  a loud, operator-visible error (H15 direction); no silent local fallback
  that skips authorization.
- **Secrets:** control-plane's ASL bearer token lives in its gitignored
  `data/secrets.json` posture; the token never enters control-plane's event
  log or the phone dashboard.

## Tests / acceptance

- control-plane side: anchor round trip (export → register → tamper → detect);
  dispatch refused when unapproved; capability scope equals approved scope.
- ASL side: existing suites stay green; the federation path adds no new ASL
  code unless a REST gap is ticketed — any addition gets its own tests.
- Secret-scan: no bearer token, project content, or canary in either repo's
  logs or events on the federation path.
- Both repos' gates green (`typecheck && test` in each).

## Docs sweep

- ROADMAP: Federation milestones table rows → [DONE] as phases land.
- CURRENT_STATE: what-works entry (federation client), counts.
- SECURITY_CLAIMS: new claim — cross-repo evidence anchoring + capability-
  gated dispatch (with limitations: shared-process tenant isolation residual,
  known-gap #7; client-side bypass is out of scope of ASL's claims).
- control-plane: its own docs note the ASL dependency (availability coupling)
  and the dispatch-before-approve order.
- AGENT-SESSION entries in BOTH repos.

## Constraints

- Zero new runtime dependencies on the ASL side; control-plane adds only its
  thin client (built-in `fetch`).
- No `as any` / `as never` at the REST boundary (whitelist parsing on both
  ends, M14 parser style).
- No secrets in logs, events, or error messages on either side.

## Acceptance + skip list

Acceptance: both gates green; anchor tamper detection demonstrated; dispatch
refused without approval demonstrated; ROADMAP rows updated; docs swept.

skipped: raven/home-agent/engineering-OS integrations (M18–M20, own prompts),
automated multi-hop delegation between projects (waits for H1), non-personal
tenants (waits for H8), rate limiting on the federation seam (H15/deployment).
add when: a tenant joins, or H1 lands and delegation chains need minting.