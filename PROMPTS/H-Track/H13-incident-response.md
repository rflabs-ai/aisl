# H13 — Incident response mechanisms (ROADMAP Stage 2)

Status: [x] **[DONE]** (ADR-026) — executed 2026-10-01; resolution record at the
bottom.

Spec of record: ROADMAP.md "H13" — attack surface: everything, under the
assumption of an active incident; failure modes: cannot revoke a session or a
capability quickly; cannot freeze issuance; cannot reconstruct what happened;
cannot preserve evidence; assumptions: an on-call human exists and can act;
test methodology: game days measuring kill-switch latency, **capability
revocation propagation (target ≤ 5 s)**, and evidence export completeness;
residual: incident response is slower than the attack. Federation flag:
structurally necessary at federation (ADR-022) — control-plane's dispatch and
M18's unattended raven both need an operator kill switch that reaches a running
node.

Baseline: in-process capability revocation is immediate (M4,
`AuthorizationService.revoke` + `revoked` set, `capability-revoked` deny);
session revocation is immediate in-memory (`SessionManager.revoke` /
`revokeAllFor`); audit query + export is authorized, tenant-scoped, and
offline-verifiable (M6, `AuditQueryService` + `verifyBundle`); evidence is
append-only, hash-chained, per-event signed, and anchor-writable (M3); M12
gives Postgres mode a shared multi-node store — with a single-writer hash chain
(`PostgresEventLog`), so revocation coordination cannot ride the event log.
Known gaps (CURRENT_STATE #12): no tenant/global kill switch, no freeze, no
cross-node revocation broadcast, no bulk revoke, no incident preservation
artifact, and `exportFor` silently caps a window at 1000 events.

Zero new runtime dependencies. `node:crypto` (sha256 digest for the
preservation artifact; the channel itself needs none), `node:fs`, and the
already-installed `postgres` driver for the Postgres channel.

## Phase 0 — ADR-026 (docs only)

ADR-026 must decide:

- **The kill switch is one operator action, enforced at the two chokepoints.**
  `IncidentService.engage(scope: 'tenant' | 'global')` = freeze issuance +
  revoke every registered capability in scope + revoke sessions in scope.
  Freeze is enforced where authority is created (`AuthorizationService.issue`
  refuses, `incident-frozen`) and where it is exercised (`authorize` denies
  with the distinct `denyReason: 'incident-frozen'` before capability
  evaluation). `lift` clears only the freeze — revoked capabilities stay
  revoked; unfreezing never restores authority.
- **Revocation coordination is a separate multi-writer channel, not the event
  log.** The hash chain is single-writer by design; a kill switch must be
  publishable from an operator CLI process (and from one node to another)
  without touching the chain. An append-only `revocation_channel` table
  (migration 4, `app_rw` INSERT/SELECT, no UPDATE/DELETE grants) carries
  scope-level records (`freeze`, `unfreeze`, `revoke-caps`,
  `revoke-sessions`) and single-target records (`revoke-cap`,
  `revoke-session`). The channel is control-plane coordination data: no
  secrets, no claim content; the evidence of record is each node's own signed
  event log (the `incident.engage` event locally, the resulting deny events
  everywhere).
- **Propagation is pull-on-decision, bounded, and fail-loud.** Every node
  syncs the channel lazily: throttled on `authorize` (default interval
  1000 ms ≤ the 5 s target) and forced on `issue` (issuance is rare and a
  post-freeze mint must not slip through a throttle window). Sync replays from
  cursor 0 on a fresh node, so a restart reconstructs freeze state and
  revocations from the channel. A channel outage never blocks local
  enforcement; it is counted and surfaced (`broadcastOk` in the engage
  metadata, sync failure counter in status).
- **Evidence preservation is a first-class incident artifact.** `preserve`
  pages the ordinary authorized audit export (removing M6's silent 1000-event
  cap), verifies each slice offline against the event public key, checks the
  live global chain, records the head/anchor match, writes an
  `asl-incident-bundle` file, and appends one `incident.preserve` event
  carrying only digest + head + counts (no event content). `report` is the
  reconstruction: an authorized, tenant-scoped summary (decision counts by
  reason, revocation/freeze events, first/last timestamps) over the same
  export.
- **No new authority path.** Engage/lift/preserve/report all run through
  existing services; the CLI is an operator surface over the local world (in
  Postgres mode its channel publish reaches the running node). No REST route
  is added until a client calls one (M17/M18 precedent, YAGNI).

Phase 0 is the ADR. Nothing else ships until ADR-026 lands.

## Phase 1 — freeze + bulk revoke (pdp + sessions)

- `Domain.DenyReason` gains `'incident-frozen'` (distinct from
  `capability-revoked`, `store-unavailable`, etc.).
- `AuthorizationService`: `freeze(tenantId | '*', reason, actor)`,
  `unfreeze(...)`, `isFrozen(tenantId)`, `freezeState()`,
  `revokeAll(tenantId | '*', reason)` (one audited `capability.revoke` event
  per revoked capability), and `applyRevocationRecord(record)` for
  channel-applied state. Freeze entries are checked first in `evaluate()`
  (deny + the ordinary decision event) and at the top of `issue()` (refusal +
  a `capability.issue` deny event mirroring H1's custody refusals).
- `SessionManager`: `all()`, `revokeAllForTenant(tenantId)`, `revokeAll()` —
  bulk revocation with counts.
- Trust-boundary invariant: freeze/revocation state channels carry no key
  material and no secret canaries; all refusals keep distinct reasons.

## Phase 2 — `src/incident.ts` + `src/incident-store-pg.ts`

- `RevocationChannel` port (`publish`, `since(cursor)`, `cursor`, `close`) with
  `InMemoryRevocationChannel` (default; shared instance = multi-node test
  seam) and `PostgresRevocationChannel` (migration id 4 wired into
  `MIGRATIONS`; tagged-template SQL; URL redacted from errors; live-DB tests
  skip cleanly without `DATABASE_URL`).
- `IncidentService` (`engage`, `lift`, `status`, `sync(force?)`, `preserve`,
  `reconstruct`) owns the channel and applies records to authorization +
  sessions. Local engage applies locally first, audits, then publishes
  (`broadcastOk` records whether the channel accepted the record); remote
  nodes apply the same records idempotently in seq order.
- `preserve` artifact: `ASL incident bundle v1` — tenant, requested/actual seq
  bounds, events with signatures, head + previousHead, `chainValid`,
  `anchorMatch`, `digest`. Refuses (no file) when unauthorized, empty, or the
  offline verification fails; paging removes the silent 1000-event cap.
- `reconstruct`: pure summary over the exported slice (decision counts by
  reason/action, freeze/revocation events, actor list, first/last timestamps).

## Phase 3 — wiring, tests first (red) + demo

- `tests/h13-incident-response.test.ts` written FIRST, red-confirmed before
  `src/incident.ts` exists: freeze denies `authorize` with `incident-frozen`
  and blocks `issue` (audited); tenant scope vs global; `lift` restores
  authorization but not revoked capabilities; `revokeAll` is tenant-scoped and
  audited per capability; kill-switch latency is immediate in-process;
  two-node broadcast through one `InMemoryRevocationChannel` — node B denies
  `incident-frozen` after one sync interval (≤ 5 s bound) and force-syncs on
  `issue`; single-target revoke records; channel replay from cursor 0 restores
  freeze + revocations on a fresh node; session bulk revocation; `preserve`
  round trip (authorized, file written, digest stable, offline `verifyBundle`
  valid, `incident.preserve` event, denied principal refused with no file,
  tampered bundle refused); `reconstruct` counts; structural invariant —
  channel records, incident events, and the preservation artifact carry no key
  material or secret canaries.
- `scenario.ts`: `World.incident` (auto-wired channel; Postgres channel under
  `EVENT_STORE=postgres` + `DATABASE_URL`), `World.close()` responsibility
  stays `incident.close()` + `eventLog.close()` at the CLI's call sites.
- `rest-api.ts`: optional `incidentSync` dependency called once per authorized
  request so a running server (not just PDP traffic) pulls the channel.
- CLI: `node src/cli.ts incident status|engage|lift|preserve|report`.
- Demo: section 22 (`H13: incident response — kill switch, broadcast,
  preservation`) with a measured engage→deny latency, a two-node broadcast,
  and a preservation round trip. Exits 0.

## Hard requirements (never simplify away)

- **The kill switch takes effect immediately in-process and within ≤ 5 s
  cross-node**; a frozen tenant's `issue` refuses and its `authorize` denies
  with the distinct `incident-frozen` reason — not a generic failure.
- **Lift never restores revoked authority.** Freeze is reversible; revocation
  is not.
- **No secrets in the channel, events, or artifact metadata**: the
  preservation bundle carries events (already sealed where sensitive) and
  digests; the `incident.preserve` event carries counts + digest + head only.
- **No new authority path and no new runtime dependencies**
  (`ADMITTED_RUNTIME_DEPS` gate stays green); no shell (argv-array posture).
- **Fail-loud broadcast**: an unreachable channel is reported, never silently
  treated as propagated; local enforcement still takes effect.

## Tests / acceptance

- `tests/h13-incident-response.test.ts` green (~20 cases, written red first).
- Full gate green: `npm run typecheck && npm test`.
- `npm run demo` exits 0 with section 22 visible; `npm run benchmark`
  unchanged (incident response is a control, not a benchmark metric).
- Postgres channel suite skips cleanly without `DATABASE_URL`; a live run is
  the milestone follow-up when a disposable container exists.
- ROADMAP H13 → [DONE]; working order next: H15.

## Docs sweep

- ROADMAP: H13 heading [DONE] (ADR-026) + mechanism line; working order;
  assurance-targets revocation row gains the cross-node note.
- CURRENT_STATE: counts, what-works entry, "What H13 closed", gap #12.
- DECISIONS.md: ADR-026 (renumber M18's planned ADR reference to ADR-027).
- SECURITY_CLAIMS.md: new claim — kill switch + broadcast + preservation.
- THREAT_MODEL.md / TM-004: incident-response row + controls.
- DEPLOYMENT.md: incident runbook (engage/lift, channel, preserve/verify).
- COMPLIANCE.md: IR rows if present.
- AGENT-SESSION.md: session entry.
- This prompt: resolution record at the bottom.

## Constraints

- No `as any` / `as never`; channel/artifact parsing typed narrowly —
  malformed input is a refusal, not a cast.
- No runtime or dev dependency additions.
- No secrets in logs/events/errors; URLs/credentials redacted.
- Every deliberate ceiling carries a `ponytail:` marker naming the ceiling
  and the upgrade path.

## Acceptance + skip list

Acceptance: tests red-then-green; gate green; demo exits 0 with the section;
ROADMAP row [DONE]; docs updated.

skipped: REST incident routes (no client calls one; the CLI/operator surface
is local + channel); single-target revocation through REST (same reason);
push-based broadcast (SSE/notify) — polling inside the 5 s target is enough;
retention/legal-hold policies (evidence is append-only and never deleted
today; preservation is an artifact, not a retention engine); signed incident
bundles with a separate custody key (the digest + anchored head chain back to
the signed events; ADR-008 key custody is the upgrade path); live Postgres
channel verification (no DATABASE_URL this session — skips cleanly, live run
is the follow-up). add when: a second node or a remote operator exists.

---

## Resolution (executed 2026-10-01)

- ADR-026 landed in `DECISIONS.md` (Phase 0, docs only, before code). M18's
  planned ADR reference renumbered to ADR-027.
- Tests written first; red confirmed (`ERR_MODULE_NOT_FOUND` from the missing
  `src/incident.ts`) before the module existed. The red-then-green cycle
  surfaced one contract fix: the preservation digest had to normalize through
  a JSON round-trip, because in-memory events carry explicit `undefined`
  fields that serialization drops (the digest must be recomputable from the
  written file).
- Shipped: `src/incident.ts` (`RevocationChannel` port + in-memory backend +
  `IncidentService`: engage/lift/sync/status/revoke-capability/revoke-session/
  preserve/reconstruct); `src/incident-store-pg.ts` (`revocation_channel`,
  migration 4, wired into `MIGRATIONS`; mirror + async refresh; URL-redacted
  errors); PDP chokepoints (`freeze`/`unfreeze`/`isFrozen`/`freezeState`/
  `revokeAll`/`applyIncidentRecord`/broadcast sync; `incident-frozen` deny);
  `SessionManager` bulk revocation; `World.incident`/`World.sessions` +
  injectable channel; REST `incidentSync` per authorized request; CLI
  `incident status|engage|lift|revoke-cap|revoke-session|preserve|report` +
  `npm run incident:status`; demo section 22.
- Two design findings from the tests, both kept: freeze must not deny
  evidence-read actions (`query.audit`, `audit.export`, `evidence.decrypt`)
  and bulk revoke must spare capabilities whose actions are entirely
  evidence-read — otherwise an incident cannot be reconstructed or preserved
  during the response, which is the point of H13.
- Gate: 588 tests (570 pass, 18 PG-mode skips, 0 fail), typecheck clean,
  supply-chain gate green, demo exits 0 with section 22 (measured
  engage→deny 0.5–0.7 ms; node B propagated at exactly one 1000 ms interval;
  preservation bundle VERIFIED), benchmark exits 0 (SLO pass, 0 hard
  failures), attack exit 0.
- Docs: ROADMAP (H13 [DONE] + mechanism, working order → H15, assurance-target
  revocation line), CURRENT_STATE (header, counts 588/570/18, 45 modules,
  what-works, What H13 closed, gap #12), SECURITY_CLAIMS Claim 35,
  THREAT_MODEL (active-incident row), TM-004 (attack path + controls + test
  methodology), DEPLOYMENT (incident runbook + migration 4 note), COMPLIANCE
  (DE-CM-06, IR-4/IR-6, CC7.3/7.4, A.16, HIPAA 164.308(a)(6), Zero-Trust
  automation), PROJECT_CONTEXT map, AGENT-SESSION SESSION 31.
- Residuals (Claim 35/ADR-026): poll-based propagation (Postgres live proof is
  the skip-clean PG suite until a `DATABASE_URL` run), a channel writer can
  freeze (DoS is the H15 accepted trade), in-memory freeze state is lost on
  restart without the Postgres channel, retention/legal hold is out of scope,
  the operator CLI mints audit authority through the existing root path, and
  the ROADMAP residual — incident response can be slower than the attack — is
  unchanged.
- Branch `feat/h13-incident-response` (off `main`); not committed — no commit
  was requested this session.


## Audit follow-up (2026-10-01)

The same-day session audit (`.scratch/session-audit/2026-10-01-h13-incident-response/`) found 4 must-fix + 5 should-fix defects; all 9 tickets were fixed in the audit-follow-up session, with regression tests added for each probe-proven one:

- 01 channel stall: a malformed row is rejected and the cursor advances past it (`load()` skip-and-count, loud via `health()`); live PG regression test added.
- 02 preserve key precondition: cross-process `preserve` fails closed on the default ephemeral event key; the refusal now names `EVENT_SIGNING_*_PEM` and the runbook/Claim 35 state it.
- 03 import cycle: `import type { StoreMigration }` removes the runtime edge; `tests/h13-import-order.test.ts` locks the entry order.
- 04 global evidence: `tenantId: '*'` reads the events recorded with `tenantId: ''`, authorized by the caller's own tenant audit capability.
- 05 `revokeSession` appends an `incident.revoke` event (signed-log evidence, mirroring `revokeCapability`).
- 06 CLI worlds are bootstrap-free (`buildWorld({ bootstrap: false })`) and evidence commands print the in-memory-mode note.
- 07 CLI refusals print a line, not a stack trace.
- 08 DEPLOYMENT no longer claims an unwired per-request REST sync.
- 09 dead `broadcastSyncFailures` counter removed.

The 04 fix surfaced a related verifier property: filtered slices (global view, interleaved tenants) are not contiguous, so bundles now record `contiguous` and `verifyIncidentBundle` verifies non-contiguous slices per-event (hash + signature + recorded live-chain state + anchor head) instead of requiring linkage. See ADR-026's addendum.
