# CURRENT STATE

Honest snapshot. Updated after H11 — tamper-evident evidence (ADR-031).
Stage 0 (ADR-020) and Stage 1 (M16, ADR-021) are
fully [DONE]: deterministic document ingestion, read-only Git integration, the
capability-request persistence seam, the developer setup scripts, the minimal
UI served by the M14 server, and the sandbox lifecycle — zero new runtime
dependencies. H1 (ADR-023, signed delegation), H10 (ADR-024, supply-chain
gate + signed build manifests), H12 (ADR-025, signed update channel with
anti-rollback and sticky canary), H13 (ADR-026, kill switch + revocation
channel + evidence preservation), H15 (ADR-027, fail-closed availability:
observed health, clock guard, degraded-mode matrix, latency budget), H2
(ADR-028, short-lived credentials: verification-seam lifetime ceiling, bounded
skew, derived workload identity, channel-propagated jti revocation), H8
(ADR-030, a table-driven cross-tenant probe over every REST route and
in-process query surface, which proved and closed a v2-evidence-key
tenant-binding gap and a capability-request reviewer-tenancy gap), and H11
(ADR-031, external anchor sinks + multi-source reconciliation, operator-held
signed checkpoints, durable federation anchor history, recorded legal holds)
are the landed Stage 2 items. M17 closed both
ASL-side REST gaps the control-plane client found (anchor registration,
capability-request status) with no new runtime dependencies. M14's REST API,
M12's Postgres control plane, M13's runtime realism, M11's authz depth and
M10's SLO gate remain the non-regression baseline.
Next frontier: H14 (continuous adversarial evaluation) or any remaining
H3–H7/H9 item.

## What exists

TypeScript foundation on Node 24, ~13,962 lines of source across 48 modules
(comments and blanks included)
(`src/` — `ingestion.ts`, `git-reader.ts`, `supply-chain.ts`,
`rest-anchors.ts`, `updates.ts`, `incident.ts`, `health.ts`, `anchors.ts`,
`retention.ts`, and `incident-store-pg.ts` are the latest additions), 712 tests
(`tests/`, `security-tests/`; 691 pass, 21 Postgres-mode tests skip cleanly
without `DATABASE_URL`), a 12-case attack
corpus (`security-attacks/`), legitimate-task fixtures and a document corpus
(`security-fixtures/`), three policy fixtures (`tests/fixtures/policy/`), five
threat models (`threat-models/`), a measured benchmark (`benchmarks/results.json`),
a static operator UI (`tools/ui/index.html`), developer setup scripts
(`scripts/setup.ps1`, `scripts/setup.sh`), the supply-chain gate artifacts
(`artifacts/sbom.json` — the committed SBOM review baseline;
`artifacts/build-manifest.json` + `.sig` — the first signed release manifest;
the per-instance update state `artifacts/update-state.json` is runtime-only,
gitignored — H12), and this documentation set.

Runtime dependencies: **2** (`jose` — JWT/JWK verification, ADR-015;
`postgres` 3.4.9 — Postgres event backend, ADR-018, zero transitive deps),
both exact-pinned (H10/ADR-024; `^` ranges refuse at the gate).
Dev dependencies: `typescript`, `@types/node`.

## What works

- **Identity and authentication (M2):** OIDC token verification via `jose`
  (`src/identity.ts`). Principals carry an `AuthContext` from the IdP. The PDP
  rejects any principal without valid auth (invariant 13). MFA enforced for
  approvals and session creation.
- **Session binding (M2):** Sessions bind capabilities and approvals to an
  authenticated human (`src/session-manager.ts`). Revoking a session
  invalidates bound capabilities and approvals.
- **Approval with authenticated reviewer (M2):** `Approval.reviewerAuth` is
  required and must include MFA. Cross-tenant and cross-principal approval
  reuse is denied.
- **IdP outage degraded mode (M2):** Distinct `denyReason: 'idp-unavailable'`
  and operator-visible health status via `getIdPHealth()`.
- **Evidence hardening (M3):** per-event Ed25519 signatures, head-hash anchor
  file, append-only SQLite enforcement (`BEFORE UPDATE/DELETE` triggers),
  offline `verifyBundle()` that operates on the exported bundle without
  database access. The EventLog class exposes only `append`, `all`,
  `forTenant`, `verify`, `bundle`, `anchor`, and `close` — no update or
  delete methods. (`src/events.ts`.)
- **Capability revocation (M4):** `AuthorizationService.revoke(capabilityId, reason)`
  adds the id to an in-memory revocation set; the next `authorize()` call returns
  `deny` with `denyReason: 'capability-revoked'`. In-process propagation is
  immediate. Multi-node broadcast is H13.
- **Capability request flow (M4):** Agents submit `CapabilityRequest` records;
  a human reviewer (`kind: 'user'`) approves, narrowing scope if desired, and
  the approval mints a single-use capability scoped exactly to the request.
   Self-approval is structurally refused; non-user principals cannot approve;
   requests expire after 5 minutes.
- **Signed delegation (H1):** a non-root issuer attenuates against its own
  signed capability, presented as `parent` — the declared `issuerAuthority`
  seam is gone (ADR-023). The parent is verified before any field is trusted
  (signature, subject match — you delegate only what you hold — tenant,
  expiry, consumption) whenever one is presented, root included; authority is
  derived from the parent's fields across all six dimensions (resources,
  actions, classification, expiry, constraints — a child may narrow network
  hosts but never drop one — and single-use parents are leaf authorities that
  cannot delegate); the child records `provenance.delegatedFrom` (parent id +
  parent signature) under its own signature, and caller-supplied values are
  overridden. The service adds custody (registered, not revoked) and audits
  every custody refusal as a `capability.issue` deny event. Two-hop chains
  verified traceable; 11-case extremes fuzz matrix plus the
  constraint/single-use bypass suite refuse every overreach.
- **Supply-chain gate + signed builds (H10):** `src/supply-chain.ts` (ADR-024)
  turns the ADR-015 admission policy into code that refuses. The gate
  (`npm run supply-chain`) regenerates a deterministic `ASL-SBOM v1` from the
  lockfile and diffs it against the committed review baseline
  (`artifacts/sbom.json`), enforces exact version pins (no `^`/`~`/`*`
  ranges), sha512 integrity + `registry.npmjs.org` resolved URLs on every
  lockfile package, and the `ADMITTED_RUNTIME_DEPS` allowlist (jose —
  ADR-015, postgres — ADR-018; a new runtime dep fails until an admission ADR
  lands in the same PR). The signed build manifest (`npm run build:sign` /
  `build:verify`) runs the full release gate first (typecheck + tests +
  supply-chain) and Ed25519-signs the canonical manifest binding
  `treeDigest` (over `git ls-files -s` blob SHAs, artifacts excluded —
  platform-independent), `sbomDigest`, `gitHead`, and the gate result;
  `build verify` recomputes and verifies fail-closed with distinct reasons
   (bad-signature / stale-source / stale-dependencies / gate-not-passed /
   not-a-build-manifest). Deploy discipline: verify before start
   (DEPLOYMENT.md). The gate also runs in the local pre-commit hook.
- **Signed update channel (H12):** `src/updates.ts` (ADR-025) consumes the
  H10 manifest as its update-verification primitive. A signed update
  descriptor (`node src/cli.ts update sign`) wraps the issued build manifest;
  `update verify` / `update apply` run the fail-closed chain — descriptor
  structure → Ed25519 descriptor signature → embedded manifest verified
  against the **live tree** (H10 `verifyManifest` recomputes digests) → the
  persisted high-water mark. `apply` requires `releaseVersion > highWaterMark`
  and raises it; the mark never lowers, so a perfectly signed, stale
  descriptor is refused (`rollback-blocked`). Emergency rollback is a signed,
  single-use grant (`update grant` / `update rollback`) naming the exact
  from-version and carrying the state's `rollbackGeneration` (one use per
  generation — a used grant stays used even if its from-version becomes
  current again; replay → `grant-mismatch`), backward-only, mark preserved.
  Staged rollout: stages ascend to 100, `apply` lands canary, `update
  promote ok|fail` advances one stage per explicit health pass, a failing
  signal halts and the halt is sticky.   State is code-written only, atomic
  (temp + rename), gitignored per instance.
- **Incident response (H13):** `src/incident.ts` (ADR-026) +
  `src/incident-store-pg.ts` (migration 4). `IncidentService.engage` is the
  kill switch — freeze issuance + authorization, revoke every registered
  capability in scope (evidence-read capabilities survive so the incident can
  be reconstructed), revoke sessions in scope — enforced at the two
  chokepoints (`issue` refuses `incident-frozen` + audits; `authorize` denies
  with the distinct `denyReason: 'incident-frozen'`); `lift` clears the freeze
  only and revoked authority stays revoked. A multi-writer, append-only
  `revocation_channel` (Postgres migration 4; the in-memory channel is the
  default and the multi-node test seam) broadcasts freeze/revoke records
  across nodes and from an operator CLI to a running node; the PDP pulls it
  throttled on `authorize` (default 1 s, inside the ≤ 5 s target) and forced
  on `issue`, a fresh node replays from cursor 0, and a channel outage still
  engages locally with `broadcastOk: false`. A malformed/unknown channel row
  is rejected and skipped with the cursor advancing past it (a rejected row
  can never stall propagation; the table is append-only). `preserve` pages
  past M6's silent 1000-event cap into an independently verifiable
  `asl-incident-bundle` (content digest, offline chain + signature
  verification, anchor check; filtered views — global incidents, interleaved
  tenants — verify per-event with `contiguous: false` instead of requiring
  slice linkage) and records digest + head + counts only; `reconstruct`
  summarizes the authorized slice, with `tenantId: '*'` as the global view
  over the events recorded with no tenant. CLI:
  `node src/cli.ts incident status|engage|lift|revoke-cap|revoke-session|
  revoke-token|preserve|report` (+ `npm run incident:status`; the CLI builds a
  bootstrap-free world so operator commands mint and append no fixture
  evidence). Demo section 22 shows a
  measured engage→deny latency, a two-node interval-bounded broadcast, and a
  verified preservation round trip.
- **Audit query + export API (M6):** In-process query and export API
  (`src/audit-query.ts`, `AuditQueryService`). Authorized through
  `AuthorizationService.queryAudit` gating on synthetic `audit-log:<tenantId>`
  resource and `query.audit` / `audit.export` actions. Tenant isolation is
  fail-closed (principal tenant derives target resource; cross-tenant query
  denies with `tenant-mismatch`). Filter limits enforced at service boundary
  (time range ≤ 90 days, limit ≤ 1000, offset ≥ 0). Prepared parameterized SQLite
  query on `security_events` table; events returned with signatures intact;
  offline chain-slice verification supported via `verifyBundle()` with `previousHead`.
- **Policy testing framework (M7):** `simulate(engine, scenarios)`,
  `diffDecisions(before, after, scenarios)`, and `loadFixtures(dir)` in
  `src/policy-testing.ts`. Validator rejects malformed JSON, missing fields,
  action outside `KnownAction`, cross-tenant scenarios. `npm run policy:diff`
  diffs `BASELINE_POLICY` against an optional overlay file. Three migrated
  fixtures under `tests/fixtures/policy/` (default-deny-empty,
  deny-overrides-allow, classification-ceiling).
- **Assurance targets + SLO gate (M10):** `src/slo.ts` holds the per-control
  target catalog (`SLO_TARGETS`) — one measurable target per control, each with
  a named measurement (ADR-014); the catalog is mirrored in the ROADMAP
  "Assurance targets" table and the ids are pinned by test.
  `evaluateSlo(metrics)` evaluates it against benchmark metrics.
  `npm run benchmark` prints the target table, writes
  `metrics.slo = { pass, hardFailures, targets[] }` to
  `benchmarks/results.json`, and exits nonzero when a `hard` target misses.
  Latency metrics are advisory (reported, never gated). The `falseClaimRate`
  denominator is the legitimate-fixture guard verdicts plus an N=100 honest
  R1-style corpus run inside the benchmark (`evidence.honestCorpusSessions`);
  those sessions' PDP decisions are added to `expectedDecisions` so
  `auditCompleteness` stays 1.0.
- **Output reliability layer (M8):** `GroundedResponseGuard` (`src/guard.ts`)
  implements D2–D5 detection with a pure `runLadder` fallback (Repair →
  Regenerate → Abstain → Escalate; Escalate gated on classification).
  `AgentSession.run()` wires the guard between `model.complete()` and trace
  return; `SessionTrace.guarded` carries the result and `metadata.sealed`
  holds the encrypted original. D5 leaks skip the ladder; D6 critic model is
  a stub (telemetry only). Guard holds no authority (R3 dependency test).
- **Guard follow-ups + drift closure (M9):** the Escalate rung queues a real
  `CapabilityRequest` through M4 when `classification >= confidential` and a
  `CapabilityRequestService` is configured (`submit()` appends the
  `capability.request` event; the awaiting-review text and `session.guard`
  metadata carry the request id); approval stays out of band. Session
  classification is derived per run by `deriveClassification()` from capability
  `maxClassification` ceilings + the registry classification of visible/requested
  resources, defaulting to `'public'`. A second guard pass runs after execution
  with the populated `steps` and emits one extra `session.guard` event
  (`phase: 'guard-second-pass'`) only when the verdict changes. `metadata.sealed`
  is a raw `Sealed` object and `metadata.ladderRung` records the rung that fired.
  The D6 critic hook is callable (`guard(ctx, criticFn?)`) but no real critic is
  wired.
- **Granular RBAC (M11):** roles are first-class data (`Role`: id, tenantId,
  actions, `maxClassification` ceiling; `BASELINE_ROLES` + `ROLE_TABLE_VERSION`
  in `src/policy.ts`). `AuthorizationService.issueForRole` mints through the
  ordinary `issue()` pipeline — issuer kinds, tenant match, attenuation
  (invariant 6, ADR-002), registration, and audit all apply unchanged — so a
  capability minted through a role can never exceed the role, and roles never
  mint authority. `createPolicyEngine` cross-validates allow rules that
  reference roles at construction: granting an action outside the role's set,
  a classification above the role's ceiling, or a wildcard action set is a
  `PolicyCompilationError` (fail closed).
- **Classification propagation (M11):** `propagateClassification`
  (`src/registry.ts`) takes the max label by `classificationRank` — unknown
  labels rank 100 and win, labels only raise, never lower. `ingestDocument`
  reports a `derivedClassification` when `derivedFrom` sources are given;
  `ResourceRegistry.raiseClassification` is the raise-only seam; and the
  runtime write path (a tool step with `changed: true`) lifts the target's
  label to the max of the data sources the step sees (capability ceilings are
  deliberately excluded — clearance is not a data label). Derived-artifact
  events carry `metadata.derivedClassification` and seal under
  `evidence-key:<derived>`; a derived label feeds ceilings, never grants.
- **Configuration management (M11):** policy and role tables are versioned
  bundles (`PolicyBundle`/`RoleBundle` in `src/policy-config.ts`) with
  `hash = sha256(canonicalJson({ version, rules | roles }))`.
  `loadPolicyBundle`/`loadRoleBundle` recompute and refuse any mismatch before
  anything compiles or logs. `createEngineFromBundle` builds the engine and —
  opt-in via `eventLog` — appends exactly one `policy.load` event (version,
  hash, rule count, provenance); plain-rule engines append nothing.
  `npm run policy:diff` verifies versioned overlay hashes before diffing;
  legacy unversioned overlays still load. Stated honestly: authoring is still
  in-repo and the review gate is git — this is a verified artifact, not a
  policy service.
- **Model provider adapters + egress gate (M13):** `HttpModelAdapter`
  (`src/model-http.ts`) is an OpenAI-compatible transport behind the
  `ModelPort` — injectable `fetch`, bounded retry with backoff, timeout, and
  output always through the whitelist parser `parseModelOutput`. Sending
  ingested content to an external provider is a disclosure, so the adapter
  enforces a **classification egress gate**: `deriveClassification` over the
  content about to be sent must fit the configured ceiling AND the PDP must
  allow `model.invoke` on the synthetic provider resource. Default-deny, not
  bypassable by config; the derivation is the max over the WHOLE content map,
  so classified content a caller forgot to declare is still caught, and a
  non-empty context with no content map is refused as unclassifiable.
  Refusals throw and never send. `model.call` events record
  id/duration/usage/decision — never content, keys, or canaries (Claim 27,
  including its free-text limitation: text absent from the map is H7 DLP
  territory, not this gate).
- **Verification pipeline (M13):** `CommandCheck` (`src/check-command.ts`)
  runs a configured argv array — no shell — against produced artifacts via
  stdin, with a config-time command allowlist, a minimal environment (no
  ambient secrets), and timeout → `fail`. Results flow through the existing
  `runVerifications` path, so a failed check marks the step errored; no new
  authority anywhere.
- **Structured telemetry (M13):** `TelemetryPort` + `JsonlTelemetry` (`src/telemetry.ts`) emit one JSON object per line (stdout or an injected sink): `session.start`/`session.end` (ids, counts, durations), `pdp.denyReasons` aggregates computed from existing step decisions, and `model.call` outcomes from the adapter. Emission failures are swallowed and counted (`dropped`) — telemetry is observability, never a control, and the PDP never reads it (dependency-direction tests; Claim 28).
- **Postgres event backend (M12):** `EventStore` port (exactly `EventLog`'s public surface) with two implementations — `EventLog` (SQLite + in-memory, the default) and `PostgresEventLog` (`src/event-store-pg.ts`, `postgres@3.4.9`, zero transitive deps, raw SQL via tagged templates, no ORM/pooling). Forward-only, versioned, sha256-recorded migrations (ids 1–3, wired from `tenant-rls.ts`/`persistence.ts`); a recorded id with a changed hash refuses to open (tamper). Chain rehydrate + verify on connect (resume parity with `EventLog.resume()`); appends persist through the same signing/hash helpers; the migrate event is persisted before `whenReady()` resolves. Opt-in via `EVENT_STORE=postgres` + `DATABASE_URL` (ambient `DATABASE_URL` alone flips nothing). Fail-closed: **a typed `StoreUnavailableError` denies with the distinct `store-unavailable` reason (H15) plus a loud warning — wired through the PDP's decision path, tested without a live DB**; appends before open fail closed; a failed write closes the store; error messages redact the URL/credentials (secret-scan test); PG-mode runtimes construct through the ready-gated `buildWorldAsync` factory (awaiting connect/migration/chain-verify before any bootstrap append), and `close()` drains the write queue before ending the pool (a PG-mode demo persists every event and exits cleanly).
- **Database-enforced tenant isolation (M12, Postgres mode):** `FORCE RLS` + deny-by-default per-role policies on the control-plane tables (`src/tenant-rls.ts` for `security_events`, `src/persistence.ts` for the state tables). `app_reader` is tenant-scoped via the per-transaction context (`set_config('app.tenant_id', ..., is_local := true)`): unset context → zero rows, hostile queries → zero rows, wrong context → only that tenant (proven live via `SET LOCAL ROLE app_reader` — superuser is not the proof); **per-tenant evidence keys are wired into the runtime write path** (`sealFor` in runtime.ts's record path and the guard's ladder/withheld seals) — sealed evidence carries `evidence-key:v2:<tenant>:<level>` and decrypts only with tenant-bound clearance (`revealEvidence` authorizes on the sealed keyId itself; a capability on another tenant's key never matches). Legacy seals keep opening — no silent re-encryption. SQLite mode stays app-level (Claim 9 updated).
- **Backup + restore (M12):** `tools/backup.ps1` (plain-SQL `pg_dump`, host pg_dump preferred with docker fallback; password via `PGPASSWORD` env, never argv/logs) and a rehearsed restore test — dump → restore into a scratch db → chain `verify()` + signature check + `verifyBundle()` + persistence row parity all pass live.
- **Persistence (M12):** `PersistenceStore` (`src/persistence.ts`) — RLS'd `projects`/`tasks`/`agent_sessions` (+ `capability_requests` table per ADR-018) with tenant-bound CRUD, upserted resumable session state, defense-in-depth cross-tenant refusals, roundtrip + restart tests live.
- Policy evaluation: default deny, deny-overrides, approval gating, classification
  ceilings, tenant isolation, deterministic output.
- Authorization: capability AND policy, fail-closed on any internal error.
- Enforcement: one path (`AgentSession.attempt`) for every agent action.
- **Container sandbox** (`src/container-sandbox.ts`): Docker-backed isolation
  with non-root, read-only rootfs, no network namespace, seccomp, memory/CPU/PID
  limits. Falls back to `LocalSandbox` when Docker is unavailable.
- **Sandbox lifecycle (M16):** `src/sandbox-registry.ts` (ADR-021) — wraps the
  container sandbox with the missing lifecycle: `create` spawns synchronously
  (spawn-before-register, so a failure leaves no orphan) and registers the
  sandbox as a tenant-bound `'system'` resource (`sandbox:<tenantId>:<name>`);
  `get`/`list`/`destroy`/`attest` re-check the registry's tenant binding on
  every call (cross-tenant get reads as absent, cross-tenant destroy refuses);
  `execute` authorizes `sandbox.execute` on the sandbox resource id through the
  ordinary PDP path before `runTool` — the agent gets a capability, never the
  handle. Every lifecycle action appends a sealed event (`sealFor`, per-tenant
  key, classification `'public'`) plus a SHA-256 digest of the limit config;
  the plaintext log shows only digest + keyId. Limits ARE
  `ContainerSandboxOptions`; `effectiveLimits` is the single defaults source so
  destroy/attest record effective-vs-declared honestly. Destroy refuses unknown
  ids, is idempotent on already-destroyed ones, and `installExitSweep()`
  (opt-in) tears down every active sandbox on `beforeExit`/SIGINT/SIGTERM.
- **Egress proxy** (`src/egress-proxy.ts`): HTTP proxy that intercepts traffic,
  blocks IP literals, and routes every request through the PDP before forwarding.
  Sessions have no route out except through the proxy.
- **REST API surface (M14):** the platform's first network ingress
  (`src/rest-api.ts`, ADR-019) — a `node:http` whitelist router of literal
  method+path pairs; unlisted method+path combinations close the connection,
  nothing is advertised. Identity: `Authorization: Bearer <JWT>` verified by
  `IdentityProvider.verifyToken` (ADR-016) + a deployment-registered
  principal resolver — **client-supplied `X-*` headers are never read for
  identity** (structural test mirrors the egress-proxy proof). Tenant comes
  from the verified principal; a request field naming a tenant is passed
  through the same in-process validation path (`tenant-mismatch` deny WITH
  its event — invariant 7 parity). Bodies: whitelist parsers
  (`parseModelOutput` style), 1 MiB cap rejected with a distinct 413 before
  parsing, prototype-pollution-safe param copies, garbage JSON → structured
  400, server keeps serving. Responses are whitelist-built (no stack traces,
  no URLs, no token contents). Fail-closed: a throwing handler → 500 + a
  deny event with `denyReason: 'evaluation-error'`; PDP denies surface as
  `403 { denyReason }`. Endpoints (all routing through the ONE existing
  decision paths, no new execution path): `POST /v1/authorize` (PDP),
  `POST/DELETE /v1/sessions` (`SessionManager`), `POST/GET
  /v1/capability-requests` + `POST /v1/capability-requests/:id/approvals`
  (`CapabilityRequestService`, MFA enforced at the boundary, narrowing
  allowed, mint unchanged), `GET /v1/audit` (`AuditQueryService` unchanged),
  `POST /v1/tasks` (the one `AgentSession.run()` path, trace summary
  returned), `GET /healthz` → `{ idp, store }` (the operator health endpoint
  since M2; H15 extends it to `{ idp, store, engine, clock }` when a
  `HealthState` is wired). Named non-goals: rate limiting
  (**resolved by H15/ADR-027 as deployment territory** — the reverse proxy
  owns request rate limits; DEPLOYMENT.md), CORS
  (same-origin loopback), TLS-in-process (loopback bind; termination is the
  deployment's job — DEPLOYMENT.md), WebSockets, streaming.
- **Document ingestion (M15):** `src/ingestion.ts` (ADR-020) — deterministic
  boundary-aware chunking (no model in the loop), chunk ids
  `doc/<documentId>/chunk/<n>`, every chunk a registry resource carrying the
  source id as `derivedFrom`; labels flow through the M11 machinery
  (`propagateClassification` for the derived label, raise-only re-ingest via
  `raiseClassification`); one `document.ingest` event per chunk with content
  sealed via `sealFor` (per-tenant key) and a SHA-256 digest — no plaintext
  chunk content in the event log. The ingester holds no issuance handle
  (invariant 3); a hostile document is injection-inert (Claim 29).
- **Git integration, read-only (M15):** `src/git-reader.ts` (ADR-020) — verbs
  allowlisted at configuration time to `log`/`show`/`diff`/`status` (write and
  network verbs refused at construction, `CommandCheck` posture); argv-array
  exec with no shell, minimal environment, timeout → failure; traversal
  refused before spawn (absolute paths, `..` segments, `rev:path` tails,
  `--no-index`/`--git-dir`/`--work-tree`/`-C` escape hatches); output is
  untrusted content that enters the ingestion path labeled with the
  repository's classification (Claim 30).
- **Capability-request persistence (M15):** the M12 seam closed —
  `PersistenceStore` gained `createCapabilityRequest` /
  `getCapabilityRequest` / `listCapabilityRequestsForTenant` /
  `updateCapabilityRequestStatus` over the migration-3 `capability_requests`
  table (raw tagged-template SQL, tenant-bound RLS context per transaction);
  the REST capability-request routes mirror to the store when one is wired
  (opt-in — without it the M14 surface is byte-for-byte unchanged); mirror
  failures propagate (fail closed, no silently unpersisted request).
- **Minimal UI (M15):** `tools/ui/index.html` (ADR-020) — one static page,
  zero dependencies, inline CSS/JS, vanilla `fetch` against `POST /v1/tasks`
  and `GET /v1/audit`; served by the M14 server through exact-route
  `staticPages` (`GET /ui`, `GET /`) — no directory serving, no parametrized
  path, so traversal does not exist by construction. The bearer token is
  typed by the operator at runtime; no canary/secret/absolute URL in any
  served page (secret-scan test); accessibility basics hold (semantic HTML,
  labeled inputs, keyboard-native controls, `aria-live` outputs); rendering
  uses `textContent` only — model text and event metadata are never
  interpreted as HTML. No new authorization surface: the UI is a client of
  the ordinary PDP path.
- **Developer setup scripts (M15):** `scripts/setup.ps1` + `scripts/setup.sh`
  (ADR-020) — Node ≥ 22.5 / git / npm checks, `npm install`, typecheck,
  tests; every check prints its result and a failed check exits nonzero
  (fail closed); offline and reviewable in-repo (no `curl | bash`, no remote
  fetches — pattern-scanned by test); optional Postgres-16 container
  bootstrap (`-WithPostgres` / `--with-postgres`) matching DEPLOYMENT.md's
  M12 workflow.
- **Envelope encryption** (`src/envelope-secrets.ts`): AES-256-GCM envelope
  encryption with HKDF-derived DEKs. Secrets are never stored in plaintext.
  Evidence records get a redacted placeholder.
- Gates: network egress decisions (PDP-gated + proxy-enforced), secret access
  decisions (PDP-gated + envelope-encrypted).
- Evidence: SHA-256 hash-chained append-only log with SQLite persistence,
  Ed25519 per-event signatures, head-hash anchor file, a verifier, an
  offline `verifyBundle()`, resume across restart, and refusal to extend a
  tampered store.
- Evidence confidentiality: every output is sealed (AES-256-GCM, one key per
  classification, HKDF from a master key) and digestable; content is readable
  only with an `evidence.decrypt` capability for that level, and reading it is
  itself an audited decision.
- Verification plane: post-execution checks with recorded results.
- Demo (`npm run demo`), attack harness (`npm run attack`), benchmark
  (`npm run benchmark`).
- **Federation client authority + evidence (M17, ADR-022):** control-plane is
  the first client over the M14 REST seam, no code merge. `POST /v1/anchors`
  (`src/rest-anchors.ts`) accepts a foreign evidence-log head-hash — tenant
  from the verified principal (body tenant must match, else `tenant-mismatch`),
  sha256-hex only, recorded in ASL's own append-only signed event log as an
  `anchor.register` event; a claimed `previousHeadHash` that disagrees with the
  last accepted head flags `tamper`. **H11 closed the registry's in-memory
  marker: the accepted head per tenant is rehydrated from those durable events,
  so mismatch detection survives a restart.** `GET /v1/capability-requests/:id`
  lets the requester read its request's outcome (pending/approved/denied/expired)
  and, once approved, the minted capability projection — closing the gap where an
  approved request vanished from the pending-only list.
- **Tamper-evident evidence, externally anchored (H11, ADR-031):**
  `src/anchors.ts`. The M3 anchor file stays byte-compatible; `AnchorSink` adds
  an external publication port — `FileAnchorSink` (a second/WORM path) and
  `HttpAnchorSink` (operator-configured witness, optional env-only bearer
  token) — with a bounded queue, kick-on-publish + `EventStore.flushAnchors()`,
  and loud `published/failed/dropped/lastError` counters. Publication never
  blocks an append and a throwing sink can never lose an event.
  `verifyAnchoredEvidence` reconciles a bundle against any number of sources:
  parse + monotone/contiguous seqs, line-to-event binding, head coverage (an
  uncovered tail fails closed), a source ahead of the bundle head = tail
  truncation, two sources disagreeing at one seq = **fork**. No source means
  `unanchored: true` — never silently anchored. `createCheckpoint` signs an
  `asl-anchor-checkpoint` with the existing event key; `verifyCheckpoint`
  refuses truncation, rewrite (even by a host attacker who re-signs the whole
  chain), broken chaining, same-seq forks, and bad signatures — the operator
  holds it off-host (H11's "store the runtime cannot rewrite", no live service
  required). Timestamp regressions are reported as non-fatal anomalies;
  witness records carry the witness clock. `src/retention.ts` records legal
  holds as signed `evidence.hold`/`evidence.release` events
  (`RetentionLedger`, replayed from the log, tenant-bound); retention itself
  is structural — no update/delete path at any layer. CLI:
  `node src/cli.ts evidence status|checkpoint|verify|witness|hold|release`
  (+ `npm run evidence:status`).
- Typecheck: clean (`npx tsc --noEmit`).

## What was tested

All 712 tests pass (691 green; 21 Postgres-mode tests skip without
`DATABASE_URL`/`RESTORE_DATABASE_URL`; the Postgres suites were verified
live against a disposable `postgres:16` container — serialized run 612 tests
(skipped suites enumerate their child cases once live), 611 pass, 1
environment-gated skip, 0 fail). Coverage of the
twelve invariants plus M2, M3, M4, M5, M6, M7, M8, M9, M10, M11, M13, M14, M15, M16, M17, H1, H10, H12, H13, H15, H2, H8, H11:

1 no capability -> deny (3) | 2 model cannot mint (3) | 3 document cannot
mint (2) | 4 tool cannot expand (2) | 5 expiry (2) | 6 attenuation (4) | 7
decisions logged (2) | 8 tamper-evidence (5) | 9 tenant isolation (3) | 10
network (3) | 11 secrets (2) | 12 fail closed (3) | **13 no unauthenticated
principal (6)** | **M3 signatures/anchor/offline (14)** | **M4 authorization
lifecycle (13)** | **M5 hierarchical matching (19)** | **M6 audit query + export (29)**
| **M7 policy testing framework (12)** | **M8 reliability layer + R1-R3 (26)**
| **M9 guard follow-ups + drift closure (26)** | **M10 assurance-target gate (5)**
| **M11 authz depth (35: RBAC 12, propagation 11, bundles 12)**
| **M13 runtime realism (33: adapter + egress gate 14, command checks 10, telemetry 9)**
| **M12 platform shift (50: backend parity 28, tenant RLS + keys 17, persistence/restore 5)**.
| **M14 REST API (50: server core + authn/whitelist/fail-closed 20, sessions + capability requests 18, audit + tasks 12)**.
| **M15 Stage-0 closure (23: ingestion 8, git 7, UI 4, setup 3, capability-request persistence 1)**.
| **M16 sandbox lifecycle (10: round trip + refusal 2, tenant isolation 2, limits + attestation 2, PDP-gated execute 2, exit sweep 1, seal-scan 1)**.
| **H1 signed delegation (32: parent refusals 7, custody + audit-event 2, chain traceability 3, constraint/single-use dimensions 6, root-with-parent 2, extremes fuzz 11, structural src-wide scan 1)**; invariant 6 rewritten against signed parents (4).
| **H10 supply chain (20: SBOM deterministic + complete 2, pins 4, drift gate 5, tree digest 2, manifest sign/verify 5)**.
| **H12 secure updates (20: descriptor signature 4, chain vs live tree 4, anti-rollback 3, rollout 3, grant 4, structural invariants 2)**.
| **H13 incident response (37: acceptance + audit follow-ups 29 — unfreeze propagation and issuance-fence regressions, `revoke-cap` tenant scope, grant semantics; Postgres channel 7, of which 4 live, skip-clean without `DATABASE_URL`; import-cycle regression 1)**.
| **H15 fail-closed availability (24: 19 acceptance — per-dependency fault matrix, recovery, false-denial pin, degraded mode, safety ordering, `/healthz` shape + structural no-secrets — plus 5 audit-follow-up regressions)**.
| **H2 short-lived credentials (31: admission contract + 2000-case fuzz 8, end-to-end jose verification 6, workload derivation 6, revocation propagation 8, credential-in-log scanning 3)**.
| **H8 cross-tenant isolation (24: probe 23 — 8 REST + 13 in-process + 2 Postgres-gated; plus 1 evidence-seal extension)**.
| **H11 tamper-evident evidence (35: sinks 9 — fan-out, failure isolation, queue bound, token redaction, memory-world env exclusion; witness protocol 4, anchor reconciliation 10, checkpoints 6, federation rehydration 1, retention/holds 5)**.

Plus: policy semantics (10), capability integrity (5), evidence sealing (8),
model output parsing (2), full attack corpus (12 + 3 aggregate), legitimate
workload (2), hostile-model behaviours, 29 M1 enforcement tests (container
sandbox, egress proxy, DNS pinning, envelope secrets, brokered injection,
canary exfiltration, secret-unreachable-from-sandbox, attack corpus with real
backends), session lifecycle (7), approval binding (3), capability binding (1).

Measured this run (stable facts only — the four advisory latency numbers are
regenerated by every `npm test`/`npm run benchmark` invocation, so any copy of
them drifts by construction; read them from `benchmarks/results.json`
(`evidence.*Latency*`) instead of from this doc). `benchmarks/results.json` is
committed at milestone boundaries only — a rerun for a local check leaves it as
an uncommitted artifact, because its absolute timestamps are never
reproducible (audit ticket 17):

- 12/12 attack cases behaved as required; 20/20 adversarial requests denied.
- Prompt-injection-driven requests: 4; successes: 0.
- Legitimate tasks: 2/2 allowed; false-denial rate 0.
- Audit completeness: 2122/2122 decisions recorded; hash chain valid.
- `falseClaimRate` 0 over 101 legitimate responses (fixture guard verdicts +
  100 honest R1-style sessions; target ≤ 1%).
- SLO gate: all 14 assurance targets pass (10 hard, 4 advisory);
  `metrics.slo.pass = true`, exit code 0. M11 added no new hard targets and
  regressed none.

These numbers describe a 12-case corpus written by the same person who wrote the
code. They are not evidence of security against a competent adversary.

## What failed

- Parameter-property syntax (`constructor(private x)`) is not supported by Node's
  type stripping: three modules had to be rewritten with explicit fields.
- Two test bugs found and fixed: a leak-detection regex that matched the benign
  `capabilityId` attribution field, and a self-referential `world` initialization.
- `tsc` initially rejected `.ts` import extensions until
  `allowImportingTsExtensions` was enabled.
- **M12:** the migrate event initially raced `close()` — `whenReady()` resolved
  after connect but before the event's persist was queued to land, losing the
  record (fixed: connect awaits its own persist directly; no double-persist via
  the append queue). The first flip-on-`DATABASE_URL` construction seam broke
  every in-process test world (fixed: opt-in via `EVENT_STORE=postgres`,
  ADR-018 amended). A live-DB run then surfaced: migration id 3 was not
  idempotent on re-apply (fixed: `IF NOT EXISTS`, matching id 1's posture) and
  the backend tamper test needed to disarm the new append-only trigger first
  (fixed, mirroring the SQLite tamper posture). The M12 session audit then
  found the two headline claims unwired (fixed: `store-unavailable` deny
  reason mapped through a typed error; per-tenant sealing wired into the
  runtime write path) and a PG-mode CLI exit hang (fixed: `close()` at each
  command's end, which itself surfaced the write-queue drain race — close now
  ends the pool only after every queued write). A first attempt at queueing
  pre-open appends was reverted with cause: seq assignment raced the chain
  load, so PG-mode construction went through a ready-gated factory instead
  (ADR-018 amended).

No M3-relevant test failure was suppressed. Nothing was skipped or marked
`todo` to make the suite green.

## Known vulnerabilities and gaps

Ordered by severity.

1. **IdP is a trust dependency.** A compromised IdP can issue valid tokens.
   The runtime cannot distinguish stolen tokens from legitimate ones (M2
   accepted tradeoff — ADR-016).
2. ~~**Token replay within the expiry window.**~~ **H2 closed (ADR-028)**: the
   verification seam refuses tokens without a bounded lifetime (`exp - iat`
   ceiling, default 1 h) and a revocation handle (`jti`), and `jti` revocations
   propagate across nodes on the H13 channel. Residual: a stolen valid token is
   replayable inside its (short) window unless its `jti` is revoked;
   revocation propagation is poll-bounded (1 s default); the revoked set is
   in-memory per process (the Postgres channel is the durable coordination
   path); SPIFFE/SPIRE workload attestation remains deferred.
3. ~~**Event log is writable.**~~ **M3 closed**: per-event Ed25519 signatures,
   head-hash anchor file, append-only SQLite triggers, and offline verifier
   detect modification, deletion, recomputation, and tail truncation when the
   anchor is held outside the runtime's trust domain. **H11 closed the
   durability half (ADR-031)**: external anchor sinks (HTTP witness, second
   file), multi-source reconciliation (binding, truncation, **fork**), and
   signed operator-held checkpoints catch a whole-log rewrite — even by a host
   attacker who re-signs the chain — as long as one sink/checkpoint is off-host.
   Residual risk: an attacker who controls the store AND every witness and
   checkpoint (witness-operator collusion / split-view; see Claim 8).
4. **Signing key from an environment variable**, unrotated, symmetric.
   (Capability HMAC key; the Ed25519 event-signing key is generated per
   process unless `EVENT_SIGNING_*_PEM` is set.)
5. **No resource limits at the process level.** The container sandbox enforces
   memory/CPU/PID limits when Docker is available; the host process itself has no
   quotas, timeouts, budgets, or rate limiting.
6. ~~**Policy is code.**~~ **M11 closed (honestly, in part)**: policy and role
   tables load as versioned, attributed, hash-verified bundles
   (`src/policy-config.ts`); a tampered bundle is refused before any rule
   compiles or any event logs, and every bundle load is recorded as a
   `policy.load` event. What remains true: authoring is still in-repo and the
   review gate is git — the hash proves integrity, not review. A committer can
   recompute a hash; signatures and an out-of-band approval service are the
   next step (H10/H12 territory). H10's release manifest now signs the whole
   source tree (policy included) at release time; the load-time hash check's
   residual is unchanged.
7. **Shared process for all tenants.** Logical isolation only; one memory-safety
   bug crosses every boundary. Container sandbox isolates per-task when Docker is
   available. **M12 (Postgres mode) narrows the data blast radius: the database
   enforces tenant isolation on stored rows (RLS) and per-tenant keys bind
   sealed-evidence decryption to tenant identity - but the shared PROCESS
   remains (both modes). H8 (ADR-030) closes the software-surface gaps the
   cross-tenant probe proved (a v2 evidence key opened for its own tenant only;
   capability-request review enforces reviewer tenancy at the decision surface)
   and now covers every REST route and in-process query surface - the shared
   PROCESS remains (physical isolation is Stage 3).**
8. **No transport security in-process.** M14 gives the platform its first
   network ingress (REST API, ADR-019): a `node:http` whitelist router bound
   to loopback with bearer-JWT authn and whitelist parsing. TLS-in-process is
   still not implemented and stays a documented gap — TLS terminates at the
   deployment (reverse proxy/balancer, DEPLOYMENT.md); loopback bind is the
   in-process story. Rate limiting is named not-implemented (H15/deployment).
9. **Detector risk.** `detectInjectionSignals` could be mistaken for a control by
   a future maintainer. It is telemetry.
10. **Unknown-unknowns in the corpus.** 12 cases is a start, not coverage.
11. ~~**Attenuation is declared, not proven.**~~ **H1 closed**: a non-root
    issuer attenuates against its own signed capability (`parent`) — authority
    is derived, never declared; the chain link is recorded in
    `provenance.delegatedFrom` under the child's signature; the service
    refuses revoked/unregistered parents (ADR-023). Residual: the HMAC key is
    symmetric and process-wide (known-gap #4).
12. ~~**No multi-node capability revocation broadcast.**~~ **H13 closed**: the
    revocation channel (ADR-026) propagates kill-switch and single-target
    revocations across nodes and from an operator CLI to a running node;
    pull-on-decision is bounded by the default 1 s interval (≤ 5 s target),
    and issuance force-syncs so a post-freeze mint cannot slip through a
    throttle window. Residual: propagation is poll-based (a channel outage
    widens the window and is reported via `broadcastOk`/health, never silent),
    a channel writer can freeze legitimate work (DoS is the H15 accepted
    trade), in-memory freeze state is lost on restart unless the Postgres
    channel replays it, and the event chain itself remains single-writer by
    design (the channel is the one deliberate multi-writer table).
13. ~~**Fail-closed is incompressible.**~~ **H15 closed (ADR-027)**: every
    dependency fault (engine throw, store unwritable, clock
    stalled/backward/unreadable) now denies with its own distinct reason AND a
    loud observed-health transition; the degraded mode is explicit, deny-only,
    and recoverable; `issue()` is evidence-before-authority; the kill switch
    completes under a store outage; the benchmark carries the decision-latency
    budget (p99 with/without persistence, advisory). Residual: an induced
    fault is still a DoS (accepted ROADMAP trade — now loud, bounded,
    recoverable), and in-memory health resets to `ok` on restart until the
    next observed fault.
14. ~~**Policy cannot express resource hierarchy.**~~ **M5 closed**:
    `PolicyRule.resources.idPatterns` supports recursive `tenant/...` and
    single-segment `prefix*`/`prefix?` globs. Patterns are compiled once at
    engine construction and cached; pathological patterns (>64 chars, `**`,
    unsupported chars) throw `PolicyCompilationError`. Hierarchical matching
    widens which RULES apply; it does not widen which resources a CAPABILITY
    may reach (`Capability.resourceIds` still lists explicit ids).
15. **No IdP circuit breaker.** Every request attempts JWKS fetch during outage.
    Rate limiting is left to the deployment (H15/ADR-027 resolved it as
    deployment territory: the reverse proxy owns request rate limits).

## What M2 closed

1. ~~**No authentication.**~~ Principals carry `AuthContext` from OIDC IdP.
   The PDP rejects any principal without valid auth (invariant 13). MFA enforced
   for approvals and session creation.
2. ~~**Unauthenticated approvals.**~~ `Approval.reviewerAuth` is required and
   must include MFA. Cross-tenant and cross-principal approval reuse is denied.
3. ~~**Agent identity as a global credential.**~~ Agent identity is derived per
   session from the launching human. Session binding connects capabilities and
   approvals to the authenticated human.
4. ~~**Silent IdP outage.**~~ Distinct `denyReason: 'idp-unavailable'` and
   operator-visible health status.

## What M3 closed

1. ~~**Event log is writable.**~~ Per-event Ed25519 signatures, append-only
   SQLite triggers, head-hash anchor file, offline `verifyBundle()`. Detection
   is upgraded to durability when the anchor lives outside the runtime's
   trust domain.

## What M4 closed

1. ~~**No capability revocation.**~~ `AuthorizationService.revoke()` adds the
   capability id to an in-process revocation set; the next `authorize()` call
   denies with `denyReason: 'capability-revoked'`. The revocation is audited in
   the event log.
2. ~~**No request-then-grant flow.**~~ `CapabilityRequestService` lets agents
   request capabilities they do not have; only a `user` principal can approve,
   self-approval is structurally refused, and the reviewer can narrow scope. The
   approval mints a single-use capability scoped to exactly what was approved.
   Request events (`capability.request`, `capability.approve`, `capability.deny`)
   are recorded in the event log as evidence.

## What M5 closed

1. ~~**Policy cannot express resource hierarchy.**~~ `PolicyRule.resources.idPatterns`
   matches hierarchical ids without enumerating them. `tenant/...` matches any
   id strictly under `tenant/` (slash is the boundary — `acme-other` does not
   match `acme/...`). `prefix*` and `prefix?` match a single non-slash segment.
   Patterns are compiled once at engine construction and cached by string
   (`Map<string, IdPatternMatcher>` in `src/policy.ts`); pathological patterns
   (>64 chars, `**`, unsupported chars) throw `PolicyCompilationError`. The
   hot path never compiles; a defensive cache miss falls back to literal match
   and emits one stderr warning. Hierarchical matching widens which RULES
   apply; it does not widen which resources a CAPABILITY may reach —
   `Capability.resourceIds` still lists explicit ids.

## What M6 closed

1. ~~**Operators cannot read their own evidence plane.**~~ `AuditQueryService`
   (`src/audit-query.ts`) and `EventLog.query()` / `EventLog.exportFor()` (`src/events.ts`)
   provide authorized, tenant-scoped evidence query and export capabilities.
   Access requires an authenticated principal, an explicit capability on synthetic
   `audit-log:<tenantId>`, and a policy allow rule; cross-tenant access denies
   fail-closed (`tenant-mismatch`). The service boundary enforces ≤ 90-day time
   ranges and ≤ 1000-event limits via `AuditFilterError`. Events preserve Ed25519
   signatures and event hashes for offline `verifyBundle()` verification; chain
   slices verify using `previousHead`. Sealed content remains sealed in the
   query output (Claim 13 invariant).

## What M7 closed

1. ~~**Policy rules have no first-class test surface.**~~
   `src/policy-testing.ts` exports `simulate(engine, scenarios)`,
   `diffDecisions(before, after, scenarios)`, and `loadFixtures(dir)` with
   validator (rejects malformed JSON, missing fields, action outside
   `KnownAction`, cross-tenant scenarios). `src/policy-diff.ts` is the
   `npm run policy:diff` entry point: argv glue, diffs `BASELINE_POLICY`
   against an optional overlay file, prints `"<n> changed"` plus per-scenario
   before/after. `tests/fixtures/policy/` holds three migrated fixtures
   (default-deny-empty, deny-overrides-allow, classification-ceiling) that
   pass against the unmodified baseline and remain green under a one-line
   no-op overlay. The harness is the test-time artifact; the runtime path is
   unchanged.

## What M8 closed

1. ~~**The text channel is unguarded.**~~ `src/guard.ts` —
   `ResponseGuard` interface; `GroundedResponseGuard` implements D2
   (claim-source binding: verbatim span verification), D3 (session-fact
   consistency: "I <verb>ed X" matches a `StepRecord` action), D4 (numeric
   recomputation against step output), D5 (prose leak check — skips ladder,
   withholds immediately); D6 stub (critic model hook, telemetry only). The
   fallback ladder (`runLadder`) is pure: `flags + repairFn + regenerateFn
   → GuardedResponse`, with rungs Repair → Regenerate → Abstain → Escalate
   (Escalate gated on `classificationRank >= 'confidential'`). D5 leaks skip
   the ladder entirely — strikethrough is not a secrecy control. D6 model-based
   critique is a stub; the upgrade path is a second model pass with critic
   prompt or n-sample agreement. `AgentSession.run()` calls the guard between
   `model.complete()` and trace return; `SessionTrace.guarded` carries the
   user-facing result, and `metadata.sealed` on the `session.guard` event
   holds the encrypted original (AES-256-GCM via `src/seal.ts`). The guard
   holds no authority: `GuardContext` exposes no issuance/authorization/
   secret/grant handle, and `src/pdp.ts` does not import `src/guard.ts`
   (R3 dependency-direction test enforces it). The poisoned-source ceiling
   is documented (TM-002 residual): a poisoned source yields a well-cited lie,
   and D2 cannot detect it — that is the inherent ceiling of evidence-bound
   detection.

## What M9 closed

M9 was a follow-up + repair milestone (not a new Stage 1 row): it closed the
three items SESSION 8 deferred and the six drift items the M7/M8 audit found.

1. ~~**Escalate produced only text.**~~ The Escalate rung now queues a real
   `CapabilityRequest` through M4 when `classification >= confidential` and a
   `CapabilityRequestService` is configured. `submit()` records the
   `capability.request` event; the awaiting-review text and the `session.guard`
   metadata carry the request id. The guard does not own the service and does not
   wait for approval — M4's existing (out-of-band) approval flow gates delivery.
   Deployments without M4 fall back to text-only, and the guard still holds no
   authority (R3 holds).
2. ~~**Classification was hardcoded `'public'`.**~~ `deriveClassification()`
   (`src/runtime.ts`) derives the per-session classification from the principal's
   capability `maxClassification` ceilings, the registry classification of every
   `content` key, and the requested resources; it defaults to `'public'` when
   nothing is visible. This makes the Escalate rung reachable in real workloads.
3. ~~**Guard ran only before execution.**~~ A second pass runs after the
   requested actions execute, on the same model text with the executed `steps`.
   It emits one extra `session.guard` event (`phase: 'guard-second-pass'`) only
   when the verdict (`status` + `flags`) changes; same-verdict passes emit
   nothing and never re-submit a capability request. The trace adopts the
   better-informed second verdict.
4. ~~**Wire-format drift.**~~ `metadata.sealed` is a raw `Sealed` object
   (`.ciphertext`/`.keyId`/`.iv`/`.tag` readable without a JSON-parse step) and
   `metadata.ladderRung` records the rung that fired.
5. ~~**D4 produced duplicate flags.**~~ A bare number is flagged exactly once:
   `unverified-claim` with no steps, `numeric-mismatch` with steps that lack it,
   never both.
6. ~~**`regenerateFn` rung untested; `falseClaimRate` not exported.**~~ Both are
   covered: the rung has success/failure tests (called once, no retry), and
   `evidence.falseClaimRate` / `totalLegitimateResponses` are in
   `benchmarks/results.json`.
7. ~~**D6 had no hook.**~~ `GroundedResponseGuard.guard()` accepts an optional
   `criticFn`; its flags merge before the ladder. No real critic is wired
   (telemetry only).

## What M10 closed

M10 was a measurement milestone (no behavior change to pdp/capability/policy/
guard): it closed ADR-014's "per-control assurance targets, reported on every
benchmark run" promise and the M9 audit's thin-denominator caveat.

1. ~~**Benchmark metrics had no targets and no gate.**~~ `src/slo.ts` —
   `SLO_TARGETS` (one measurable target per control, named measurement) and
   `evaluateSlo(metrics, targets?)`. `npm run benchmark` prints the target
   table, writes `metrics.slo = { pass, hardFailures, targets[] }` to
   `benchmarks/results.json`, and exits nonzero when a `hard` target misses;
   latency is advisory (reported, never gated). The catalog is mirrored in the
   ROADMAP "Assurance targets" table; a test pins the ids and the `slo` block
   shape, and a fabricated-metrics test proves the gate CAN fail.
2. ~~**`falseClaimRate` denominator was 1.**~~ The benchmark now runs the
   R1-style honest corpus (100 `summarizeRepoModel` sessions; ~1 s). Its
   first-pass guard verdicts join the fixture corpus's, so the denominator is
   101 and the non-delivered count covers all of them. The sessions' PDP
   decisions are added to `expectedDecisions`, keeping `auditCompleteness` at
   1.0 (test-asserted).

## What M11 closed

M11 was the authz-depth milestone (three Stage-1 rows, subagents A ∥ B then C,
zero new runtime dependencies). It did not change the decision semantics —
capability AND policy still gate every action — it narrowed what can be
granted and made the grant surface a verified artifact.

1. ~~**Roles were free strings with no definition and no effect on issuance.**~~
   `Role` is data (`src/policy.ts`: `BASELINE_ROLES`, `ROLE_TABLE_VERSION`):
   an action set bounded by a classification ceiling, tenant-scoped
   (`'*'` = tenant-agnostic). `AuthorizationService.issueForRole` builds the
   `IssueRequest` through `issueRequestForRole` (`src/capability.ts`) and then
   flows through the ordinary `issue()` pipeline, so issuer kinds, tenant
   match, and attenuation (invariant 6, ADR-002) apply unchanged. A role can
   never widen a mint: over-privileged requests throw, unknown roles fail
   closed, and a principal that could not mint before still cannot.
   `createPolicyEngine` rejects allow rules that grant a referenced role more
   than the role holds (actions, classification, wildcards) at construction.
2. ~~**Classification was fixed at `defineResource`; derived artifacts
   inherited nothing.**~~ `propagateClassification` computes the max label by
   `classificationRank` (unknown labels rank 100 and win); `ingestDocument`
   reports `derivedClassification` for `derivedFrom` sources;
   `ResourceRegistry.raiseClassification` is the raise-only seam; the runtime
   write path lifts a written target to the max of the step's data sources and
   the execution event records `metadata.derivedClassification`, sealed under
   `evidence-key:<derived>`. Labels only raise; a derived label feeds
   ceilings, never grants.
3. ~~**Policy had no version, signature, review gate, or attribution
   (known-gap #6).**~~ `PolicyBundle`/`RoleBundle` (`src/policy-config.ts`)
   carry `version`, `provenance`, and `hash = sha256(canonicalJson({ version,
   rules | roles }))`; `loadPolicyBundle`/`loadRoleBundle` verify and refuse
   any mismatch before compilation or logging; `createEngineFromBundle`
   appends exactly one `policy.load` event (opt-in seam); `npm run policy:diff`
   verifies versioned overlays before diffing and still loads legacy
   unversioned ones. Stated honestly: authoring is still in-repo, the review
   gate is git, and a hash proves integrity rather than review — the
   residual is recorded in known-gap #6 and Claim 26.

## What M13 closed

M13 was the runtime-realism milestone (three Stage-1 rows, subagents A ∥ B ∥ C
on disjoint surfaces, zero new runtime dependencies — `fetch` is built into
Node 24). It did not change decision semantics: the PDP, capabilities, and
guard are untouched; the model is still assumed compromised.

1. ~~**The only model was `ScriptedModel` — no real provider, and no gate on
   what a provider call discloses.**~~ `HttpModelAdapter` is a real transport
   (OpenAI-compatible, injectable `fetch`), and every call passes the
    **classification egress gate**: the derived classification of the content
    being sent must fit the configured ceiling, and the PDP must allow
    `model.invoke` on the provider resource. Both default-deny; the gate is not
    bypassable by configuration. A provider receives nothing above the ceiling
    that the gate can classify — the whole-content-map max catches undeclared
    ids, an absent map denies — with the free-text residual documented in
    Claim 27's limitations. `model.call` events carry
    id/duration/usage/decision only.
2. ~~**Post-execution verification had only built-in programmatic checks — no
   path to run real linters/SAST.**~~ `CommandCheck` executes a configured
   argv array (never a shell string), allowlisted at configuration time,
   artifact delivered via stdin, minimal environment, timeout → fail. It flows
   through the existing `runVerifications` path, so failed checks already mark
   steps errored — the milestone added a check type, not authority.
3. ~~**Observability was ad-hoc console output.**~~ Structured telemetry
   (JSONL via `TelemetryPort`) covers session start/end, per-session
   deny-reason aggregates (computed from existing decisions — no PDP
   re-entry), and model-call outcomes. Failures are swallowed and counted;
   the PDP never reads telemetry (dependency-direction tests). Scoped
   honestly: it is observability, not a control (Claim 28).

## What M12 closed

M12 was the platform-shift milestone (ADR-018, Postgres control plane;
Phase 0 ADR → Phase 1 backend → Phase 2 B ∥ C on disjoint surfaces; the
second runtime dependency ever admitted, per the ADR-015 policy). Decision
semantics did not change: capability AND policy still gate every action.

1. ~~**There is no multi-node state store.**~~ ADR-018 lands the Postgres
   control plane: `EventStore` port with `PostgresEventLog`
   (`src/event-store-pg.ts`) beside the default SQLite `EventLog`;
   forward-only, versioned, sha256-recorded migrations (ids 1–3) that
   refuse a tampered hash; opt-in via `EVENT_STORE=postgres` +
   `DATABASE_URL`; fail-closed on unreachable store (`store-unavailable`)
   with no silent fallback. Postgres mode is verified live (backend parity
   28 tests); SQLite default unchanged (ADR-010's air-gapped install
   remains a feature, not a deprecation).
2. ~~**Tenant isolation is app-code only (known-gap #7, partially).**~~ The
   database now enforces it in Postgres mode: `FORCE RLS` +
   deny-by-default per-role policies — the `app_reader` role reads only its
   tenant's rows, hostile queries read zero rows (live-tested via
   `SET LOCAL ROLE`; the superuser connection is not the proof). Per-tenant
   evidence keys (`evidence-key:v2:<tenant>:<level>`) bind sealed-evidence
   decryption to tenant identity, no silent re-encryption. What remains
   true: the shared process, and that all of this is Postgres-mode only.
3. ~~**Backups were assumed, not rehearsed.**~~ `tools/backup.ps1`
   (`pg_dump`, plain SQL, docker fallback) plus a restore test that dumps,
   restores into a scratch database, and proves the restored chain verifies
   (`verify()` + signatures + `verifyBundle()` + persistence parity) live.
4. ~~**Nothing survives restart except events.**~~ `PersistenceStore`
   (`src/persistence.ts`) keeps `projects`/`tasks`/`agent_sessions` under
   RLS with tenant-bound CRUD and upserted resumable session state
   (roundtrip + restart tests live). The `capability_requests` table
   exists per ADR-018; ~~its API is a future seam~~ **M15 closed: the
   persistence API exists and the REST capability-request routes mirror to
   it when wired (see "What M15 closed").**

## What M15 closed

M15 was the Stage-0 cleanup milestone (ADR-020: document ingestion, read-only
Git, setup scripts, minimal UI; the M12 capability-request persistence seam
folded in; zero new runtime dependencies — git shells out to the installed
CLI, the UI is static HTML). Decision semantics did not change: capability
AND policy still gate every action, and every new surface is data plumbing
over the existing PDP path.

1. ~~**Ingestion had no chunk/label/classify pipeline.**~~
   `DocumentIngester` (`src/ingestion.ts`) chunks deterministically, labels
   every chunk through the M11 machinery (raise-only), registers chunks as
   capability-scoped registry resources, and seals chunk content into
   `document.ingest` events — no plaintext in the evidence plane, no
   authority minted by hostile documents (Claim 29).
2. ~~**The platform had no repository access.**~~ `GitReader`
   (`src/git-reader.ts`) is read-only by construction: verbs allowlisted at
   configuration time, argv exec with no shell, traversal refused pre-spawn,
   output ingested as a document at the repo's classification (Claim 30).
3. ~~**`capability_requests` had a table but no API (M12 seam).**~~
   `PersistenceStore` gained tenant-bound create/get/list/status methods
   (raw tagged-template SQL, RLS context per transaction); the REST
   capability-request routes mirror to the store when one is wired —
   opt-in, so the M14 in-memory surface is unchanged without it.
4. ~~**There was no developer setup path.**~~ `scripts/setup.ps1` +
   `scripts/setup.sh`: offline, reviewable, fail-closed (nonzero exit on
   any failed check), optional Postgres bootstrap per DEPLOYMENT.md.
5. ~~**The REST surface had no client.**~~ `tools/ui/index.html` — a static
   operator console served by the M14 server (exact routes, no traversal
   surface), posting tasks and querying the audit log through the ordinary
   bearer-JWT contract; the UI shows the trace and never bypasses the guard.

## What M16 closed

M16 was the sandbox-lifecycle milestone (ADR-021: create, limit, destroy,
attest — ROADMAP row 61, the last open Stage 1 row). The lifecycle is a
wrapper over the existing `ContainerSandbox` plumbing, not a reimplementation:
zero new runtime dependencies, attestation reuses `sealFor` (ADR-018) and the
event chain, and the execution seam (`runTool`) is untouched.

1. ~~**The sandbox was created once and left running — no lifecycle.**~~
   `SandboxRegistry` (`src/sandbox-registry.ts`) owns create (synchronous,
   spawn-before-register), tenant-scoped get/list, idempotent destroy, attest,
   and an opt-in process-exit sweep (Claim 31).
2. ~~**Sandbox limits had no typed, auditable config surface.**~~ Limits ARE
   `ContainerSandboxOptions` (re-exported as `SandboxLimits`); `effectiveLimits`
   extracts the Docker-path defaults into one source so attestation records
   effective-vs-declared without drift.
3. ~~**Sandbox execution had no PDP-gated authority surface.**~~
   `SandboxRegistry.execute` authorizes `sandbox.execute` on the sandbox
   resource id through the ordinary `authorize` path (which appends its own
   decision event) before `runTool`; the agent never holds the handle.
4. ~~**No attestation of sandbox state.**~~ `sandbox.create`/`sandbox.destroy`
   /`sandbox.attest` events carry a sealed payload (pid, kind, limits,
   timestamps, duration) under the tenant's `'public'` key plus a SHA-256
   limit-config digest — plaintext events show only digest + keyId.

## What H1 closed

H1 was the root-of-trust milestone (ADR-023, the first Stage 2 item): it did
not change decision semantics — capability AND policy still gate every action
— it changed what issuance accepts as proof of the issuer's own authority.

1. ~~**Attenuation was declared, not proven (known-gap #11).**~~ The declared
   `IssuerAuthority` object is gone from the API. A non-root issuer must
   present `parent` — its own signed capability — and `issueCapability`
   verifies the parent's HMAC signature BEFORE any field is trusted, then
   checks subject match (you delegate only what you hold), same tenant,
   unexpired, and unconsumed. Authority is derived from the parent's fields;
   `findOverreach` is unchanged.
2. ~~**Delegation chains carried no parent signature.**~~ The child's
   `provenance.delegatedFrom` records the parent's `{ id, signature }`, is set
   by `issueCapability` (caller-supplied values overridden), and is covered by
   the child's own HMAC — the chain link is tamper-evident and walkable by id.
3. **Service custody added:** `AuthorizationService.issue` refuses a parent
   that is not registered with it or that is revoked (stateful checks the pure
   function cannot make). Revoked parents cannot mint further authority.

Tests: `tests/h1-signed-delegation.test.ts` (32) + invariant 6 rewritten to
mint real parents. Structural invariant: no `issuerAuthority`/`IssuerAuthority`
symbol remains in any `src/*.ts` (the scan globs the whole tree). The session
audit's four findings were closed the same day: the subset check now covers
constraints (subset, narrowing legitimate) and single-use (leaf authority —
no delegation); parent validity runs for the root too, so no chain link is
recorded from an unvalidated parent; the structural scan globs `src/`; and
custody refusals are audited as `capability.issue` deny events (ADR-023
addendum). Residuals named in Claim 6: the symmetric process-wide HMAC key
(known-gap #4) and the absence of a chain-depth limit (every hop attenuates
strictly, so cycles cannot escalate).

## What H10 closed

H10 was the supply-chain milestone (ADR-024, the second Stage 2 item): it
does not touch the PDP — it changes what the repository will let you build,
commit, and ship.

1. ~~**The SBOM-diff policy item (ADR-015 item 5) was prose, not code.**~~ The
   gate generates a deterministic `ASL-SBOM v1` from the lockfile and diffs it
   against the committed baseline (`artifacts/sbom.json`); any dependency
   drift fails with the added/removed/changed list until the baseline is
   regenerated in a reviewed PR. The SBOM diff is now the dependency review
   gate, not a session discipline.
2. ~~**Pins were ranges; the lockfile pinned silently.**~~ `package.json` is
   exact-pinned (`jose 6.2.12`, `postgres 3.4.9`, dev deps exact) and the gate
   refuses range characters — every version change is now a visible one-line
   diff. Every lockfile package must carry a sha512 integrity hash and a
   `registry.npmjs.org` resolved URL (hash verification, H10 methodology).
3. **No build signing existed.** `build sign` runs the full release gate
   (typecheck + tests + supply-chain) and Ed25519-signs a build manifest
   binding the tree digest (git blob SHAs), SBOM digest, git head, and the
   gate result; `build verify` is the deploy-time check — fail-closed with
   distinct reasons. Unsigned-artifact deploy now means "verify refuses".
4. ~~**The dependency update review gate was a paragraph.**~~ The
   `ADMITTED_RUNTIME_DEPS` allowlist is code: a new runtime dep fails the
   gate with the instruction to write the admission ADR and update the
   allowlist in the same reviewed PR.

Tests: `tests/h10-supply-chain.test.ts` (20, red-confirmed before the module
existed). The gate is wired into the local pre-commit hook (hooks are
untracked; the wiring is documented, not enforced in-repo — no CI exists).
Residuals (Claim 32): signing-key custody is an env var (known-gap #4
family), no transparency log, no CI enforcement, and the trusted-maintainer
residual is unchanged — a coerced maintainer can still land a reviewed PR;
H10 raises the cost of a malicious dependency from "edit a JSON file" to
"forge a reviewable diff AND an ADR in the same PR".

## What M17 closed

M17 (ADR-022) made control-plane the first federation client. The integration
itself lives in the control-plane repo (config + a thin `fetch` client, no code
merge); ASL's side closed the two REST gaps that client surfaced, ticketed
rather than absorbed during the control-plane implementation:

1. ~~**No route accepted a foreign evidence head-hash.**~~ `POST /v1/anchors`
   registers a federation client's log head (the M3 anchor pattern across
   repos) and records it in ASL's own signed event log. Tamper signal: a
   claimed `previousHeadHash` disagreeing with the tenant's last accepted head
   flags `tamper` on the response and in the event metadata.
2. ~~**A requester could not learn its capability request's outcome.**~~
   `GET /v1/capability-requests/:id` returns the request status and, once
   approved, the minted capability projection — so the client can poll for
   approval and record the granted scope instead of the request vanishing from
   the pending-only list.

Both routes enforce the tenant from the verified principal (body tenant must
match, else `tenant-mismatch`), carry no plaintext project content (hash +
counts only), and add no new authority path — the mint remains exactly M4's.
Tests: `tests/m17-federation.test.ts` (13 — the 12 route cases red-confirmed
before the routes existed, plus the session-audit regression test proving a
throwing event append cannot poison the anchor registry). Residuals: the
anchor registry is in-memory (mismatch detection is
advisory; the durable attestation is the event itself) and this is a
shared-process tenant residual (known-gap #7). Client-side bypass is outside
ASL's claim boundary.

## What H12 closed

H12 was the secure-update milestone (ADR-025, the third Stage 2 item): it
does not touch decision semantics — it decides whether the code running the
enforcement may change, and refuses the failure modes ROADMAP named.

1. ~~**The update channel did not exist; unsigned update was RCE by
   design.**~~ `src/updates.ts` defines the signed update descriptor
   (Ed25519 over the canonical descriptor, embedding the H10 build manifest +
   its signature). Verification chains into `verifyManifest`, which recomputes
   the live tree/SBOM digests — a transported value is never trusted. Missing
   key env, bad structure, bad signature, or a stale tree each refuse with a
   distinct reason.
2. ~~**Nothing prevented rollback to a vulnerable version.**~~ A persisted
   high-water mark: `apply` requires `releaseVersion > highWaterMark` and
   raises it; the mark never lowers. Signature validity and freshness are
   separate checks — a perfectly signed, perfectly stale descriptor is
   refused (`rollback-blocked`). A malformed state file is a refusal
   (`state-malformed`), never a silent reset to zero.
3. ~~**Emergency rollback did not exist (the assumption said it must).**~~
   It exists as a signed, single-use grant naming the exact `fromVersion`
   and the state's monotonic `rollbackGeneration` — one use per generation,
   so a used grant stays used even if its from-version becomes current again
   (`grant-mismatch`) — backward-only, and it does not lower the mark — the
   version rolled back *from* stays burned.
4. ~~**No staged rollout, canary, or auto-halt.**~~ Descriptors declare
   ascending stages ending in 100; `apply` lands canary; `promote` advances
   one stage per explicit health pass; a failing signal halts and the halt is
   sticky (only a new descriptor or a rollback grant resolves it). There is
   no default-healthy path to `promoted`.

Tests: `tests/h12-secure-updates.test.ts` (20, red-confirmed before the
module existed — `ERR_MODULE_NOT_FOUND` recorded as the red signal). The
trust-boundary invariant test asserts no key material or PEM headers in the
state file, descriptor, grant, signatures, or any refusal message. Audit 01
(same day) closed the grant replay window it found: single-use is enforced
by a monotonic `rollbackGeneration`, with the regression test added to the
same suite (the red run for it failed with "a used grant must not revive").
Residuals
(Claim 34): the health signal is caller-supplied (garbage-in can promote a
canary), one release key under the ADR-008 env posture, no transport (this
repo verifies updates; hosting them is a release endpoint away), and the
signed-but-maintainer-rogue release residual from H10 is unchanged.

## What H13 closed

H13 was the incident-response milestone (ADR-026; one module pair, two
chokepoint edits, zero new runtime dependencies). It did not change decision
semantics: capability AND policy still gate every action; the kill switch adds
a state that trumps both, and its evidence is the ordinary decision log.

1. ~~**No kill switch.**~~ `IncidentService.engage` freezes issuance and
   authorization (tenant or global) and revokes every registered capability +
   session in scope in one operator action. The PDP denies a frozen tenant
   with the distinct `incident-frozen` reason; `issue` refuses with an audited
   `capability.issue` deny. `lift` clears the freeze only — revoked authority
   remains revoked. Evidence-read capabilities (`query.audit`, `audit.export`,
   `evidence.decrypt`) survive the bulk revoke and remain authorized while
   frozen, so an incident can be reconstructed and preserved during the
   response instead of after it.
2. ~~**No cross-node revocation.**~~ The `revocation_channel` (Postgres
   migration 4; in-memory default) is the deliberate multi-writer control
   table beside the single-writer event chain. Records are scope-level
   (`freeze`/`unfreeze`/`revoke-caps`/`revoke-sessions`) and single-target
   (`revoke-cap`/`revoke-session`); nodes pull on decision (throttled
   `authorize`, forced `issue`), replay from cursor 0 reconstructs state, and
   a channel outage still engages locally with the failure reported.
   `revoke-caps` is fenced by issuance time, so replay cannot kill authority
   issued after the incident.
3. ~~**Cannot reconstruct or preserve evidence at scale.**~~ `preserve` pages
   the ordinary authorized audit export past M6's silent 1000-event cap,
   verifies the bundle offline (content digest + chain + Ed25519 signatures +
   anchor), writes an `asl-incident-bundle`, and records digest + head +
   counts only; `reconstruct` summarizes decisions by reason/action, actors,
   and incident actions over the same authorized slice.

Tests: `tests/h13-incident-response.test.ts` (24, red-confirmed before the
module existed - `ERR_MODULE_NOT_FOUND` recorded as the red signal),
`tests/h13-revocation-pg.test.ts` (7: 3 static/redaction + 4 live, skip
cleanly), and `tests/h13-import-order.test.ts` (1: the channel module must be
importable first - the audit-found import-cycle regression). The
trust-boundary invariant test asserts no key material or secret canaries
reach channel records, incident events, or the preservation artifact.
The same-day session audit (`.scratch/session-audit/2026-10-01-h13-incident-response/`)
found and fixed four must-fix defects: a malformed channel row stalled the
cursor forever (now skip-and-count), cross-process `preserve` failed on the
default ephemeral event key (now a named precondition + actionable refusal),
an inline-type import cycle crashed the channel module (now `import type`),
and global-incident events (`tenantId: ''`) were unreachable (now the
`tenantId: '*'` view). Filtered views are verified per-event
(`contiguous: false` bundles) instead of requiring slice linkage. Residuals
(Claim 35/ADR-026): poll-based propagation, a channel writer can freeze (the
H15 DoS trade), single-node freeze state is in-memory (durability is the
Postgres channel's), the skip-clean live Postgres tests, and the ROADMAP
residual that incident response can be slower than the attack.

## What H15 closed

H15 was the fail-closed availability milestone (ADR-027; one new module,
chokepoint edits in the PDP/incident service/REST health route, zero new
runtime dependencies). It did not change decision semantics: capability AND
policy still gate every action; every fault still denies — it made the denial
distinguishable, observable, and recoverable.

1. ~~**Silent fail-closed.**~~ Every dependency fault now has its own deny
   reason and an observed health transition: engine throws →
   `evaluation-error`; store unavailable → `store-unavailable` (typed
   backend error) or `evidence-write-failure` (any other failed write);
   clock unusable/stalled/backward → `clock-unavailable` (new). None of them
   can produce an allow while faulted.
2. ~~**No health signal / alert spam.**~~ `src/health.ts` `HealthState`
   observes what the decision path experiences (append succeeded/failed,
   engine returned/threw, clock read valid/faulted) and emits one loud
   `process.emitWarning` per transition — down and recovery — instead of one
   warning per denied decision (the M12 per-deny warning became
   transition-based). `ClockGuard` checks the decision clock: throws and
   non-finite readings always fault; stall/backward detection is enabled by
   an injected monotonic reference so deterministic test clocks keep working.
   `GET /healthz` reports `{ idp, store, engine, clock }` when wired (M14
   `{ idp, store }` otherwise).
3. ~~**Safety mechanisms degrade worse than the decision path.**~~ `issue()`
   now records the issuance event **before** registering the capability (a
   store outage refuses the mint; no unaudited authority exists).
   `unfreeze` records evidence before clearing the freeze (a lift that cannot
   be recorded stays frozen — widening needs evidence), while `revoke`/
   `freeze` apply first and report missed evidence (narrowing must not
   abort): `revokeAll` completes the kill switch past per-capability evidence
   failures, and `IncidentService.engage` completes local enforcement during
   a store outage with `evidenceRecorded: false`.
4. ~~**No latency budget.**~~ The benchmark measures `authorize()` p99 with
   persistence (SQLite-file `EventLog`) and without (in-memory), as two
   advisory SLO rows (ADR-014: latency never fails the build). In-process
   sample: ~1.6 ms vs ~0.2 ms.

Tests: `tests/h15-fail-closed-availability.test.ts` (24 — 19 initial + 5
audit-follow-up regression cases; written before
`src/health.ts` existed; the red signal — `ERR_MODULE_NOT_FOUND` without the
module — was verified by the 2026-10-02 audit probe, not captured during the
build — audit ticket 02). The structural invariant test asserts health state,
transitions, and emitted warnings carry no secret values (details are fixed
labels, never error messages). Residuals (ADR-027): `HealthState` is
in-memory (a restart resets to `ok`; the next observed fault re-marks it);
clock trend detection needs the embedder's monotonic wiring (DEPLOYMENT.md);
the engine-fault reason stays shared with other evaluation errors
(`ponytail:` marker, split `engine-unavailable` if operators need it); an
adversary who can induce a fault still gets a DoS — accepted, now loud,
bounded, and recoverable.

**Audit follow-up (2026-10-02):** the same-day session audit found 1 must-fix +
3 should-fix + 4 nits; all 8 tickets fixed with regression tests. The
must-fix: `syncBroadcast` ran before the guarded clock read and read the raw
clock, so with the production broadcast hook installed a faulted clock crashed
`authorize`/`issue` instead of denying `clock-unavailable` (probe-proven on
both paths); the sync body now try/catches its clock reads. Also:
`issue()`'s clock-fault refusal now appends its `capability.issue` deny event;
grant/consume/revoke/freeze use `bookkeepingNow()` (a faulted clock cannot
disable the kill switch or leave a single-use capability unconsumed);
`clockFaultDeny` recovers store health on its successful append; the
"red-confirmed" wording, the prompt's Phase 1 constructor drift, and the
PROJECT_CONTEXT module map are corrected; `queryAudit`'s clock-fault branch is
tested. Tickets: `.scratch/session-audit/2026-10-02-h15-fail-closed-availability/`.

## What H2 closed

H2 was the short-lived-credentials milestone (ADR-028; zero new runtime
dependencies, no new module). It did not change the decision model — the PDP's
single authentication guard (`isAuthenticated`) is unchanged; what changed is
which credentials are worth trusting and for how long.

1. ~~**Leaked long-lived token.**~~ `IdentityProvider.verifyToken` now
   enforces an admission contract: `sub`, `exp`, `iat`, and `jti` are required;
   the declared lifetime (`exp - iat`) must be positive and at most
   `maxTokenLifetimeSec` (default 1 h; the configured ceiling is capped at
   24 h); a `jti` revocation is honored immediately (local set) and across
   nodes (H13 `revoke-token` records consumed by `attachRevocationFeed`;
   `IncidentService.revokeToken` applies local-first, publishes, and audits;
   CLI `incident revoke-token`). A long-lived token is refused at the seam
   even when its signature is perfect.
2. ~~**Clock skew extending life.**~~ Clock tolerance is bounded (default
   30 s, hard cap 60 s; a config outside the bound throws `IdentityConfigError`)
   and — for the first time — actually applied: the old `clockToleranceSec`
   option was silently ignored because jose expects `clockTolerance`. Tokens
   issued beyond tolerance in the future are refused. Total accepted life is
   bounded by `min(declared lifetime, ceiling) + tolerance`.
3. ~~**Credential left in a crash dump or event payload.**~~ Workload identity
   is derived, not inherited: `IdentityProvider.workloadAuth` (and
   `sessionAgent` through it) mints a context with a distinct subject, a
   derivation-linked token id (`wl:<workload>:<parent jti>`), `amr: []`,
   `claims: {}`, and an expiry capped by the parent and a 15-minute default
   workload ceiling. Raw JWTs are never stored on the context; tests scan the
   full event log for a minted token and a payload canary on success and
   failure paths.

Tests: `tests/h2-short-lived-credentials.test.ts` (31 — admission contract +
deterministic 2000-case expiry fuzz, end-to-end jose verification including
the tolerance regression, workload derivation, cross-node revocation
propagation, credential-in-log scanning). Written before the implementation;
the red signal (missing module exports) is captured at `.scratch/h2/red.txt`.
Residuals (ADR-028): window of validity (≤ 1 h default) and in-memory exposure
during processing; a stolen valid token is replayable until expiry unless its
`jti` is revoked; revocation propagation is poll-bounded; the revoked set is
per-process in-memory; `jti`/`sub`/`iat` are now required claims (an IdP that
omits them needs configuration); SPIFFE/SPIRE attestation remains HARD-stage
(skip list).

## What H8 closed

H8 was the cross-tenant-isolation milestone (ADR-030; zero new runtime
dependencies, no new module). The artifact is one table-driven probe
(`tests/h8-cross-tenant-probe.test.ts`) that enumerates the whole
tenant-facing surface — 8 REST routes and 12 in-process query surfaces, plus
2 Postgres-gated storage cases that skip cleanly. Every row asserts isolation
in both directions, a log-scan property, or a named `global-by-design`
exposure. The probe proved two real gaps, both closed in this branch:

1. ~~**A v2 evidence key could be decrypted by the wrong tenant.**
   `revealEvidence` did not check the tenant named by the sealed keyId. A
   tenant-A capability naming tenant B's key (`evidence-key:v2:B:<level>` —
   resource ids are opaque strings, so the mint was legal) registered B's key
   under A and decrypted B's content. It now refuses a foreign keyId before
   any registration or authorization, records one clean deny event in the
   caller's own tenant, and opens with `openFor(principal.tenantId, …)` as a
   second binding (`tenantFromKeyId` is the new seal helper). Legacy
   `evidence-key:<level>` seals keep their documented tenant-agnostic
   behavior.
2. ~~**Capability-request review had no reviewer-tenant predicate.**
   `CapabilityRequestService.approve`/`deny` now refuse a reviewer from
   another tenant — the REST boundary already did; the in-process decision
   surface (embedders, the guard's escalation lane) now holds on its own, and
   a refused review appends nothing.

The probe also pins the H13 global view: `tenantId: '*'` is authorized only by
the caller's own tenant audit capability and exposes only tenant-less events
(reconstruct and preserve), while a cross-tenant window and a caller without
its own audit authority are refused. The log-scan rows assert tenant B's
unique marker and sealed plaintext never appear in tenant A's visible records,
exports, or REST responses.

Tests: `tests/h8-cross-tenant-probe.test.ts` (22: 8 REST, 12 in-process, 2
Postgres-gated skips) + 1 evidence-seal extension in `tests/evidence.test.ts`,
written before the fixes; the red signal (the globex content returned to an
acme clearance; the cross-tenant review accepted) is captured at
`.scratch/h8/red.txt`. Residuals (ADR-030): the shared process (known-gap #7;
physical isolation is Stage 3), SQLite app-level-only checks, hardware side
channels, principal-id collisions on non-tenant-facing helpers, one
`CapabilityRequestService` per root, and the probe's marker-scope limitation.

**Audit follow-up (2026-10-04):** the session audit returned a ship verdict -
no must-fix or should-fix items - and five tracked nits, all resolved in the
follow-up: the `capability-request` docstring audience, the probe's `log-scan`
exposure class (code labels now match ADR-030's three assertion classes), the
reverse direction in the session-manager row, the `revealEvidence` ordering
rationale, and the Claim 38 `deny`-guard note. Suite unchanged: 676 / 655
pass / 0 fail / 21 Postgres-mode skips.

## What H11 closed

H11 was the tamper-evident-evidence milestone (ADR-031; two new modules,
`src/anchors.ts` + `src/retention.ts`, zero new runtime dependencies — the
witness uses the built-in `fetch`). It did not change decision semantics: the
PDP, capabilities, and policy are untouched; the milestone makes the evidence
plane durable against a host attacker who holds the signing key.

1. ~~**The anchor lived inside the runtime's trust domain (Claim 8 residual:
   an attacker with host access rewrites store and anchor consistently).**~~
   `AnchorSink` is the external publication port: `FileAnchorSink` (second
   path, e.g. WORM mount) and `HttpAnchorSink` (operator-configured witness,
   optional env-only bearer token). Publication is non-blocking — bounded
   queue, kick-on-publish + `flushAnchors()`, loud counters — and a throwing
   sink can never break an append. A dead witness degrades detection
   granularity, never availability.
2. ~~**One anchor file, one reader: no fork detection, no reconciliation.**~~
   `verifyAnchoredEvidence` reconciles any number of sources: parse +
   monotone/contiguous seqs, line-to-event binding, head coverage
   (uncovered tail fails closed), a source ahead of the bundle head = tail
   truncation, and two sources disagreeing at one seq = **fork** (anchor
   collusion). No source is reported `unanchored`, never silently verified.
3. ~~**No proof the operator can hold off-host.**~~ `createCheckpoint` signs
   `asl-anchor-checkpoint` with the existing event key (no new key, no new
   authority); `verifyCheckpoint` refuses truncation, rewrite (proven by a
   test that re-signs a truncated chain with the same key), broken checkpoint
   chaining, same-seq forks, and bad signatures. The operator moves the file
   off-host — H11's "at least one append-only store the runtime cannot
   rewrite" with no live service.
4. ~~**The federation anchor registry was in-memory (M17 marker).**~~
   `AnchorRegistry` rehydrates accepted heads from `anchor.register` events, so
   a restarted registry still flags a rolled-back client head.
5. ~~**Clock manipulation was unexamined; retention was implicit.**~~
   Timestamps live inside the signed body (any edit breaks hash/signature);
   regressions are additionally reported as non-fatal anomalies, and witness
   records carry the witness clock. `RetentionLedger` records legal holds as
   signed `evidence.hold`/`evidence.release` events (replayed from the log,
   tenant-bound: a principal may only hold its own tenant; the H8 probe has the
   new `retention-ledger-tenancy` row). Retention is structural — no
   update/delete path exists at any layer, and storage DELETE still aborts.

Tests: `tests/h11-tamper-evident-evidence.test.ts` (35, red-confirmed before
the module existed — `ERR_MODULE_NOT_FOUND` captured at `.scratch/h11/red.txt`)
+ the H8 probe row (23 cases now). Residuals (ADR-031): a host attacker who
controls the store *and* every witness/checkpoint; witness-operator collusion
or a coordinated split view; signing-key custody (ADR-008 family, unchanged);
no prune path exists yet, so the hold ledger is the contract a future
prune/archive tool must consult rather than a live gate.

## Watch-items from the M9 audit

Not vulnerabilities — deliberate ceilings with named upgrade paths (details in
Claim 23's limitations and RELIABILITY §8):

1. Derived per-session classification is coarse (max over all principal
   capabilities and the full content map; conservative by design). Upgrade:
   derive from per-session granted caps only.
2. ~~Benchmark `falseClaimRate` denominator is 1 legitimate-corpus verdict per
   run.~~ **M10 closed**: the benchmark runs the R1-style honest corpus
   (N=100); the denominator is 101 (`evidence.totalLegitimateResponses`, floor
   ≥ 100 is a hard assurance target). See "What M10 closed".
3. A failed `CapabilityRequestService.submit()` degrades to the text-only
   withhold without a distinct error marker on the `session.guard` event.
   Upgrade: a `guard.error` marker.

## Known assumptions

- The runtime process is not compromised.
- The clock is monotonic and not manipulated by an operator.
- Operators who can change policy are honest.
- The filesystem and SQLite file are not adversarially mutable at rest, or at
  least one H11 anchor sink / operator-held checkpoint lives outside the
  runtime's trust domain (ADR-031).
- Resource ids are not secret; authorization is the boundary.
- TypeScript types hold at runtime (no attacker rewriting the module graph).
- Customers will author sane capabilities. The platform constrains scope; it
  cannot constrain judgment.
- Docker is available for full isolation; without it, the sandbox falls back to
  in-process execution.
- The IdP is trusted and correctly enforces MFA.
- The signing key (Ed25519 event-signing and HMAC capability-signing) is held
  by the runtime and not by an adversary.

## Reproducing this snapshot

```bash
npm install            # exact-pinned; CI should use npm ci (H10)
npm run supply-chain   # H10 gate: SBOM diff vs artifacts/sbom.json, pins, integrity, allowlist
npm run typecheck
npm test
npm run demo
npm run attack
npm run benchmark
```
