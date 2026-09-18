# CURRENT STATE

Honest snapshot. Updated after M14 — REST API surface (ADR-019): the
platform's first network ingress, a `node:http` whitelist router with
bearer-JWT authn, tenant-from-principal derivation, whitelist body/response
parsing, and a fail-closed error mapping over the ONE existing decision
path — zero new runtime dependencies. M12's Postgres control plane, M13's
runtime realism, M11's authz depth and M10's SLO gate remain the
non-regression baseline.

## What exists

TypeScript foundation on Node 24, ~8,160 lines of source across 37 modules
(`src/` — `rest-api.ts`, `rest-sessions.ts`, and `rest-audit.ts` are M14's
additions), 439 tests (`tests/`, `security-tests/`; 426 pass, 13
Postgres-mode tests skip cleanly without `DATABASE_URL`), a 12-case attack
corpus (`security-attacks/`), legitimate-task fixtures and a document corpus
(`security-fixtures/`), three policy fixtures (`tests/fixtures/policy/`), five
threat models (`threat-models/`), a measured benchmark (`benchmarks/results.json`),
and this documentation set.

Runtime dependencies: **2** (`jose` — JWT/JWK verification, ADR-015;
`postgres` 3.4.9 — Postgres event backend, ADR-018, zero transitive deps).
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
  returned), `GET /healthz` → `{ idp, store }` (H15's first operator health
  endpoint since M2). Named non-goals: rate limiting (H15/deployment), CORS
  (same-origin loopback), TLS-in-process (loopback bind; termination is the
  deployment's job — DEPLOYMENT.md), WebSockets, streaming.
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
- Typecheck: clean (`npx tsc --noEmit`).

## What was tested

All 439 tests pass (426 green; 13 Postgres-mode tests skip without
`DATABASE_URL`/`RESTORE_DATABASE_URL`; the Postgres suites were verified
live at 28 + 17 + 5 tests against a disposable container). Coverage of the
twelve invariants plus M2, M3, M4, M5, M6, M7, M8, M9, M10, M11, M13, M14:

1 no capability -> deny (3) | 2 model cannot mint (3) | 3 document cannot
mint (2) | 4 tool cannot expand (2) | 5 expiry (2) | 6 attenuation (4) | 7
decisions logged (2) | 8 tamper-evidence (5) | 9 tenant isolation (3) | 10
network (3) | 11 secrets (2) | 12 fail closed (3) | **13 no unauthenticated
principal (6)** | **M3 signatures/anchor/offline (13)** | **M4 authorization
lifecycle (13)** | **M5 hierarchical matching (19)** | **M6 audit query + export (29)**
| **M7 policy testing framework (12)** | **M8 reliability layer + R1-R3 (26)**
| **M9 guard follow-ups + drift closure (26)** | **M10 assurance-target gate (5)**
| **M11 authz depth (35: RBAC 12, propagation 11, bundles 12)**
| **M13 runtime realism (33: adapter + egress gate 14, command checks 10, telemetry 9)**
| **M12 platform shift (50: backend parity 28, tenant RLS + keys 17, persistence/restore 5)**.
| **M14 REST API (50: server core + authn/whitelist/fail-closed 20, sessions + capability requests 18, audit + tasks 12)**.

Plus: policy semantics (10), capability integrity (5), evidence sealing (6),
model output parsing (2), full attack corpus (12 + 3 aggregate), legitimate
workload (2), hostile-model behaviours, 29 M1 enforcement tests (container
sandbox, egress proxy, DNS pinning, envelope secrets, brokered injection,
canary exfiltration, secret-unreachable-from-sandbox, attack corpus with real
backends), session lifecycle (7), approval binding (3), capability binding (1).

Measured this run (stable facts only — the four advisory latency numbers are
regenerated by every `npm test`/`npm run benchmark` invocation, so any copy of
them drifts by construction; read them from `benchmarks/results.json`
(`evidence.*Latency*`) instead of from this doc):

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
2. **Token replay within the expiry window.** No revocation cache or token
   blacklist. The IdP's token lifecycle is the control.
3. ~~**Event log is writable.**~~ **M3 closed**: per-event Ed25519 signatures,
   head-hash anchor file, append-only SQLite triggers, and offline verifier
   detect modification, deletion, recomputation, and tail truncation when the
   anchor is held outside the runtime's trust domain. Residual risk: anchor
   rewrite by an attacker with host access (see Claim 8).
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
   next step (H10/H12 territory).
7. **Shared process for all tenants.** Logical isolation only; one memory-safety
   bug crosses every boundary. Container sandbox isolates per-task when Docker is
   available. **M12 (Postgres mode) narrows the data blast radius: the database
   enforces tenant isolation on stored rows (RLS) and per-tenant keys bind
   sealed-evidence decryption to tenant identity — but the shared PROCESS
   remains (both modes).**
8. **No transport security in-process.** M14 gives the platform its first
   network ingress (REST API, ADR-019): a `node:http` whitelist router bound
   to loopback with bearer-JWT authn and whitelist parsing. TLS-in-process is
   still not implemented and stays a documented gap — TLS terminates at the
   deployment (reverse proxy/balancer, DEPLOYMENT.md); loopback bind is the
   in-process story. Rate limiting is named not-implemented (H15/deployment).
9. **Detector risk.** `detectInjectionSignals` could be mistaken for a control by
   a future maintainer. It is telemetry.
10. **Unknown-unknowns in the corpus.** 12 cases is a start, not coverage.
11. **Attenuation is declared, not proven.** `issuerAuthority` is an object the
    caller supplies; a caller can overstate it. Delegation must carry the
    parent's signature (ADR-002, H1).
12. **No multi-node capability revocation broadcast.** In-process revocation is
    immediate; a multi-node deployment needs a revocation channel (H13). M12
    gives Postgres mode the storage it needs (one writer is still enforced:
    `PostgresEventLog` is single-process, single-writer — a second node must
    land the revocation channel first).
13. **Fail-closed is incompressible.** A broken engine, full disk, or closed
    evidence store denies everything silently, with no health signal or degraded
    mode (H15). IdP outage now has a distinct deny reason and health signal.
    **M12 adds a third: an unreachable/mid-migration Postgres denies with
    `store-unavailable` and a loud event — the degraded mode is explicit.**
14. ~~**Policy cannot express resource hierarchy.**~~ **M5 closed**:
    `PolicyRule.resources.idPatterns` supports recursive `tenant/...` and
    single-segment `prefix*`/`prefix?` globs. Patterns are compiled once at
    engine construction and cached; pathological patterns (>64 chars, `**`,
    unsupported chars) throw `PolicyCompilationError`. Hierarchical matching
    widens which RULES apply; it does not widen which resources a CAPABILITY
    may reach (`Capability.resourceIds` still lists explicit ids).
15. **No IdP circuit breaker.** Every request attempts JWKS fetch during outage.
    Rate limiting is left to the deployment.

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
   exists per ADR-018; its API is a future seam.

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
- The filesystem and SQLite file are not adversarially mutable at rest.
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
npm install
npm run typecheck
npm test
npm run demo
npm run attack
npm run benchmark
```
