# CURRENT STATE

Honest snapshot. Updated after M7/M8 — policy testing framework and output
reliability layer landed.

## What exists

TypeScript foundation on Node 24, ~4,500 lines of source across 27 modules
(`src/`), 243 test assertions (`tests/`, `security-tests/`), a 12-case attack
corpus (`security-attacks/`), legitimate-task fixtures and a document corpus
(`security-fixtures/`), three policy fixtures (`tests/fixtures/policy/`), five
threat models (`threat-models/`), a measured benchmark (`benchmarks/results.json`),
and this documentation set.

Runtime dependencies: **1** (`jose` — JWT/JWK verification, ADR-015). Dev
dependencies: `typescript`, `@types/node`.

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
- **Output reliability layer (M8):** `GroundedResponseGuard` (`src/guard.ts`)
  implements D2–D5 detection with a pure `runLadder` fallback (Repair →
  Regenerate → Abstain → Escalate; Escalate gated on classification).
  `AgentSession.run()` wires the guard between `model.complete()` and trace
  return; `SessionTrace.guarded` carries the result and `metadata.sealed`
  holds the encrypted original. D5 leaks skip the ladder; D6 critic model is
  a stub (telemetry only). Guard holds no authority (R3 dependency test).
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

All 243 assertions pass. Coverage of the twelve invariants plus M2, M3, M4, M5,
M6, M7, M8:

1 no capability -> deny (3) | 2 model cannot mint (3) | 3 document cannot
mint (2) | 4 tool cannot expand (2) | 5 expiry (2) | 6 attenuation (4) | 7
decisions logged (2) | 8 tamper-evidence (5) | 9 tenant isolation (3) | 10
network (3) | 11 secrets (2) | 12 fail closed (3) | **13 no unauthenticated
principal (6)** | **M3 signatures/anchor/offline (13)** | **M4 authorization
lifecycle (13)** | **M5 hierarchical matching (19)** | **M6 audit query + export (20)**
| **M7 policy testing framework (12)** | **M8 reliability layer + R1-R3 (26)**.

Plus: policy semantics (10), capability integrity (5), evidence sealing (6),
model output parsing (2), full attack corpus (12 + 3 aggregate), legitimate
workload (2), hostile-model behaviours, 29 M1 enforcement tests (container
sandbox, egress proxy, DNS pinning, envelope secrets, brokered injection,
canary exfiltration, secret-unreachable-from-sandbox, attack corpus with real
backends), session lifecycle (7), approval binding (3), capability binding (1).

Measured this run (`benchmarks/results.json`):

- 12/12 attack cases behaved as required; 20/20 adversarial requests denied.
- Prompt-injection-driven requests: 4; successes: 0.
- Legitimate tasks: 2/2 allowed; false-denial rate 0.
- Audit completeness: 2022/2022 decisions recorded; hash chain valid.
- Audit query latency p99: 0.262 ms; audit export latency p99: 0.231 ms.
- Policy diff latency: 0.119 ms (one run, sub-ms).
- Guard latency p99: 0.007 ms (1000 runs of a small honest input).

These numbers describe a 12-case corpus written by the same person who wrote the
code. They are not evidence of security against a competent adversary.

## What failed

- Parameter-property syntax (`constructor(private x)`) is not supported by Node's
  type stripping: three modules had to be rewritten with explicit fields.
- Two test bugs found and fixed: a leak-detection regex that matched the benign
  `capabilityId` attribution field, and a self-referential `world` initialization.
- `tsc` initially rejected `.ts` import extensions until
  `allowImportingTsExtensions` was enabled.

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
6. **Policy is code.** Anyone who can edit the repository can edit the security
   boundary. No signature, versioning, review gate, or attribution.
7. **Shared process for all tenants.** Logical isolation only; one memory-safety
   bug crosses every boundary. Container sandbox isolates per-task when Docker is
   available.
8. **No transport security** because there is no transport.
9. **Detector risk.** `detectInjectionSignals` could be mistaken for a control by
   a future maintainer. It is telemetry.
10. **Unknown-unknowns in the corpus.** 12 cases is a start, not coverage.
11. **Attenuation is declared, not proven.** `issuerAuthority` is an object the
    caller supplies; a caller can overstate it. Delegation must carry the
    parent's signature (ADR-002, H1).
12. **No multi-node capability revocation broadcast.** In-process revocation is
    immediate; a multi-node deployment needs a revocation channel (H13).
13. **Fail-closed is incompressible.** A broken engine, full disk, or closed
    evidence store denies everything silently, with no health signal or degraded
    mode (H15). IdP outage now has a distinct deny reason and health signal.
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
