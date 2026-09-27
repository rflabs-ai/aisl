# SECURITY CLAIMS

Every claim below uses the required structure. Nothing is claimed that is not
tested. Where a claim has a ceiling, the ceiling is stated — not buried.

---

## Claim 1 — No action without a capability

**Claim:** An agent principal cannot invoke a protected action on a resource unless a
valid, unexpired, HMAC-verified capability naming that resource and action exists and
a policy rule permits the action.

**Mechanism:** `AgentSession.attempt` -> `AuthorizationService.authorize`
(capability check, then policy check); `verifyCapability` for integrity, subject,
tenant, expiry, single-use, scope, classification ceiling, constraints.

**Threat model:** TM-001 (compromised model), TM-002 (injection), TM-003 (domains).

**Assumptions:** the runtime process is not compromised; the policy set is what
the operator intended; the signing key is secret.

**Evidence:** `npm test` (full suite; counts per milestone in CURRENT_STATE.md);
`benchmarks/results.json` reports `unauthorizedActionDenialRate`.

**Test:** `tests/invariants.test.ts` invariant 1 (three cases, including
"capability alone is not enough").

**Known limitations:** a capability issued too broadly makes the abuse
legitimate. The control constrains scope; it does not judge intent.

**Residual risk:** operator error in capability scope.

---

## Claim 2 — A model cannot create authority

**Claim:** No model output can cause a capability to be issued. `issueCapability`
rejects any issuer whose `kind` is `model`, `tool`, or `agent`.

**Mechanism:** `CAPABILITY_ISSUER_KINDS` allowlist at `src/capability.ts:134`;
model output parsed through a field whitelist at `src/model.ts:42`;
`ActionRequest` has no authority field.

**Threat model:** TM-001.

**Assumptions:** the runtime is not compromised; TypeScript types are not
modified at runtime by an attacker with code execution.

**Evidence:** invariant 2 tests; attack corpus ATK-004.

**Test:** `tests/invariants.test.ts` invariant 2 (issuance throws; request
denied; capability count unchanged after a hostile model turn).

**Known limitations:** enforcement is in-process. A compromised runtime can call
`issueCapability` directly — as it could call anything.

**Residual risk:** process compromise; insider with code access.

---

## Claim 3 — A document cannot create authority

**Claim:** No content ingested from a document, repository, web page, email, or
tool result can produce a capability or alter an authorization decision.

**Mechanism:** there is no code path from text to capability;
`IngestedData.authority === 'none'`; the injection detector's output is never
read by the authorization path.

**Threat model:** TM-002.

**Assumptions:** none beyond process integrity.

**Evidence:** invariant 3 tests; ATK-002, ATK-008; benchmark reports
`promptInjectionSuccesses: 0` for the current corpus.

**Test:** `tests/invariants.test.ts` invariant 3.

**Known limitations:** injected content can still influence *which legitimate
action* the agent requests within its granted scope.

**Residual risk:** semantic manipulation inside authorized scope. Unavoidable
without solving goal correctness.

---

## Claim 4 — A tool cannot expand its own authority

**Claim:** A tool invoked by a session receives an `ExecutionContext` that exposes
no capability-issuance handle, no authorization service, and no secret store.

**Mechanism:** `ExecutionContext` (`src/runtime.ts:27`) is constructed by the
session; tools receive it and nothing else. When `ContainerSandbox` is active,
tool code executes inside a Docker container with non-root user, read-only
rootfs, no network namespace, seccomp default profile, and memory/CPU/PID/time
limits.

**Threat model:** TM-001, TM-002.

**Assumptions:** the Docker daemon is running and the container image is trusted;
when Docker is unavailable, `ContainerSandbox` falls back to `LocalSandbox`
(zero isolation, documented ceiling).

**Evidence:** invariant 4 test enumerates context keys and asserts none match
`issue|authoriz|secret|grant|admin`. Enforcement tests verify Docker detection,
fallback behaviour, and that secret values never appear in the execution context.

**Test:** `tests/invariants.test.ts` invariant 4;
`tests/enforcement.test.ts` container sandbox suite.

**Known limitations:** when Docker is unavailable, the sandbox falls back to
in-process execution. The `ContainerSandbox` kind string includes `fallback` in
this case, making the ceiling visible. Full tool-code-in-container execution
requires a bundled runner image (next step).

**Residual risk:** reduced from HIGH to MEDIUM when Docker is available. Falls
back to HIGH when Docker is unavailable.

---

## Claim 5 — Expired, consumed, and revoked capabilities are refused

**Claim:** A capability whose expiry has passed, whose single-use has been
consumed, or whose id appears in the revocation set, fails verification and
cannot authorize an action.

**Mechanism:** `verifyCapability` expiry and `usedAt` checks; `markUsed` after a
successful execution; issuance refuses an expiry in the past; `AuthorizationService.revoke`
adds the capability id to an in-memory revocation set, checked before signature
verification in the authorization path.

**Threat model:** TM-001 (replay), TM-003.

**Assumptions:** a monotonic clock. A clock that runs backwards extends capability life.
Revocation is in-process — multi-node deployments require broadcast (future work).

**Evidence:** invariant 5 tests; `tests/authorization-lifecycle.test.ts`
revocation suite.

**Test:** `tests/invariants.test.ts` invariant 5; `tests/capability.test.ts`
single-use case; `tests/authorization-lifecycle.test.ts` revocation tests.

**Known limitations:** clock is in-process and not authenticated; no replay cache
across processes; multi-node consumption is not atomic; revocation set is
in-process — a revoked capability on node A is still usable on node B until
broadcast lands.

**Residual risk:** clock manipulation by an operator; race in a future
distributed deployment; multi-node revocation propagation delay.

---

## Claim 6 — Capabilities cannot exceed their issuer's authority

**Claim:** A non-root issuer can only mint a capability that is a subset of its own
resources, actions, classification ceiling, and expiry.

**Mechanism:** `findOverreach` attenuation check at `src/capability.ts:296`;
issuers other than the authorization root must present `parent` — their own
signed capability (ADR-023). The parent is verified before any field is
trusted: HMAC signature, `parent.subject === issuer.id` (you delegate only
what you hold), same tenant, unexpired, unconsumed. The attenuation authority
is DERIVED from the parent's own fields, never declared; the child records the
chain link (`provenance.delegatedFrom` = parent id + parent signature) under
its own signature, and a caller-supplied `delegatedFrom` is overridden.
`AuthorizationService.issue` adds custody: the parent must be registered and
not revoked. Revocation is checked in `AuthorizationService.evaluate()` before
attenuation, so a revoked capability fails before signature or scope
verification.

**Threat model:** TM-001, TM-003.

**Assumptions:** the root principal is trustworthy; the HMAC capability key is
process-resident (known-gap #4).

**Evidence:** invariant 6 tests (rewritten against signed parents) plus the H1
suite: tampered/forged parents, foreign-subject parents (the declared-object
bypass), cross-tenant, expired, consumed, revoked, and unregistered parents,
two-hop chains, an issuance-fuzzing extremes matrix, and a structural test
asserting no declared-authority symbol remains in `src/`.

**Test:** `tests/invariants.test.ts` invariant 6;
`tests/h1-signed-delegation.test.ts`.

**Known limitations:** the chain is provable within the process's HMAC key
domain; portable cross-process chains wait for per-issuer asymmetric keys
(ADR-008). Every hop attenuates strictly, so a delegation cycle cannot
escalate, but no explicit chain-depth limit exists (ADR-023 residual).
Hierarchical matching (`PolicyRule.resources.idPatterns`,
M5) adds a way to express a scope ceiling without enumerating ids, but it does
not weaken attenuation: the matcher still respects the per-rule resource
ceiling and the per-capability `resourceIds` array. If a capability lists
specific resource ids, the matcher only succeeds against those ids; patterns in
the rule do not expand the set of ids the capability may reach.

**Residual risk:** key theft (known-gap #4) — an attacker holding the
capability signing key can mint validly-signed parents. Chain-depth policy is
deferred until a workload demands long chains.

---

## Claim 7 — Every decision is recorded

**Claim:** Every authorization decision, allow or deny, appends exactly one audit
event containing principal, actor, action, resource, decision, deny reason,
policy id, capability id, and result.

**Mechanism:** `authorize()` appends before returning and has no early-return
path that skips it; the event log is the only sink.

**Threat model:** TM-004.

**Assumptions:** the process survives to append; the store is reachable.

**Evidence:** invariant 7 tests; benchmark `auditCompleteness` = decisions
logged / decisions made.

**Test:** `tests/invariants.test.ts` invariant 7.

**Known limitations:** appends are synchronous. There is no write-ahead
durability guarantee against a crash between the action and the event, and
no automatic external publication of the anchor file (the runtime appends
to a configurable anchor path on each event; periodic publication to a
transparency log or WORM bucket is a deployment-level concern, HARD stage).

**Residual risk:** log destruction by an attacker with filesystem access.

---

## Claim 8 — The audit log is tamper-evident and externally anchored (M3)

**Claim:** Modifying, deleting, reordering, or appending events is detected.
Tail truncation (removing the newest events) is detected when the bundle is
reconciled against the head hash recorded in the anchor file. Each event is
signed with an Ed25519 key separate from the HMAC capability signing key, and
the verifier works offline against the exported bundle.

**Mechanism:** SHA-256 hash chain over canonical JSON of each event including
the previous event's hash (`src/events.ts:83`); Ed25519 signature per event
covering the same body (`src/events.ts:147`); append-only SQLite with
`BEFORE UPDATE/DELETE` triggers that raise `security_events is append-only`
(`src/events.ts:204`); head-hash anchor file (`<seq>:<eventHash>\n`,
`src/events.ts:269`); standalone `verifyBundle()` verifier that operates
entirely on an exported bundle plus optional public key and anchor content
(`src/events.ts:357`).

**Threat model:** TM-004 (evidence store as a target).

**Assumptions:** the anchor file path is on a medium the attacker cannot
silently rewrite (filesystem ACLs, WORM storage, or a customer-held witness).
The signing key is kept separate from the evidence store.

**Evidence:** invariant 8 tests; M3 tests (`tests/m3-evidence-hardening.test.ts`,
13 cases including signature tamper, tail truncation, anchor tampering,
offline verify, and the structural check that EventLog has no update or
delete method); benchmark `hashChainValid`.

**Test:** `tests/invariants.test.ts` invariant 8;
`tests/m3-evidence-hardening.test.ts`.

**Known limitations:** an attacker with host access can rewrite both the
event store and the anchor file *consistently* if they hold the signing key —
that is the residual risk and the reason the anchor is meant to live on a
witness the attacker does not control (a customer-held WORM bucket, a
transparency log, or a separate storage tier). Verification without the
public key still detects modification and tail truncation via the hash chain;
signature verification is what proves *who* signed each event. Rotation of
the signing key is not implemented — a key compromise requires re-signing
history (a migration, not a flag), same caveat as ADR-013.

**Residual risk:** MEDIUM when the anchor file is on attacker-accessible
storage; LOW when the anchor is on a witness outside the runtime's trust
domain. Hardware-backed key custody (HSM/TPM) and external transparency-log
publication are HARD-stage items that close the residual.

---

## Claim 9 — Tenants cannot reach each other

**Claim:** A principal in tenant A is denied access to any resource in tenant B,
and a capability issued in tenant A cannot be used by a tenant B principal.

**Mechanism:** `src/pdp.ts:273` tenant equality check before policy;
`@tenant-isolation` deny inside the engine; issuance refuses cross-tenant
subjects; capabilities bind `tenantId`. **M12 (Postgres mode):** the
DATABASE enforces isolation on the control-plane tables — `ENABLE`+`FORCE
ROW LEVEL SECURITY` with deny-by-default per-role policies
(`src/tenant-rls.ts`, `src/persistence.ts`): `app_reader` sees only rows
whose `tenant_id` equals the per-transaction context
(`set_config('app.tenant_id', ..., is_local := true)`), unset context →
NULL → false → **zero rows against hostile queries** (tested via
`SET LOCAL ROLE app_reader` from a superuser connection — superuser itself
is not the proof); per-tenant evidence keys (`sealFor`/`openFor`,
`evidence-key:v2:<tenant>:<level>`) bind decryption to tenant identity, so
one tenant's sealed evidence does not open under another tenant's key.

**Threat model:** TM-003.

**Assumptions:** single control-plane process; resource records carry the
correct tenant id; in Postgres mode the app connects as the non-superuser
`app_rw` role (superuser bypass is operator discipline, enforced by
DEPLOYMENT.md's role setup).

**Evidence:** invariant 9 tests (three cases); ATK-003; M12 live-DB RLS
proofs (17 tests against a real Postgres: zero rows without context, zero
cross-tenant rows, INSERT with wrong context rejected, no cross-tenant
seal opening); SQLite-mode parity suite (memory + SQLite backends).

**Test:** `tests/invariants.test.ts` invariant 9;
`tests/tenant-rls.test.ts` (live-DB RLS proofs);
`tests/event-store-pg.test.ts` (backend parity).

**Known limitations:** logical isolation only. All tenants share one
process and one memory space. In SQLite mode they share one SQLite table
(app-level checks are the only control); SQL-level isolation exists only
in Postgres mode (`EVENT_STORE=postgres`), where it covers the database —
not the shared process memory.

**Residual risk:** memory-disclosure or serialization bugs cross the
boundary in both modes; a superuser connection bypasses RLS entirely.

---

## Claim 10 — Unauthorized network destinations are denied

**Claim:** Egress to any host not explicitly allowlisted by a capability constraint
**and** a policy rule is denied. IP literals are blocked at the proxy layer.
Sessions have no route out except through the egress proxy.

**Mechanism:** `EgressProxy` (`src/egress-proxy.ts`) intercepts HTTP traffic,
blocks IP literals, and routes every request through the PDP before forwarding.
`NetworkGateway` (`src/gates.ts`) makes the same decision via the PDP. The
sandbox runs with `--network none` when Docker is available, so all traffic
must pass through the proxy. Canary-exfiltration tests generate unique tokens per
classification level and assert they never appear at any egress endpoint.

**Threat model:** TM-001, TM-002.

**Assumptions:** the sandbox enforces `--network none` (Docker only); the proxy
is the only route out; DNS resolution returns only allowlisted hosts.

**Evidence:** invariant 10 tests including normalization bypass attempts;
ATK-006; enforcement tests verify IP literal blocking, canary exfiltration
tokens never leak, and `proxyEnv` configuration.

**Test:** `tests/invariants.test.ts` invariant 10;
`tests/enforcement.test.ts` egress proxy and canary suites.

**Known limitations:** HTTPS CONNECT tunneling is not yet implemented (HTTP
only). DNS pinning is the caller's responsibility - the proxy blocks IP
literals but does not yet pin DNS resolution, so **an allowlisted hostname may
still resolve to a private or link-local address (cloud metadata at
169.254.169.254)**. Forwarded requests have no body-size or timeout limit.
DNS pinning, SSRF range checks, and quotas are H7, not done. When Docker is
unavailable, the `--network none` constraint does not apply and the proxy is the
only remaining control.
enforcement layer.

**Residual risk:** MEDIUM when Docker is available (proxy + network namespace).
HIGH when Docker is unavailable (proxy only).

---

## Claim 11 — Secrets require explicit authorization

**Claim:** An agent cannot obtain a secret value unless a capability naming that
secret and a policy rule permitting `secret.use` both exist, plus any required
approval. Secrets are envelope-encrypted at rest with AES-256-GCM; the master
key is never logged. Evidence records receive a redacted placeholder, not the
plaintext value.

**Mechanism:** `EnvelopeSecretBroker` (`src/envelope-secrets.ts`) encrypts each
secret with a unique DEK derived via HKDF-SHA256 from a master key. Access is
gated by the PDP; baseline policy grants no `secret.use` rule, so the default
is denial. The broker decrypts only after authorization and records
`[decrypted-withheld]` in the event log.

**Threat model:** TM-001, TM-003.

**Assumptions:** the master key is stored in an environment variable or file and
is not logged; secrets registered with the broker are the only secrets; Docker
is not required for this control.

**Evidence:** invariant 11 tests (default deny, and an explicit break-glass path
that is allowed); enforcement tests verify encrypt/decrypt roundtrip, wrong-key
failure, default deny, break-glass decryption, event-log redaction, cross-tenant
denial, and that secret values never appear in the execution context.

**Test:** `tests/invariants.test.ts` invariant 11;
`tests/enforcement.test.ts` envelope encryption and secret-unreachable suites.

**Known limitations:** single master key, no rotation, no KMS/HSM backing.
Short-lived dynamic credentials and brokered injection (the agent never sees
the value) are the next steps. The master key is in an environment variable,
not a hardware security module.

**Residual risk:** MEDIUM (envelope encryption at rest, PDP-gated access).
Reduces to LOW with KMS-backed key management and credential rotation.

---

## Claim 12 — Failures deny

**Claim:** If the policy engine throws, if a resource is unknown, if no rule
matches, or if a classification is unrecognized, the decision is deny.

**Mechanism:** `try/catch` around `evaluate()` returning
`evaluation-error`; `NO_MATCH` default deny; unknown classification rank 100.

**Threat model:** TM-001, TM-003.

**Assumptions:** none.

**Evidence:** invariant 12 tests (three cases).

**Test:** `tests/invariants.test.ts` invariant 12.

**Known limitations:** fail-closed also means a broken policy engine stops all
legitimate work — availability is traded for safety, deliberately.

**Residual risk:** none additional; availability impact is accepted.

---

## Claim 13 — Evidence is sealed at rest and decryptable by clearance

**Claim:** Output content is encrypted (AES-256-GCM, one HKDF-derived key per
classification level) before it is written to the evidence store. The plaintext
digest is stored so integrity is verifiable without clearance. Content can be
read only by a principal holding a capability for `evidence.decrypt` on that
level's key resource, and the read attempt is authorized and audited.

**Mechanism:** `seal`/`open` in `src/seal.ts`; `AgentSession.record` seals every
non-empty output; `AuthorizationService.revealEvidence` authorizes before
decrypting. Default policy contains no `evidence.decrypt` allow rule, so the
default answer is denial.

**Threat model:** TM-004 (evidence store as a target), TM-003 (one store, many
tenants), TM-001 (agent used to surface secrets to a reader).

**Assumptions:** the master key is held more securely than the database. A
master key sitting on the same host as the store gives obfuscation, not
confidentiality.

**Evidence:** `tests/evidence.test.ts` — six cases: plaintext and secrets absent
from the serialized store; digest verifiable without clearance; unauthorized
reveal denied and audited; cleared reviewer decrypts the exact content;
clearance for one level does not open another; tampered ciphertext yields
nothing.

**Test:** `npm test`.

**Known limitations:** no key rotation (re-sealing history is a migration); one
master key for all tenants; no per-tenant data keys; no KMS/HSM; no protection
if the master key and database are both taken. Outputs are sealed, not the
decision metadata — resource ids, classifications, principals, and decisions
remain readable in the store.

**Residual risk:** an adversary who controls the host, or who takes both the
file and the master key, reads everything a cleared reviewer can. Closing that
requires hardware-backed keys and separation between key custody and data
custody (H2, ADR-008, ADR-013 migration path).

---

# What this platform does NOT claim

- It does not claim the system is secure, compliant, or certified.
- It does not claim isolation. `LocalSandbox` is in-process execution.
- It does not claim prompt-injection *prevention*. It claims injection cannot
  create authority.
- It does not claim the event log cannot be destroyed — only that tampering with
  its contents is detectable.
- It does not claim protection against a compromised host, a malicious
  administrator, or a malicious hardware/firmware supply chain.
- It does not claim HIPAA, SOC 2, ISO 27001, or any government authorization.
  See COMPLIANCE.md.

---

## Claim 14 — No path to a principal without authentication (M2)

**Claim:** Every principal that reaches `AuthorizationService.authorize` carries
a valid, non-expired `AuthContext` issued by a trusted OIDC IdP, except system
principals (`kind: 'authorization'`). Unauthenticated or expired-auth principals
are denied with `denyReason: 'unauthenticated-principal'` before any capability
or policy check.

**Mechanism:** `isAuthenticated(principal, now)` guard at `src/pdp.ts:166`,
enforced once in the shared `authorize()` function — not per caller. The
`AuthContext` is produced only by `IdentityProvider.verifyToken` (`src/identity.ts`)
using `jose` for JWT/JWK signature verification (ADR-015). Hand-rolled token
verification is a defect by the bar in SECURITY_PRINCIPLES.md.

**Threat model:** TM-001 (impersonation), TM-003 (cross-tenant).

**Assumptions:** the IdP is trusted; the signing keys are distributed securely;
the runtime process is not compromised.

**Evidence:** invariant 13 tests (4 cases: unauthenticated denied, expired auth
denied, root bypass works, no-auth fires before no-capability).

**Test:** `tests/invariants.test.ts` invariant 13.

**Known limitations:** the IdP is an external trust dependency. A compromised
IdP can issue valid tokens. The runtime cannot distinguish a stolen token from
a legitimate one — that is the IdP's responsibility.

**Residual risk:** IdP compromise; token theft before expiry; IdP clock skew
extending token life (mitigated by clock tolerance).

---

## Claim 15 — Approvals require an authenticated human with MFA (M2)

**Claim:** An approval record (`Approval`) cannot be created without a
`reviewerAuth` field containing a valid, non-expired `AuthContext` whose AMR
(Authentication Methods References) includes MFA. The PDP filters out approvals
whose reviewer lacks MFA or whose auth has expired, before passing approvals
to the policy engine.

**Mechanism:** `Approval.reviewerAuth` field (required, `src/policy.ts:142`);
`hasMfa(a.reviewerAuth)` check in `src/pdp.ts:330` before policy evaluation.
Session creation (`src/session-manager.ts:66`) also requires MFA.

**Threat model:** TM-001 (impersonation), TM-003 (separation of duties bypass).

**Assumptions:** the IdP enforces MFA and accurately reports it in the AMR claim.

**Evidence:** invariant 13 tests; policy engine approval tests; MFA enforcement
in session creation.

**Test:** `tests/invariants.test.ts` invariant 13;
`tests/policy.test.ts` approval tests.

**Known limitations:** MFA enforcement depends on the IdP correctly populating
the AMR claim. A malicious or misconfigured IdP could omit MFA from the AMR.

**Residual risk:** IdP misconfiguration; AMR claim manipulation by the IdP.

---

## Claim 16 — Cross-tenant and cross-principal approval reuse is denied (M2)

**Claim:** An approval issued for principal A on resource R cannot be used by
principal B, and an approval for tenant A cannot authorize actions in tenant B.
The policy engine's `approvalApplies` function matches on `principalId`,
`action`, `resourceId`, and expiry — all four must match.

**Mechanism:** `approvalApplies` in `src/policy.ts:223`; tenant equality check
in `src/policy.ts:269`; PDP tenant guard in `src/pdp.ts:273`.

**Threat model:** TM-003 (cross-tenant), TM-001 (approval theft).

**Assumptions:** the approval record is created correctly.

**Evidence:** policy engine tests (approval for one resource does not carry to
another; cross-tenant denied).

**Test:** `tests/policy.test.ts` approval tests.

**Known limitations:** approvals are in-memory; no persistence or revocation
mechanism yet.

**Residual risk:** approval reuse within the same session (bounded by expiry).

---

## Claim 17 — Token replay and signature-stripped tokens are rejected (M2)

**Claim:** JWT tokens with invalid signatures, expired claims, wrong audience,
wrong issuer, or `alg: none` are rejected by `IdentityProvider.verifyToken`.
The `jose` library performs full JWT verification including algorithm
whitelisting.

**Mechanism:** `jwtVerify` from `jose` with `algorithms: ['RS256', 'ES256']`
(default), `issuer` and `audience` checks, clock tolerance. Token expiry is
checked both by `jose` and by `isAuthenticated` at the PDP.

**Threat model:** TM-001 (token forgery, replay), TM-005 (algorithm confusion).

**Assumptions:** the IdP's signing keys are secure; the JWKS endpoint is
accessible.

**Evidence:** invariant 13 tests (expired auth rejected); `jose` library's own
test suite covers signature verification, alg:none rejection, etc.

**Test:** `tests/invariants.test.ts` invariant 13 (expired auth case).

**Known limitations:** token replay within the expiry window is not detected
by the runtime — the IdP's token lifecycle and revocation are the control.

**Residual risk:** stolen valid tokens; IdP token lifetime exceeding the
session lifetime.

---

## Claim 18 — IdP outage produces operator-visible degraded state (M2)

**Claim:** When the IdP is unreachable or returns errors, the system denies
all unauthenticated requests with `denyReason: 'idp-unavailable'` (distinct
from 'unauthenticated-principal'). The IdP health status is exposed via
`IdentityProvider.getIdPHealth()` for operator monitoring. This is NOT silent
universal denial — the deny reason is distinct and the health signal is
emitted.

**Mechanism:** `IdentityProvider.health` field updated on each JWKS fetch;
`IDP_UNAVAILABLE_DENY` constant; `getSigningKeys()` returns `undefined` on
fetch failure, causing `verifyToken` to return `undefined`, causing
`isAuthenticated` to fail.

**Threat model:** H15 (fail-closed availability engineering).

**Assumptions:** the operator monitors the health endpoint; fail-closed is
the correct default.

**Evidence:** IdP health tracking in `src/identity.ts`; distinct deny reason
for IdP unavailability.

**Test:** `src/identity.ts` IdP health tracking.

**Known limitations:** no circuit breaker — every request attempts JWKS fetch
during outage. Rate limiting is left to the deployment.

**Residual risk:** request amplification during IdP outage; availability
impact from fail-closed.

---

## Claim 19 — Per-event Ed25519 signatures prove who wrote each event (M3)

**Claim:** Every event appended to the evidence log is signed with an Ed25519
key pair generated by the runtime. The signature covers the canonical JSON of
the event body (every field except `eventHash` and `signature`). `EventLog.verify()`
checks the signature when a public key is supplied, and the standalone
`verifyBundle()` does the same offline.

**Mechanism:** `node:crypto` `generateKeyPairSync('ed25519')` (`src/events.ts:122`);
`sign` / `verify` over the canonical body (`src/events.ts:147`, `src/events.ts:154`);
the signing key is independent of the HMAC capability signing key (ADR-002,
ADR-004); the public key is exported via `eventPublicKey()`
(`src/events.ts:141`) for distribution.

**Threat model:** TM-004 (repudiation).

**Assumptions:** the runtime process holds the private signing key for the
duration of an append. In a multi-node deployment the key is shared via KMS
or HSM (future work); today the key is in process memory and is not durable
across restarts unless `EVENT_SIGNING_PRIVATE_KEY_PEM` is set.

**Evidence:** M3 test suite — `tampering with an event field breaks the signature`,
`a signature produced by the wrong key is rejected`, `a bundle with a forged
signature is rejected`, `an exported bundle verifies offline against the public key`.

**Test:** `tests/m3-evidence-hardening.test.ts`.

**Known limitations:** today the runtime generates an ephemeral key per process
unless `EVENT_SIGNING_PRIVATE_KEY_PEM` and `EVENT_SIGNING_PUBLIC_KEY_PEM` are
supplied. This means the public key must be exported and held by the
verification side; an event signed by yesterday's process cannot be
verified today without the matching PEM. KMS-backed key custody, key
rotation, and signed-key bundles are HARD-stage items.

**Residual risk:** key loss or compromise. A signing key in process memory
without hardware backing is exposed to any attacker with host access at the
moment of signing. Production: HSM/TPM (HARD stage).

---

## Claim 20 — Revoked capabilities are denied immediately (M4)

**Claim:** Once a capability id is added to the revocation set, the next
`AuthorizationService.authorize` call referencing it returns `deny` with
`denyReason: 'capability-revoked'` — regardless of signature, scope, or
classification validity. Propagation is in-process and synchronous: the
revocation takes effect on the very next decision.

**Mechanism:** `AuthorizationService.revoke(capabilityId, reason)` adds to an
in-memory `RevokedCapability` record; the revocation set is consulted before
`verifyCapability` in `src/pdp.ts:evaluate()`; a revocation event is appended
to the event log so the withdrawal is auditable.

**Threat model:** TM-001 (compromised model or tool with a stale capability),
TM-003 (separation of duties — offboarded principals).

**Assumptions:** the PDP process is the single decision point; revocation
propagates synchronously in-process. Multi-node deployments require broadcast
(future work, documented in ROADMAP H13).

**Evidence:** `tests/authorization-lifecycle.test.ts` — revocation suite:
issue/use/revoke/deny cycle, immediate propagation, event log entry, and the
end-to-end request-approval-minting-revoke-deny chain.

**Test:** `tests/authorization-lifecycle.test.ts` M4 revocation tests.

**Known limitations:** in-process revocation only. A capability revoked on node
A is still usable on node B until broadcast lands. There is no
distributed-coordination mechanism yet — this is H13.

**Residual risk:** revocation window in multi-node deployments until broadcast
is implemented.

---

## Claim 21 — Audit query + export is authorized and tenant-scoped (M6)

**Claim:** Operators can read and export their own tenant's evidence plane
records without cross-tenant leakage. Any audit query or export requires an
authenticated principal, an explicit capability granting `query.audit` on the
synthetic `audit-log:<tenantId>` resource, and a matching policy allow rule.
Tenant scope is derived strictly from the authenticated principal; cross-tenant
queries fail closed (`tenant-mismatch`). Exported bundles preserve Ed25519
signatures and event hashes for offline `verifyBundle()` verification.

**Mechanism:** `AuditQueryService` (`src/audit-query.ts`) validates service-side
query bounds (limit ≤ 1000, offset ≥ 0; time range ≤ 90 days when both bounds
are present; an open-ended `fromTime` window is measured against the service
clock; `toTime` without `fromTime` is rejected as unbounded — a deliberate
tightening beyond the M6 spec, which only described both-bound behavior);
authorizes via `AuthorizationService.queryAudit` (`src/pdp.ts`); synthetic
resource `audit-log:<tenantId>` (`ResourceType: 'audit-log'`) is registered on
demand as an authorization target when audit access is first authorized (mirrors
`evidence-key:<classification>` in `revealEvidence`); it carries no content and
is never part of the tenant's resource inventory. A capability holding
`query.audit` also authorizes `audit.export` (`verifyCapability` in
`src/capability.ts` and the candidate filter in `src/pdp.ts:evaluate()`), while
policy still lists both actions explicitly — the distinction between the two is
policy-side. Storage query via `EventLog.query()` (`src/events.ts`) executes
parameterized SQL against `security_events`; `AuditExport.fromSeq` / `toSeq`
are the seq values of the first and last events actually returned (result
bounds, not the requested filter bounds), so `previousHead` is the in-chain
predecessor of the slice and `verifyBundle()` can validate it offline.

**Threat model:** TM-004 (evidence store as a target), TM-003 (one store, many tenants).

**Assumptions:** the PDP process is the single point of entry; the synthetic
resource id derivation cannot be overridden by caller input.

**Evidence:** `tests/m6-audit-query.test.ts` (29 cases) covering: unauthenticated
denial, tenant-mismatch denial, capability requirement, default deny, policy
matching, filter parity (actor, action, decision, resourceId, time range,
limit/offset), empty matches, bad filter bounds, single-bound time filters
(toTime-only rejected, open-ended fromTime clock-bounded), tenant isolation
invariant, direct `authorize()` on a caller-constructed `audit-log:*` id denied
as unknown-resource, `QueryResult` array-plus-`.decision`/`.events` shape,
export shape, export `generatedAt` from the service clock, the
`audit.export`-implied-by-`query.audit` rule and its reverse direction, result
bounds vs requested filter bounds, chain slice verification, decision audit
completeness, SQLite parity, and sealed content confidentiality.

**Test:** `tests/m6-audit-query.test.ts`.

**Known limitations:** in-process query only; multi-node audit aggregation and
distributed query federation are H13. Sealed outputs stay sealed; plaintext
inspection requires a separate `evidence.decrypt` authorization. The
`audit.export`-implied-by-`query.audit` rule is encoded in two code sites
(`verifyCapability` and the PDP candidate filter); a future third audit action
must be handled in both, or the rule factored into one shared helper.

**Residual risk:** LOW. Audit query is read-only and gated by the same capability
and policy engine as all other actions.

---

## Claim 22 — Policy rules are unit-testable (M7)

**Claim:** A policy rule is a unit-testable artifact. Operators author
fixtures (`{ scenarios, expected }` JSON), run them through the engine via
`simulate()`, and diff against a baseline via `diffDecisions()`. A change
that flips a decision in the scenario set is the surface the operator
reviews — before the rule reaches a live PDP.

**Mechanism:** `src/policy-testing.ts` exports `simulate(engine, scenarios)`,
`diffDecisions(before, after, scenarios)`, and `loadFixtures(dir)` with
validator (rejects malformed JSON, missing fields, action outside
`KnownAction`, principal kind outside `domain.ts` vocabulary, cross-tenant
scenarios). `src/policy-diff.ts` is the `npm run policy:diff` entry point:
argv glue (5 lines), diffs `BASELINE_POLICY` against an optional overlay
file, prints `"<n> changed"` plus per-scenario before/after.

**Threat model:** TM-001 (rule authoring — a typo in a rule is detectable),
TM-003 (cross-tenant via scenario validator).

**Assumptions:** the operator has the `BASELINE_POLICY` reachable (exported
from `src/policy.ts`); JSON is the only fixture format (per spec; no DSL).

**Evidence:** `tests/policy-harness.test.ts` — 12 cases covering simulate
returns one decision per scenario in input order with typed reasons;
diffDecisions surfaces effect, ruleId, and reason changes separately;
adding a no-op allow rule produces zero diff entries; loadFixtures rejects
malformed JSON / missing fields / action outside vocabulary / cross-tenant
scenarios; three migrated fixtures pass against the unmodified baseline and
remain green under a one-line no-op overlay. `npm run policy:diff` with no
overlay prints `0 changed`; with a `deny-agent-read` overlay, prints the
changed scenarios with before/after rule ids and reasons.

**Test:** `tests/policy-harness.test.ts`.

**Known limitations:** validators cover `KnownAction`/`PrincipalKind`/
`ResourceType`/`KnownClassification` plus a shape check on action strings
(action must be non-empty and free of whitespace); the validator does not
enforce a closed vocabulary because both `Action` and `ResourceType` are
extensible via the `string & {}` brand in `domain.ts`. Operators who
introduce new vocabulary should extend the validator's allowlists.

**Residual risk:** LOW. A passing fixture suite proves the operator's
intended rules behave as documented; it does not prove the rules are
sufficient or correct in production.

---

## Claim 23 — Delivered claims are evidence-bound or annotated (M7/M8)

**Claim:** Every response with status `delivered` carries either a verbatim
citation to a real ingested source, or it carries no consequential claim.
Every other response is marked `flagged`, `repaired`, or `withheld` with the
flag list sealed into the evidence store. A response containing a canary or
secret value is withheld and never delivered. The guard exposes no
authority handle, and the PDP does not import it.

**Mechanism:** `src/guard.ts` — `ResponseGuard` interface; `GroundedResponseGuard`
implements D2 (claim-source binding: verbatim span verification), D3
(session-fact consistency: "I <verb>ed X" matches a `StepRecord` action), D4
(numeric recomputation against step output), D5 (prose leak check — skips
ladder, withholds immediately); D6 has a callable optional `criticFn` hook
(telemetry only, no real critic wired). The fallback ladder (`runLadder`) is
pure: `flags + repairFn + regenerateFn → GuardedResponse`, with rungs Repair →
Regenerate → Abstain → Escalate (Escalate gated on `classificationRank >=
'confidential'`), and records the rung that fired in `GuardedResponse.ladderRung`.
The Escalate rung wires into M4: when a `CapabilityRequestService` is provided
and the principal is an agent, `guard()` submits a `CapabilityRequest`
(synthetic `guard.review` resource/action id) via
`CapabilityRequestService.submit()`, which appends the `capability.request`
event itself; the awaiting-review text names the request id and the
`session.guard` event metadata carries `requestId`. The guard does not own the
service and does not wait for approval — M4's out-of-band approval flow gates
delivery. Per-session classification is derived in `AgentSession.run()` by
`deriveClassification()` from the principal's capability `maxClassification`
ceilings, the registry classification of every `content` key, and the resources
named in the model's requests; it defaults to `'public'` when nothing is
visible. A second guard pass runs after the requested actions execute, on the
same model text with the executed `steps` populated; it emits ONE extra
`session.guard` event (`metadata.phase === 'guard-second-pass'`) only when the
verdict (`status` + `flags`) changes, and the trace adopts the better-informed
second verdict. `session.guard` metadata carries `metadata.sealed` as a raw
`Sealed` object (`.ciphertext`/`.keyId`/`.iv`/`.tag`, no JSON-parse step) and
`metadata.ladderRung`. D5 leaks skip the ladder entirely — strikethrough is not
a secrecy control.

**Threat model:** TM-001 (compromised model asserting unverified claims),
TM-004 (withheld text leaking flagged spans or canaries via the evidence
store).

**Assumptions:** the guard module is invoked at most twice per `run()` (pre- and
post-execution) and the second pass never submits a capability request; the
per-session classification (derived from capability ceilings + visible/requested
resources, default `'public'`) determines whether the Escalate rung is
reachable; `GuardContext.context` carries the ingested content keyed by
`resourceId`; a deployment without an M4 `CapabilityRequestService` falls back to
text-only escalation.

**Evidence:** `tests/guard.test.ts` — 33 cases covering D2 (cited-and-real,
cited-and-forged, cited-but-span-missing, uncited number), D3
(action-claim-mismatch and its inverse), D4 (numeric-mismatch, and the
exclusivity rule: a bare number with no steps flags `unverified-claim`, with
steps that lack it flags `numeric-mismatch`, never both), D5 leak (skips ladder,
withholds), ladder repair (success and abort-on-empty), abstain, escalate
(reached for confidential+), escalate NOT reached for low classification,
`regenerateFn` success (status repaired, rung `regenerate`, called once) and
failure (withheld, no retry), `ladderRung` mapping, the D6 `criticFn` hook
(absent → no critic flags; supplied → flags merge before the ladder), the
M4 wiring (escalate queues a `CapabilityRequest` with `principalId`,
`requestedActions: ['guard.review']`, flag reasons in the justification, and a
`requestId` in the awaiting-review text; text-only fallback without a service;
no queue below confidential or for a non-agent principal), fail-closed when the
guard throws, R3 structural assertion on `GuardContext` keys +
dependency-direction between `src/pdp.ts` and `src/guard.ts`.
`security-tests/guard-invariants.test.ts` — 8 cases: R1 false-claim budget
(100/100 honest sessions delivered cleanly on the `summarizeRepoModel` corpus;
`falseClaimRate = 0`); R2 withhold scan (four hostile cases: forged citation,
action-claim-mismatch, prose leak, poisoned source — first three
withhold/repair; poisoned source is correctly delivered and documents the D2
ceiling); R3 no-authority (`GuardContext` keys clean, `pdp.ts` and `guard.ts` do
not import each other). `tests/runtime-second-pass.test.ts` — 8 cases:
`deriveClassification` (default public, content → internal, capability ceiling →
confidential, unknown label fail-closed) and the second pass (agree → exactly one
event; a first-pass action-claim-mismatch cleared post-execution → one
`guard-second-pass` event and a delivered trace; same-verdict escalate does not
double-queue a `CapabilityRequest`). `tests/runtime-drift-fixes.test.ts` — 3
cases: `metadata.sealed` is a raw `Sealed` object with a string `ciphertext`;
`metadata.ladderRung` records the rung that fired. Benchmark `guardLatencyP99Ms`
and `evidence.falseClaimRate` measured per run; since M10 the `falseClaimRate`
denominator is the fixture guard verdicts plus a 100-session honest R1 corpus
(101 responses; the sessions' PDP decisions count toward `expectedDecisions`),
and `falseClaimRate ≤ 0.01` is a `hard` assurance target gated on every
benchmark run (`src/slo.ts`, `metrics.slo` in `benchmarks/results.json`).

**Test:** `tests/guard.test.ts`, `security-tests/guard-invariants.test.ts`,
`tests/runtime-second-pass.test.ts`, `tests/runtime-drift-fixes.test.ts`.

**Known limitations:** verifies *support*, not *truth* — a poisoned source
yields a well-cited lie (TM-002 residual). Uncited-but-true claims are
flagged as `unverified-claim` (false-positive budget applies; on the
current corpus `falseClaimRate = 0`, measured since M10 over 101 honest
responses per benchmark run). The `action-claim-mismatch` check
matches by verb only (deleted→delete, wrote→write); a noun-vs-resource
match is a future enhancement. D5 takes the *first* canary match and stops
the ladder; future versions may enumerate all matches and surface them.
`regenerateFn` is exercised by tests but no production caller supplies one —
`GroundedResponseGuard` passes `null`, so the rung is dormant until a model
retry is wired. The second-pass verdict compares `status` + `flags` only, and a
second-pass escalation never submits a second request by design; an escalated
second-pass verdict therefore renders the text-only escalate message even when
the first pass queued a request (the first `session.guard` event retains the
`requestId`). The Escalate rung requires both `classification >= confidential`
and a configured `CapabilityRequestService`. The per-session classification is
deliberately coarse: it is the maximum over *all* capabilities the principal
holds (not only the session's grants) and over the entire `content` map, so
sessions in a mixed-sensitivity world derive a high label — the conservative
direction, and what makes Escalate reachable; deriving from per-session granted
caps only is the upgrade path if coarseness bites. If
`CapabilityRequestService.submit()` throws, the fail-closed catch degrades to
the text-only withhold — no `requestId`, no `capability.request` event, and the
`session.guard` event carries no distinct error marker (a `guard.error` marker
is the upgrade path). The `criticFn` hook exists only on `GroundedResponseGuard`,
not on the `ResponseGuard` interface — intentional: the runtime cannot pass a
critic.

**Residual risk:** LOW for the four cases the test suite exercises. MEDIUM
in production because generative models hallucinate by construction
(IMPOSSIBLE+ row in ROADMAP): the guard's mitigation is requiring evidence
for consequential claims, not detecting all hallucinations. The second pass
reduces false positives from pre-execution flags; it is a quality gate, not a
new boundary.

---

## Claim 24 — Role-templated issuance cannot exceed the role (M11)

**Claim:** A capability minted through `AuthorizationService.issueForRole` never
grants an action outside the referenced role's action set and never carries a
classification ceiling above the role's ceiling. Issuing through a role never
bypasses the ordinary issuance checks: a principal that could not mint before
still cannot, and a non-root issuer still attenuates against its own authority.

**Mechanism:** `issueRequestForRole` (`src/capability.ts`) resolves the role
from the table the service was constructed with (id + tenant match, `'*'` =
tenant-agnostic), throws on unknown/invisible roles, throws when requested
actions leave the role's set, throws when a requested `maxClassification`
outranks the role ceiling (an omitted ceiling defaults TO the role ceiling —
never silently capped beyond it), and returns a plain `IssueRequest`. That
request flows through `issueCapability` unchanged, so `CAPABILITY_ISSUER_KINDS`
(invariant 2), tenant match (invariant 9), and attenuation (invariant 6,
ADR-002) are enforced where they always were. `createPolicyEngine`
cross-validates allow rules that reference roles at construction: an action
outside the role's set, a classification above the role's ceiling, or a
wildcard action set is a `PolicyCompilationError` — fail closed, before any
decision is made.

**Threat model:** TM-001 (a compromised model or tool convincing a caller to
mint through a role), TM-003 (role overreach across tenants).

**Assumptions:** the role table is the operator's intent (it is data loaded at
construction; bundles make it a verified artifact — Claim 26); the runtime is
not compromised.

**Evidence:** `tests/m11-rbac.test.ts` — 12 cases: role caps issuance (mint at
ceiling, narrower requests win); over-privileged issuance throws (action
outside the role, classification above the ceiling); unknown role fails closed;
roles are tenant-scoped; roles never mint (agent issuers refuse, non-root
issuers attenuate — `must present its own authority` / `exceeds issuer
authority`); cross-validation rejects widening rules (action, classification,
wildcard) and skips deny rules and unknown-role references; tampering a
role-minted capability fails the signature check; a role-minted capability used
above its ceiling denies with `classification-ceiling`; structural invariant —
every baseline role mints only its own actions at or below its own ceiling.

**Test:** `tests/m11-rbac.test.ts`.

**Known limitations:** roles narrow issuance; they are not an ABAC system —
no role inheritance, no nested roles, no dynamic role CRUD (upgrade path when
operators define more than a handful of roles). Rules referencing roles absent
from the constructed table are not validated (org tables may define them
elsewhere) — cross-validation is only as strong as the table it is given. The
baseline table is tenant-agnostic; per-tenant role tables load through
`RoleBundle` (Claim 26).

**Residual risk:** an operator who defines an over-broad role has made the
over-broad mint legitimate — the control constrains scope, it does not judge
judgment (same shape as Claim 1's limitation).

---

## Claim 25 — Propagation only raises (M11)

**Claim:** A derived artifact's classification is the maximum rank of its source
labels; it can only raise, never lower; an unknown label outranks every known
label; and a derived label never grants authority — it only feeds ceilings
(capability ceilings, policy `maxClassification`, sealing keys).

**Mechanism:** `classificationRank` (`src/domain.ts`) ranks unknown labels at
100, so a typo or org-specific label fails toward sensitivity.
`propagateClassification` (`src/registry.ts`) is a max-by-rank over the current
label plus source labels — no new ranking logic. `ingestDocument` reports
`derivedClassification` when `derivedFrom` sources are given (pure — callers
apply it). `ResourceRegistry.raiseClassification` refuses to lower, returns
undefined for unknown ids, and never creates resources. The runtime write path
(`AgentSession.attempt` with `changed: true`) derives from data sources only —
the session's content map plus the target resource; capability ceilings are
deliberately EXCLUDED (clearance is not a data label) — then raises the target
in the registry and records the derived label: the execution event carries
`metadata.derivedClassification` and the output seals under
`evidence-key:<derived>`, so the sealing key matches the derived sensitivity.

**Threat model:** TM-002 (H4 failure mode: "classification lost on derived
content"), TM-003.

**Assumptions:** the source labels in the registry and content map are correct
(propagation inherits whatever the inputs claim); the runtime is not
compromised.

**Evidence:** `tests/m11-classification.test.ts` — 11 cases: derived-from-
confidential is confidential; public + phi → phi; unknown label wins; labels
never lower; `ingestDocument` reports the derived label only when
`derivedFrom` is given; `raiseClassification` raises, refuses to lower, and
never creates; end-to-end write path — a write into a public draft from a
session holding a confidential source raises the target, records
`metadata.derivedClassification`, and seals under `evidence-key:confidential`
(= `keyIdFor('confidential')`); a second write with no higher sources leaves
the label at confidential.

**Test:** `tests/m11-classification.test.ts`.

**Known limitations:** deliberately coarse — the write path takes the max over
the session's whole content map, not a per-document lineage (the same
conservative coarseness as the guard's session classification; content-level
lineage is the Stage-3 "Advanced provenance" row). The ingest path is pure by
design: `ingestDocument` reports the derived label, and the caller must apply
it to the registry — nothing downstream raises automatically on ingest alone.

**Residual risk:** a source labeled too low propagates a too-low label —
propagation is only as honest as the labels it inherits.

---

## Claim 26 — Policy bundles fail closed on tamper (M11)

**Claim:** A policy or role table loaded as a versioned bundle is refused unless
its hash matches `sha256(canonicalJson({ version, rules | roles }))`. A refused
bundle never compiles rules, never constructs an engine, and never appends an
event. Every successful bundle load through the seam is recorded as exactly one
`policy.load` event with version, hash, rule count, and provenance.

**Mechanism:** `src/policy-config.ts` — `PolicyBundle`/`RoleBundle` carry `id`,
`version`, the payload (`rules`/`roles`), `provenance`
(`source`, optional `reviewedBy`/`approvedAt`), and `hash`;
`policyBundleHash`/`roleBundleHash` compute it over `canonicalJson` (deterministic
across runs and platforms — `src/domain.ts`); `loadPolicyBundle`/`loadRoleBundle`
reject structurally broken bundles, recompute the hash, and throw
`PolicyBundleError` on any mismatch; `createEngineFromBundle` verifies first,
builds via `createPolicyEngine` (which also runs Claim 24's role
cross-validation against the bundled role table), and — opt-in via
`opts.eventLog` — appends exactly one `policy.load` event; plain
`createPolicyEngine` calls append nothing (the seam stays optional).
`npm run policy:diff` (`src/policy-diff.ts`) routes versioned overlays through
`loadPolicyBundle` before any engine is built and aborts on mismatch; legacy
unversioned overlays load unchanged.

**Threat model:** TM-003/H3 (adversarial policy conditions), H10 (supply chain —
the bundle hash is the review artifact's fingerprint).

**Assumptions:** the hash function is intact; whoever verifies the bundle has
the authentic hash out of band (git history, review record); the runtime is not
compromised.

**Evidence:** `tests/m11-policy-config.test.ts` — 12 cases: a well-formed
baseline bundle loads and the engine behaves like the baseline (allow +
default-deny spot checks); tampered rules refuse (loader and
`createEngineFromBundle`); structural breakage refuses (missing id/version/
rules, non-array rules, non-string hash); the mismatch names the bundle id;
exactly one `policy.load` event per successful load with version/hash/
ruleCount/bundleId/provenance, a second load appends one more, plain engines
append none; a refused bundle appends zero events; role bundles verify, refuse
on tamper, and drive role cross-validation (a bundled-role overgrant throws
`PolicyCompilationError`); `policy:diff` subprocess: versioned overlay exits 0
with `"<n> changed"`, tampered overlay exits nonzero naming the hash mismatch,
legacy overlay still exits 0.

**Test:** `tests/m11-policy-config.test.ts`.

**Known limitations:** stated honestly — the hash proves integrity, not review.
Authoring is still in-repo and the review gate is git; a committer can recompute
a hash, so this is not a signature scheme and not a policy service.
`provenance` is unverified metadata. Bundle format versioning starts at 1 with
no migration tooling. No signature, no external anchoring, no approval routing
(H10/H12 territory — the upgrade path is signed bundles with an out-of-band
approval record).

**Residual risk:** an attacker with commit access can ship a tampered bundle
with a recomputed hash; the defense is the same one that guards every other
line in the repo — review — plus the `policy.load` evidence trail, which makes
the load attributable and detectable after the fact.

## Claim 27 — A provider receives nothing above the configured classification ceiling (M13)

**Claim:** When a session's content is sent to an external model provider
through `HttpModelAdapter`, the egress gate refuses the call unless (a) the
classification derived over the content being sent (`deriveClassification`
over the session's capabilities, content map, registry, and the context
resource ids) fits the adapter's configured ceiling, AND (b) the PDP allows
`model.invoke` on the synthetic provider resource for the acting principal.
The gate is default-deny and not bypassable by configuration: no capability
issued, or content above the ceiling, means no bytes leave the process.

**Mechanism:** `src/model-http.ts` — `complete()` first computes
`deriveClassification(...)` over what is about to be sent and compares ranks
against the configured `ceiling`; above it, the adapter appends a `model.call`
event with `decision: 'deny'`, emits telemetry, throws
`ModelEgressDeniedError`, and the injected `fetch` is never invoked. The
derivation takes the max over the WHOLE content map, so classified content a
caller forgot to declare in `contextResourceIds` is still caught; a non-empty
context with NO content map is refused as unclassifiable
(`egress: 'refused-unclassifiable'`) — there is no adapter configuration that
sends context without a classification oracle. It then
consults the PDP (`authorize` on a `model.invoke` action against the
`providerResourceId`); a PDP deny produces the same refusal (the PDP appends
its own audit event). Provider responses are untrusted: the body's message
content is `JSON.parse`d and flows through `parseModelOutput` — the whitelist
parser that drops unrecognized fields — and any malformed output fails closed
(error event + throw, no fabricated output). Transport is injectable `fetch`
with a timeout and bounded retry/backoff; non-retryable HTTP statuses fail
immediately. `model.call` events record model id, duration, token usage, and
the egress decision — never prompt, context, output text, API key, or
canaries (parse/HTTP error messages are static strings so a hostile provider
echoing canaries cannot leak them into events). The adapter is a transport,
not a trust boundary: the compromised-model assumption is unchanged, and the
session's guard still polices the text channel.

**Threat model:** H7 (exfiltration via model prompt — the model call is itself
an egress), H4 (model output is hostile input; the whitelist parser bounds
what a hostile provider response can smuggle).

**Assumptions:** the classification labels on the registry resources and the
content map are truthful (garbage in, garbage out — the gate is only as good
as the labels); the ceiling is configured by the operator, not the agent; the
provider resource and `model.invoke` capability are issued through the
normal issuance pipeline.

**Evidence:** `tests/model-http.test.ts` — 14 cases: allow path (fetch called
once, correct Authorization header, parsed output, usage recorded); ceiling
refusal above `internal` (fetch NOT called, `model.call` deny event, throws),
including map-covered confidential content and fragments sent with NO declared
context ids; non-empty context with no content map refused as unclassifiable
(fetch not called); empty context with no map still reaches the PDP gate;
PDP deny with no capability issued (fetch not called, deny recorded,
default-deny); retry on 5xx then success and bounded failure; malformed
provider output (prose content, missing `choices`) fails closed with an error
event and no output; timeout path; a scan of the full event log and every
error message for the API key and a planted canary — neither appears
anywhere; end-to-end through `AgentSession.run()`. The demo's scripted
provider section exercises allow and refusal end-to-end.

**Test:** `tests/model-http.test.ts`.

**Known limitations:** the ceiling is derived coarsely (max over the session's
content map and context ids — conservative by design, more withholding, never
less; same ceiling doctrine as Claim 23). The gate's classification oracle is
the adapter's content map plus the declared context ids: text that appears in
neither — a derived summary, a fragment rewritten by the caller, hostile
injected content — is free text and goes unexamined, exactly like the `prompt`
field itself. That is not a configuration bypass (the coarse whole-map max
catches undeclared ids for anything the map covers, and a missing map denies
the call), it is the absence of content-level DLP: a canary planted by the
ingestion layer in a public-classification document would still be sent —
H7's volume/semantic layer, the upgrade path. The deployment rule stands:
construct the adapter with the session's content map, and route all provider
traffic through the adapter — a deployment that hands the model provider's SDK
to a tool bypasses the gate entirely. Streaming responses are out of scope; a
streaming adapter must apply the same gate before the first byte.

**Residual risk:** a provider operator sees and retains everything sent —
that is inherent to cloud inference (IMPOSSIBLE+ table: confidentiality
against a compromised provider is not claimable; customer-hosted inference is
the answer). The claim is only: nothing above the configured ceiling is sent
at all.

## Claim 28 — Structured telemetry is observability, never a control (M13)

**Claim:** Telemetry emission (session start/end with durations and counts,
per-session PDP deny-reason aggregates, model-call outcomes) never changes an
authorization decision, never blocks or fails a request, and never carries
secrets, canaries, or unsealed model text. The PDP never reads telemetry, and
telemetry code never re-enters the PDP for its aggregates.

**Mechanism:** `src/telemetry.ts` — `TelemetryPort.emit(name, attrs)` writes
one JSON object per line via `JsonlTelemetry` (stdout by default, injected
sink for tests). Both serialization and the sink call are wrapped: an
emission failure increments a `dropped` counter and never throws into the
request path — a broken telemetry sink degrades evidence, not behavior.
Aggregates come from `denyReasonCounts` over the step decisions the session
already made — no re-entry into the PDP, no second evaluation. Runtime wiring
emits only ids, counts, durations, and model ids. Two dependency-direction
tests enforce the doctrine structurally: `src/pdp.ts` contains no telemetry
import, and `src/runtime.ts` imports only the type.

**Threat model:** H14/H15 adjacent (the health-signal gap); R3 spirit (the
evidence/telemetry plane must not feed the decision plane).

**Assumptions:** the JSONL consumer (stdout, collector) is outside the trust
boundary — treat emitted lines as potentially readable by anyone with host
access, which is exactly why the attribute discipline exists.

**Evidence:** `tests/telemetry.test.ts` — 9 cases: lines are valid JSON with
`ts`/`name` and intact attrs; sink throws → caller unaffected, `dropped`
increments; unserializable attrs are dropped, not thrown; session wiring
emits `session.start`/`session.end` (durationMs ≥ 0, allowed/denied counts
correct) and `pdp.denyReasons` with the observed deny reason; a leakage scan
over all emitted lines for canaries, model text, and task text — none appear;
dependency-direction assertions (pdp.ts clean, runtime type-only).

**Test:** `tests/telemetry.test.ts`.

**Known limitations:** telemetry is best-effort by design — it is NOT
evidence; the tamper-evident event log (Claims 8/19/21) remains the only
record with integrity guarantees. A dropped line is lost forever; nothing
buffers or retries. There is no sampling, batching, or export pipeline, and
no OTel SDK — an adapter behind the same port is the upgrade path when a
collector exists (that dependency needs its own ADR).

**Residual risk:** an operator mistaking telemetry for evidence and acting on
it in an incident. The claim itself is the guard: any use of telemetry as a
control would violate this document and the dependency-direction tests.


## Claim 29 — Document ingestion is injection-inert, labeled, and sealed (M15)

**Claim:** Document ingestion (`src/ingestion.ts`) chunks deterministically
(no model in the loop), registers every chunk as a registry resource labeled
with the source document's id as `derivedFrom`, computes its label through the
M11 machinery (max-by-rank, raise-only on re-ingest), and records one
`document.ingest` event per chunk whose content is sealed with the tenant-bound
key — no plaintext chunk content ever enters the event log. Ingestion holds no
issuance handle and cannot mint authority (invariant 3), whatever the document
says.

**Mechanism:** `chunkContent` is a pure function (boundary-aware fixed-size
windows; chunk ids `doc/<documentId>/chunk/<n>` are deterministic). Labels:
`propagateClassification` over the document plus any `derivedFrom` sources;
re-ingest goes through `ResourceRegistry.raiseClassification` (refuses to
lower). Events: `sealFor(tenant, content, classification)` per chunk (Claim 13
machinery, ADR-018 per-tenant keys) plus a SHA-256 digest. The constructor
surface is registry + event log + actor attribution only — there is no
authorization or issuance dependency to abuse.

**Threat model:** TM-002 (injection), TM-004 (evidence store as a target).

**Assumptions:** the source document's label is correct at ingestion time
(labels propagate; garbage-in-garbage-labeled is the contract, not label
authorship).

**Evidence:** `tests/m15-ingestion.test.ts` — 8 cases: deterministic ids and
chunking; label = source label with a higher `derivedFrom` source raising it;
raise-only re-ingest; one sealed event per chunk with the plaintext canary
absent from the whole serialized event log; a hostile document (matching
injection-telemetry patterns) mints no capability events and stays at the
source's label.

**Test:** `tests/m15-ingestion.test.ts`.

**Known limitations:** chunking is coarse (fixed windows with paragraph/line/
space boundary awareness — no semantic chunking, no OCR, no embeddings).
Content lives in the embedder's content map; the evidence plane holds sealed
copies only. A mislabeled source document mislabels its chunks.

**Residual risk:** operator error in source-document labeling; a deployment
that feeds ingestion output straight to a model without the guard — the
ingestion path is data plumbing, the PDP path (Claim 1/3) remains the control.

---

## Claim 30 — Git access is read-only, confined, and its output is data (M15)

**Claim:** Git integration (`src/git-reader.ts`) can only read: the verb set
is allowlisted at configuration time to `log`, `show`, `diff`, `status` (every
write or network verb is refused when the reader is constructed); the command
is an argv array with no shell; arguments that name paths outside the
configured repository root (absolute paths, `..` segments) or root-escape
hatches (`--no-index`, `--git-dir`, `--work-tree`, `-C`) are refused before
spawn; and the output is untrusted content that enters the ingestion pipeline
(Claim 29) labeled with the repository's classification — no path from output
text to authority exists.

**Mechanism:** constructor validation against `GIT_READ_VERBS` (runtime-
validated like `CommandCheck`'s allowlist, so a JS caller cannot dodge it);
`spawnSync('git', [verb, ...args])` with minimal environment and timeout →
failure; `assertSafeArg` refuses traversal/escape hatches pre-spawn
(`rev:path` tails are checked too). Output composition with ingestion is the
caller's one-liner (`ingester.ingest({ document: repo, content })`) — the
reader returns a string, never authority.

**Threat model:** TM-001 (compromised model driving reads), TM-002
(injected content inside repository files), TM-005 (supply chain — no new
dependency; the installed git CLI is the only executor).

**Assumptions:** git is installed; the configured root is the intended
boundary; the repository's classification label is correct.

**Evidence:** `tests/m15-git.test.ts` — 7 cases against a real throwaway
repository: write verbs (`push`, `commit`, `fetch`) refused at construction;
instance-allowlist refusals; absolute-path, traversal, and escape-hatch
argument refusals; missing root refusal; `log`/`show`/`status`/`diff` round
trip; output ingested with the repo's label, sealed under the tenant key,
plaintext canary absent from the event log.

**Test:** `tests/m15-git.test.ts`.

**Known limitations:** no write-side git (out of scope by design, ADR-020);
no network remotes (local repositories only); `..` is refused even inside
revision ranges (`A..B`) — over-broad for that idiom, fail-closed by
preference; git CLI error text is reduced to exit codes (no redacted
diagnostics yet).

**Residual risk:** a repository whose content is hostile is exactly the
poisoned-source case (TM-002): reads succeed and stay data — the ceiling is
the guard's documented D2 limit, not a new one.

---

## Claim 31 — Sandbox lifecycle is attested, tenant-scoped, and PDP-gated (M16)

**Claim:** Every sandbox managed by `SandboxRegistry` (`src/sandbox-registry.ts`)
has a complete, tamper-evident lifecycle record: creation, destruction, and
attestation each append an event whose attestation payload (pid, sandbox kind,
declared + effective limits, timestamps, duration) is sealed under the owning
tenant's key — the plaintext event log shows only a SHA-256 digest of the limit
config and the key id, never the payload. Every lifecycle call re-checks the
ResourceRegistry's tenant binding (cross-tenant get reads as absent,
cross-tenant destroy refuses), and tool execution inside the sandbox happens
only through `execute()`, which the ordinary PDP path gates on a
`sandbox.execute` capability scoped to the sandbox resource id — the agent never
receives the handle.

**Mechanism:** `create` spawns synchronously and registers only after a
successful spawn (a failed create leaves no half-registered handle), naming the
sandbox `sandbox:<tenantId>:<name>` as a `'system'` resource with the registry
as the tenant authority. `execute` authorizes through
`AuthorizationService.authorize` (which appends its own decision event — every
execute attempt, allowed or denied, is evidence) before `runTool`; no capability,
no execution. Limits are the container sandbox's own `ContainerSandboxOptions`;
`effectiveLimits` is the single defaults source, so the destroy/attest payloads
record what the Docker path actually applies versus what was declared. Destroy
refuses unknown ids, is idempotent on already-destroyed sandboxes (explicit
destroy and the exit sweep cannot race into a throw), and `installExitSweep()`
tears down every active sandbox on `beforeExit`/SIGINT/SIGTERM, each with its
own destroy event.

**Threat model:** TM-004 (evidence store as a target — sealed payloads resist
reading and the chain resists tamper), TM-001 (a compromised model driving
sandbox execution — capability-scoped, PDP-gated), ATK-011 (resource exhaustion
— limits are declared, applied, and attested).

**Assumptions:** the runtime process is not compromised; the sandbox kind
string is honest (it is — the fallback path self-reports `fallback/...`);
the ResourceRegistry is not mutated to re-bind a sandbox across tenants except
by an operator with registry authority (a re-bind flips lifecycle verdicts
fail-closed, and that is tested).

**Evidence:** `tests/m16-sandbox-lifecycle.test.ts` — 10 cases: create/destroy
round trip with sealed events; duplicate-create and unknown-id-destroy
refusals; idempotent destroy; cross-tenant get/destroy/list refusals;
registry-rebind flips the tenant verdict; limit digest over the declared
config; sealed payload carrying effective limits (defaults included); attest
payload sealed under the tenant key with the plaintext canary absent from the
whole serialized event log; execute denied without a capability and executed
with one (through `AgentSession`-grade principals, real PDP); exit sweep
destroys every active sandbox and records the evidence; a per-event scan that
every `sandbox.*` event carries both a sealed payload and a digest. The demo's
M16 section exercises create -> execute -> attest -> destroy end-to-end.

**Test:** `tests/m16-sandbox-lifecycle.test.ts`.

**Known limitations:** the attested pid is the runtime's own pid — the current
sandbox is ephemeral per invocation (`docker run --rm`, tmpdirs removed in
`finally`), so there is no resident container or image digest to attest; those
arrive with a long-lived sandbox model. The exit sweep is opt-in (it installs
process-level signal handlers) and swallow-fails per sandbox: evidence for the
rest of the fleet outranks a clean exit code on one broken teardown. Per-sandbox
action policy (which tools a sandbox may run), multi-tenant sandbox sharing,
snapshot/restore, and HSM-backed remote attestation are named non-goals (ADR-021
migration path).

**Residual risk:** an embedder that hands the `SandboxHandle` (or the raw
`Sandbox`) to the agent bypasses the registry's gating exactly as handing out
the `AuthorizationService` would — the handle is the embedder's credential, and
the claim covers the registry's surface, not a deployment that leaks it.
