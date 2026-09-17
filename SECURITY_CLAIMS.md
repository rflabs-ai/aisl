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

**Evidence:** `npm test` — 70 assertions; `benchmarks/results.json` reports
`unauthorizedActionDenialRate`.

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

**Mechanism:** `findOverreach` attenuation check at `src/capability.ts:188`;
issuers other than the authorization root must present their own authority.
Revocation is checked in `AuthorizationService.evaluate()` before attenuation,
so a revoked capability fails before signature or scope verification.

**Threat model:** TM-001, TM-003.

**Assumptions:** the root principal is trustworthy; delegation chains are short.

**Evidence:** invariant 6 tests (four cases, including a valid attenuation).

**Test:** `tests/invariants.test.ts` invariant 6.

**Known limitations:** attenuation is checked against a declared authority
object, not a cryptographically chained delegation. A capability does not yet
carry its parent's signature. Hierarchical matching (`PolicyRule.resources.idPatterns`,
M5) adds a way to express a scope ceiling without enumerating ids, but it does
not weaken attenuation: the matcher still respects the per-rule resource
ceiling and the per-capability `resourceIds` array. If a capability lists
specific resource ids, the matcher only succeeds against those ids; patterns in
the rule do not expand the set of ids the capability may reach.

**Residual risk:** forged delegation chains until full chain-of-custody signing
lands (HARD stage).

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
subjects; capabilities bind `tenantId`.

**Threat model:** TM-003.

**Assumptions:** single control-plane process; resource records carry the
correct tenant id.

**Evidence:** invariant 9 tests (three cases); ATK-003.

**Test:** `tests/invariants.test.ts` invariant 9.

**Known limitations:** logical isolation only. All tenants share one process, one
memory space, and one SQLite table.

**Residual risk:** memory-disclosure or serialization bugs cross the boundary;
SQL-level isolation does not yet exist.

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

