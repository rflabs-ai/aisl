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

**Claim:** A non-root issuer can only mint a capability that is a subset of its
own resources, actions, classification ceiling, and expiry; it must carry every
constraint the issuer's own capability carries (it may narrow network hosts
further, never drop one), and a single-use issuer capability cannot delegate
at all.

**Mechanism:** `findOverreach` attenuation check at `src/capability.ts`;
issuers other than the authorization root must present `parent` — their own
signed capability (ADR-023). The parent is verified before any field is
trusted: HMAC signature, `parent.subject === issuer.id` (you delegate only
what you hold), same tenant, unexpired, unconsumed — checked whenever a parent
is presented, including by the root. The attenuation authority is DERIVED from
the parent's own fields, never declared, and the subset check covers all six
dimensions: resources, actions, classification, expiry, constraints (child
must carry every parent constraint; network hosts compare as intersections,
so narrowing is legitimate), and single-use (a single-use parent is a leaf
authority — no delegation). The child records the chain link
(`provenance.delegatedFrom` = parent id + parent signature) under its own
signature, and a caller-supplied `delegatedFrom` is overridden.
`AuthorizationService.issue` adds custody: the parent must be registered and
not revoked, and a refused custody check is audited as a `capability.issue`
deny event before the throw. Revocation is checked in
`AuthorizationService.evaluate()` before attenuation, so a revoked capability
fails before signature or scope verification.

**Threat model:** TM-001, TM-003.

**Assumptions:** the root principal is trustworthy; the HMAC capability key is
process-resident (known-gap #4).

**Evidence:** invariant 6 tests (rewritten against signed parents) plus the H1
suite: tampered/forged parents, foreign-subject parents (the declared-object
bypass), cross-tenant, expired, consumed, revoked, and unregistered parents,
two-hop chains, an issuance-fuzzing extremes matrix, the constraint/single-use
dimension suite (drop-network, drop-param, carry-both, narrow-hosts,
single-use-leaf), root-with-parent validation, and a structural test scanning
every `src/*.ts` for the removed declared-authority symbol.

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
the previous event's hash (`eventBody`/`eventHash`, `src/events.ts`); Ed25519
signature per event
covering the same body (`signEventBody`/`verifyEventSignature`, `src/events.ts`);
the hashed body normalizes
`metadata` through a JSON round trip so explicit `undefined` values (which
persistence drops) cannot make a stored event irreproducible after reload
(audit ticket 19, live PG); append-only SQLite with
`BEFORE UPDATE/DELETE` triggers that raise `security_events is append-only`
(`src/events.ts`); head-hash anchor file (`<seq>:<eventHash>\n`,
`appendAnchorLine`, `src/events.ts`); standalone `verifyBundle()` verifier
that operates
entirely on an exported bundle plus optional public key and anchor content
(`src/events.ts`). **H11 (ADR-031):** external anchor sinks
(`src/anchors.ts`) publish every head to operator-configured witnesses
(`HttpAnchorSink`, a second `FileAnchorSink`) without blocking an append;
`verifyAnchoredEvidence` reconciles any number of anchor sources — line/event
binding, head coverage, a source ahead of the bundle head = tail truncation,
two sources disagreeing at one seq = **fork**; `createCheckpoint` /
`verifyCheckpoint` sign and verify an operator-held `asl-anchor-checkpoint`
with the same event key (no new key), refusing truncation, rewrite, broken
chaining, same-seq forks, and bad signatures. Timestamp regressions are
reported as non-fatal anomalies; witness records carry the witness clock.

**Threat model:** TM-004 (evidence store as a target).

**Assumptions:** the anchor file path is on a medium the attacker cannot
silently rewrite (filesystem ACLs, WORM storage, or a customer-held witness).
The signing key is kept separate from the evidence store.

**Evidence:** invariant 8 tests; M3 tests (`tests/m3-evidence-hardening.test.ts`,
14 cases including signature tamper, tail truncation, anchor tampering,
offline verify, metadata-with-undefined persist/reload, and the structural
check that EventLog has no update or delete method); benchmark `hashChainValid`.

**Test:** `tests/invariants.test.ts` invariant 8;
`tests/m3-evidence-hardening.test.ts`.

**Known limitations:** a host attacker who holds the signing key can rewrite
the event store and a local anchor file *consistently* — H11 (ADR-031) closes
this whenever at least one anchor sink or the operator-held checkpoint lives
outside the runtime's trust domain (a truncated chain re-signed with the same
key fails the checkpoint; cross-source disagreement is reported as a fork).
The remaining residual is an attacker who controls the store **and every
witness and checkpoint** (including a colluding/split-view witness operator) —
that is the residual risk. Verification without the
public key still detects modification and tail truncation via the hash chain;
signature verification is what proves *who* signed each event. Rotation of
the signing key is not implemented — a key compromise requires re-signing
history (a migration, not a flag), same caveat as ADR-013.

**Residual risk:** LOW when an H11 witness or checkpoint is off-host and HONEST
(a signed checkpoint catches a full re-signed rewrite; a witness ahead of the
bundle catches truncation); MEDIUM when the anchor file and the store share the
runtime's trust domain and no checkpoint is taken; the named residual is an
attacker who controls every witness and checkpoint — multi-party public
transparency logs are the HARD-stage upgrade. Hardware-backed key custody
(HSM/TPM) remains a HARD-stage item.

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
**H8 (ADR-030):** one table-driven probe
(`tests/h8-cross-tenant-probe.test.ts`) enumerates every REST route and every
in-process query surface, and the two gaps it proved are closed:
`revealEvidence` binds a v2 keyId to its tenant (`tenantFromKeyId`) before any
registration/authorization and opens with `openFor(principal.tenantId, …)` —
a foreign-tenant seal returns `undefined`, records one clean deny event in the
caller's own tenant (without naming the foreign key), and never binds the
foreign key to the caller; `CapabilityRequestService.approve`/`deny` enforce
reviewer tenancy at the decision surface, not only at the REST boundary; and
the H13 global view (`tenantId: '*'`) is authorized only by the caller's own
tenant audit capability and exposes only tenant-less events.

**Threat model:** TM-003.

**Assumptions:** single control-plane process; resource records carry the
correct tenant id; in Postgres mode the app connects as the non-superuser
`app_rw` role (superuser bypass is operator discipline, enforced by
DEPLOYMENT.md's role setup).

**Evidence:** invariant 9 tests (three cases); ATK-003; M12 live-DB RLS
proofs (17 tests against a real Postgres: zero rows without context, zero
cross-tenant rows, INSERT with wrong context rejected, no cross-tenant
seal opening); SQLite-mode parity suite (memory + SQLite backends); H8
cross-tenant probe (23 cases: 8 REST routes, 13 in-process surfaces, 2
Postgres-gated skips) plus the evidence-seal extension (`tests/evidence.test.ts`),
including log-scan marker assertions (no foreign tenant marker or sealed
plaintext in the caller's visible records or responses).

**Test:** `tests/invariants.test.ts` invariant 9;
`tests/h8-cross-tenant-probe.test.ts` (H8 probe);
`tests/evidence.test.ts` (cross-tenant seal refusal, audited);
`tests/tenant-rls.test.ts` (live-DB RLS proofs);
`tests/event-store-pg.test.ts` (backend parity).

**Known limitations:** logical isolation only. All tenants share one
process and one memory space. In SQLite mode they share one SQLite table
(app-level checks are the only control); SQL-level isolation exists only
in Postgres mode (`EVENT_STORE=postgres`), where it covers the database —
not the shared process memory. The H8 probe proves absence of the markers it
plants, not absence of unknown leak channels (H14 territory). Low-level
id-keyed helpers (`SessionManager.get`/`activeSessionsFor`, `registry.get`)
have no tenant predicate and are not tenant-facing (the REST route owns the
check); `capabilitiesFor(principalId)` is principal-id-keyed (a collision is
re-checked by `verifyCapability` and is monotone-raise in classification
derivation); one `CapabilityRequestService` mints only for its root's tenant
(a cross-tenant approval fails closed).

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
classification level — and, for the v2 format, per **(tenant, classification)**
pair) before it is written to the evidence store. The plaintext digest is
stored so integrity is verifiable without clearance. Content can be read only
by a principal holding a capability for `evidence.decrypt` on that level's key
resource, and the read attempt is authorized and audited. An
`evidence-key:v2:<tenant>:<level>` seal additionally decrypts only for the
tenant it names (H8/ADR-030).

**Mechanism:** `seal`/`open` (legacy global-tenant) and `sealFor`/`openFor`
(v2 per-tenant) in `src/seal.ts`; `AgentSession.record` seals every non-empty
output under the session principal's tenant; `AuthorizationService.revealEvidence`
checks `tenantFromKeyId` against the caller before any registration or
authorization, then authorizes before decrypting. Default policy contains no
`evidence.decrypt` allow rule, so the default answer is denial.

**Threat model:** TM-004 (evidence store as a target), TM-003 (one store, many
tenants), TM-001 (agent used to surface secrets to a reader).

**Assumptions:** the master key is held more securely than the database. A
master key sitting on the same host as the store gives obfuscation, not
confidentiality.

**Evidence:** `tests/evidence.test.ts` — eight cases: plaintext and secrets
absent from the serialized store; digest verifiable without clearance;
unauthorized reveal denied and audited; cleared reviewer decrypts the exact
content; clearance for one level does not open another; a clearance naming
another tenant's v2 key does not open ours; an acme clearance naming globex's
v2 key cannot decrypt a globex event (refused, audited as `tenant-mismatch`,
no foreign key id copied into acme evidence); tampered ciphertext yields
nothing. `tests/tenant-rls.test.ts` (eight cases) pins the HKDF contract and
per-tenant key separation; the H8 probe carries the event-level binding case.

**Test:** `tests/evidence.test.ts`; `tests/tenant-rls.test.ts`;
`tests/h8-cross-tenant-probe.test.ts`.

**Known limitations:** no key rotation (re-sealing history is a migration);
**one master key derives every per-(tenant, level) key**, so a master-key
holder can derive any tenant's key — tenant separation at rest is
authorization-bound (the v2 keyId check), plus HKDF domain separation, not
independent custody; legacy `evidence-key:<level>` seals remain
tenant-agnostic by design (no silent re-encryption); no KMS/HSM; no protection
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

**Known limitations:** replay within a token's validity window is not detected
— the IdP's token lifecycle and the H2 revocation channel are the control (H2
bounds the window with a lifetime ceiling and adds `jti` revocation; see
Claim 37).

**Residual risk:** stolen valid tokens, bounded by the H2 lifetime ceiling and
revocable by `jti`; a token lifetime exceeding the session lifetime; a
compromised IdP signing key.

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

**Mechanism:** `node:crypto` `generateKeyPairSync('ed25519')`
(`eventSigningKeyPair`); `signEventBody` / `verifyEventSignature` over the
canonical body (`src/events.ts`); the signing key is independent of the HMAC
capability signing key (ADR-002, ADR-004); the public key is exported via
`eventPublicKey()` (`src/events.ts`) for distribution.

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

---

## Claim 32 — The supply-chain gate fails closed and the build manifest binds source, dependencies, and gate result (H10)

**Claim:** Every commit that changes the dependency set fails the
supply-chain gate until the SBOM baseline is regenerated in a reviewed PR;
every runtime dependency is exact-pinned, integrity-hashed, registry-pinned,
and named in the code-enforced allowlist; and a build manifest — when issued —
refuses to verify unless the signature is valid, both digests match the live
repository, and the recorded gate fields all say the full gate passed.
Verification is fail-closed with distinct reasons; no path prints
"verified" without a verified signature over a matching recomputed state.

**Mechanism:** `src/supply-chain.ts` (ADR-024). The gate
(`runSupplyChainGate`) regenerates the deterministic `ASL-SBOM v1` from
`package-lock.json` (every package: name/version/resolved/integrity/direct/dev,
canonically sorted, digest = `sha256(canonicalJson(sbom))` — the Claim 26
primitive) and byte-diffs it against the committed baseline
`artifacts/sbom.json`: added/removed/version-changed entries fail the gate
with remediation instructions (regenerate via `npm run sbom -- --write`, name
the admission ADR). `checkPins` refuses range characters in `package.json`
(exact versions only — every bump is a visible diff); `checkLockfileIntegrity`
requires a `sha512-` integrity value and a `https://registry.npmjs.org/`
resolved URL on every lockfile package and catches a direct-dep pin/lockfile
version mismatch; `checkRuntimeAllowlist` refuses any runtime dep outside
`ADMITTED_RUNTIME_DEPS` (jose — ADR-015, postgres — ADR-018). Malformed
manifest/lockfile/baseline is a violation, never a crash-past. The build
manifest is Ed25519-signed over its canonical form; `build sign` runs the
full release gate (typecheck + tests + supply-chain) first and refuses to
sign on any failure; `verifyManifest` checks structure → gate fields →
signature → `sbomDigest`+`runtimeDeps` (dependencies first: a lockfile change
also changes the tree digest, so the specific reason wins) → `treeDigest`
(over `git ls-files -s` blob SHAs, `artifacts/*` and `benchmarks/results.json`
excluded — committed-content hashes, platform-independent by construction).

**Threat model:** TM-004 (malicious dependency; direct code change;
"rewrite the event log" class of host-access attacks extends to the source
tree), H10's recorded residuals (trusted maintainer going rogue; a malicious
update to an already-trusted dep inside a pinned version).

**Assumptions:** the Ed25519 release key is held by the honest signer and not
by an adversary (custody is an env var until ADR-008's KMS path — the same
known-gap #4 family); `git ls-files` reports the true tracked set; the gate
runs wherever the commit or release is produced (locally via the pre-commit
hook — hooks are untracked; CI wiring is documented, not in-repo).

**Evidence:** `tests/h10-supply-chain.test.ts` — 20 cases (written
red-first): SBOM determinism and direct/transitive/dev completeness with
integrity + registry assertions; exact pins pass on the committed manifest
and refuse `^`/`~`/`*`/`>=`/`1.x` fixtures naming each dep; lockfile
integrity refuses stripped hashes, non-registry URLs, and pin/version
mismatches; the allowlist refuses an unadmitted dep with the ADR
instruction; the drift gate catches added/removed/version-changed
dependencies and a missing/malformed baseline, and passes on the committed
repository state; the tree digest is deterministic, artifacts-exclusion
holds, and staging a source change flips it; sign/verify round trip;
verify refuses tampered payload, foreign key, stale source, stale
dependencies, and gate-not-passed with distinct reasons; garbage key
material refuses (verify) and throws (sign).

**Test:** `tests/h10-supply-chain.test.ts`; the gate runs in the pre-commit
hook and `npm run supply-chain`.

**Known limitations:** the artifact of record is the source tree — there is
no compiled binary, so provenance binds inputs (source + lockfile + gate),
not a byte-reproducible output (reproducible builds are Stage 3). The
manifest binds the git index (committed content): uncommitted working-tree
changes do not flip `treeDigest` — deploy discipline is verify on a clean
checkout, and a dirty tree is not a control. No transparency-log publication
(H11), no CI enforcement, no hardware key custody — each is a named upgrade
path, not an accepted-by-silence gap.

**Residual risk:** a trusted maintainer going rogue is unchanged by any
software control here — the gate raises the cost of a malicious dependency
from "edit a JSON file" to "forge a reviewable diff AND land an admission
ADR in the same PR". An attacker with host access who also holds the signing
key can sign anything; that is the key-custody residual, not a gate defect.

---

## Claim 33 — Cross-repo evidence anchoring and capability-gated dispatch (M17)

**Claim:** A federation client can register its event-log head-hash with ASL,
and the digest is recorded in ASL's own append-only signed event log — an
attestation of the client's evidence that exists independently of the client's
repo. A claimed previous head that disagrees with the tenant's last accepted
head is flagged as `tamper`. A client can read back a capability request's
outcome and, once a human approves it, the minted capability projection. Both
routes derive the tenant from the verified principal, refuse a mismatched body
tenant, and carry no plaintext project content (a sha256 digest and event
counts only). ASL mints no authority for a federation client that a human did
not approve through the ordinary M4 flow.

**Mechanism:** `src/rest-anchors.ts` (`AnchorRegistry`, `POST /v1/anchors`)
and `src/rest-sessions.ts` (`GET /v1/capability-requests/:id`, backed by
`CapabilityRequestService.capabilityFor`). `POST /v1/anchors` validates
`headHash`/`previousHeadHash` as sha256 hex, requires `tenant ===
ctx.principal.tenantId` (else `tenant-mismatch`), and appends an
`anchor.register` event (action added to `KnownAction`) carrying the digest,
count, and a `tamper` flag when the claimed previous head mismatches the last
accepted head for that tenant. `GET /v1/capability-requests/:id` returns the
whitelisted request projection plus, when approved, the same
`projectCapability` projection the approval response uses (no signature/issuer
internals). Registration is wired into `createRestApi`; the control-plane
client (`control-plane/src/asl/`) is eligible to call them.

**Threat model:** TM-004 (host-access rewrite of client evidence), TM-003
(cross-tenant reach), the M17 control-plane thesis that "external verification
decides" — a client cannot self-attest without ASL's durable record.

**Assumptions:** ASL's own event log is append-only and signed (Claims 8/19);
the federation client is a registered principal with a resolvable bearer token;
client-side bypass is outside ASL's boundary (a client that skips the gate is
its own failure, not ASL's).

**Evidence:** `tests/m17-federation.test.ts` — 13 cases (written red-first):
anchor round trip (register → `anchor.register` event → chained anchor with no
tamper → mismatched previous head flags tamper on response and event);
tenant-from-principal refusal with no evidence on a refused anchor; non-sha256
refusal; unauthenticated 401; a throwing event append leaves the registry's
last-accepted head unchanged (session-audit ticket 01 — the in-memory head
advances only when the evidence append landed); capability status pending
(no capability), approved (capability scope equals the approved scope, no
signature leaked), denied, 404 unknown, 403 cross-tenant, 401 unauthenticated.

**Test:** `tests/m17-federation.test.ts`.

**Known limitations:** the anchor registry is in-memory, so "first anchor" vs
"lost predecessor" is not distinguished across an ASL restart — mismatch
detection is advisory; the durable attestation is the `anchor.register` event
itself, which the EventStore already persists append-only (upgrade: a
persisted accepted-head table). Tenant isolation remains the shared-process
residual (ASL known-gap #7); H8 closes it for non-personal tenants. Anchoring
is non-blocking-but-loud on the control-plane side; the dispatch gate is
fail-closed (H15 direction). Client-side bypass, worker sandbox execution, and
rate limiting on the federation seam are out of M17 scope (named in the
prompt's skip list).

**Residual risk:** a client that holds a valid bearer token and never calls the
gate is unconstrained by ASL — the federation makes authorization and evidence
available and durable, it cannot make a non-cooperating client ask.

---

## Claim 34 — The update channel refuses unsigned, stale, and rolled-back updates fail-closed (H12)

**Claim:** An update is applied only when its signed descriptor verifies,
its embedded build manifest verifies against the **live tree** (H10
recomputation), and its release version is strictly above the persisted
high-water mark. Signature validity and freshness are separate checks and
only the conjunction applies: a perfectly signed, perfectly stale descriptor
is refused (`rollback-blocked`). The high-water mark never lowers — including
under emergency rollback, which exists only as a signed, single-use,
backward-only grant naming the exact version being rolled back from (replay
→ `grant-mismatch`). Promotion through the canary stages requires an explicit
passing health signal; a failing signal halts the rollout and the halt is
sticky — no path reaches `promoted` without an explicit pass. No serialized
state, descriptor, grant, or refusal message carries key material.

**Mechanism:** `src/updates.ts` (ADR-025), CLI `node src/cli.ts update
sign|verify|apply|promote|status|grant|rollback`. The chain: descriptor
structure (`not-an-update`/`bad-stages`/`bad-version`) → Ed25519 descriptor
signature (`bad-signature`, `no-verification-key`) → embedded manifest via
H10 `verifyManifest` (`manifest-rejected:<inner reason>` — stale-source,
stale-dependencies, gate-not-passed, bad-signature all surface) →
high-water mark (`rollback-blocked`) → atomic state write (temp + rename;
corrupt state → `state-malformed`, never a reset to zero). Rollback grants
are signed with the same release key, single-use (from-version must equal
current AND the grant's `generation` must equal the state's
`rollbackGeneration`, which increments on use — a used grant stays used even
if its from-version becomes current again), and leave the mark untouched.
Stages must ascend and end at 100
(`bad-stages`); `apply` lands canary; `promote` advances one stage per pass;
failed health → `halted` (sticky).

**Threat model:** TM-004 (malicious/rolled-back software update); ROADMAP H12
failure modes — rollback to a vulnerable version, unsigned update, update as
RCE with high privilege; M18 (project-raven's unsigned self-update is RCE by
design — this seam is its gate).

**Assumptions:** the release-signing key is held by an honest custodian (the
ADR-008 env posture; one key signs builds and updates); the caller-supplied
health signal is truthful; the per-instance state file lives on storage the
update process does not share with an untrusted writer.

**Evidence:** `tests/h12-secure-updates.test.ts` — 20 cases (written
red-first): descriptor round trip + tamper/wrong-key/garbage-sig refusals;
structure/stages/version refusals before any signature claim; missing-key
refusal; full chain vs live fixture repo with inner-manifest refusals
(forged sig, stale source, gate-not-passed) surfaced as
`manifest-rejected`; apply advances the mark and persists across loads;
stale signed descriptor refused with the mark holding; corrupt state file
refused, not overwritten; sticky halt (a passing signal does not clear it);
one-stage-per-pass promotion to `promoted` with `no-pending-rollout`
afterward; no default-healthy promote; signed grant moves `current` back
without lowering the mark and cannot be replayed; burned version stays
burned (re-apply refused, next version applies); a used grant stays used
even when its from-version becomes current again (audit 01 regression,
generation mismatch refuses, a fresh grant at the current generation still
works); distinct grant refusals
(structure, signature, key, direction) with no state mutation; structural
invariant — no key material in state/descriptor/grant/signatures/refusal
text, state shape exactly the declared contract.

**Test:** `tests/h12-secure-updates.test.ts`; demo section 21 exercises the
chain end-to-end on ephemeral demo keys (`npm run demo`, exits 0).

**Known limitations:** the health signal is a caller-supplied boolean — a
lying caller can promote a canary (upgrade: per-instance attested health,
when a second instance exists); canary cohort selection is the deployer's
(the module gates promotion, not scheduling); there is no transport — this
repo verifies updates, it does not host them (upgrade: a release endpoint
when one exists); no descriptor transparency log (H11/Stage-3); one release
key, no separate update key until a ceremony decides otherwise (ADR-008);
the state file must outlive the update process and be protected from
untrusted writers — an attacker who can delete it resets the mark (this is
why it is code-written only, atomic, and gitignored per instance).

**Residual risk:** a *signed but malicious* release — the ROADMAP-stated
residual and H10's trusted-maintainer residual, unchanged by this control: a
compromised release key or coerced maintainer signs anything. H12 raises the
cost of rollback-and-unsigned attacks to "forge a signature AND beat a mark
that never goes down"; it does not raise the cost of signing a bad release.

---

## Claim 35 — The kill switch freezes authority immediately in-process and propagates within the poll interval; preserved evidence verifies offline (H13)

**Claim:** One operator action (`IncidentService.engage`) freezes issuance and
authorization for a tenant or globally, revokes every registered capability
and session in scope, and broadcasts the decision through the revocation
channel. A frozen tenant's next decision denies with the distinct
`denyReason: 'incident-frozen'` and its `issue` refuses with an audited
`capability.issue` denial — not a generic failure. Cross-node propagation is
bounded by the channel poll interval (default 1 s, inside the ROADMAP ≤ 5 s
target); issuance force-syncs so a post-freeze mint cannot slip through a
throttle window. `lift` clears the freeze only — revoked authority is never
restored. Evidence-read capabilities survive the bulk revoke and remain
authorized while frozen, so an incident can be reconstructed and preserved
during the response. `preserve` pages the ordinary authorized audit export
past the M6 1000-event cap and writes an `asl-incident-bundle` whose content
digest, event chain, and Ed25519 signatures verify offline; the event log
records digest + head + counts, never event content. A filtered view (global
incident via `tenantId: '*'`, or a tenant interleaved with other tenants) is
recorded as non-contiguous and verified per-event (hash + signature + the
recorded live-chain state + anchor head) instead of requiring slice linkage.

**Mechanism:** `src/incident.ts` (ADR-026) + `src/incident-store-pg.ts`
(migration id 4, `revocation_channel`) + chokepoint edits in `src/pdp.ts`
(freeze check first in `evaluate`, refusal at the top of `issue`) and bulk
methods on `src/session-manager.ts`. The channel is the one deliberate
multi-writer table (append-only by privilege: `app_rw` SELECT/INSERT, no
UPDATE/DELETE grant, no RLS — control-plane coordination data with no claim
content); the event chain stays single-writer. Records are scope-level
(`freeze`/`unfreeze`/`revoke-caps`/`revoke-sessions`) and single-target
(`revoke-cap`/`revoke-session`/`revoke-token`); a tenant-scoped `revoke-cap`
record can only
revoke a capability registered to that tenant (audit 12), and `revoke-caps`
is fenced by local issuance
time so replay cannot kill authority issued after the incident. A fresh node
replays from cursor 0. A malformed/unknown channel row is rejected and
skipped with the cursor advancing past it (audit 01) — one hostile or
future-version row can never stall propagation on a node, and the rejection is
loud through `health()`. A channel outage still engages locally and reports
`broadcastOk: false`; async backends surface failures through `health()`, and
`flush()` awaits every in-flight write and refresh before health is read
(audit 19, live PG).
CLI: `node src/cli.ts incident status|engage|lift|revoke-cap|
revoke-session|revoke-token|preserve|report`; operator commands build a bootstrap-free
world (no fixture issuance/appends) and print a diagnosable refusal instead of
a stack trace.

**Threat model:** TM-004 (operators and evidence integrity); ROADMAP H13
failure modes — cannot revoke quickly, cannot freeze issuance, cannot
reconstruct, cannot preserve evidence; ADR-022 (federation: an operator kill
switch that reaches a running node; M18's unattended agent).

**Assumptions:** an on-call human exists and can act; clocks across nodes are
roughly synchronised (the issuance-time fence and record timestamps compare
wall clocks); the channel is control-plane data and its reason text contains
no secrets; a channel writer is an operator (write access is the incident
authority).

**Evidence:** `tests/h13-incident-response.test.ts` — 29 cases (written
red-first): engage denies the next decision with `incident-frozen` + records
it; issuance blocked with an audited refusal; `lift` restores authorization
but not revoked capabilities; tenant vs global scope; `revokeAll`
tenant-scoped and audited per capability; kill-switch latency immediate with
no clock advance; input validation; session bulk revocation + engage session
sweep; two-node shared-channel propagation denied after exactly one 1 s
interval; forced issuance sync inside a 60 s throttle window; fresh-node
replay from cursor 0; single-target revoke-cap/revoke-session cross-node (the
session revocation is also a signed-log event — audit 05); monotonic channel
cursor; channel outage engages locally with `broadcastOk=false`; the REST
server pulls the channel once per authorized request; preserve round trip
(file written, digest recomputable, offline verification valid, digest + head
+ counts only in the event); paging past 1000 events; denied principal
refused with no file; tampered bundle fails offline verification;
reconstruction counts; the global-incident view (`tenantId: '*'`) reads
`tenantId: ''` events, refuses without authority, and preserves a verified
bundle; `bootstrap: false` builds a world that issues/appends nothing; all
under the structural invariant — no key material or secret canaries in
channel records, incident events, or the bundle. Audit follow-ups (tickets
10/12/16): cross-node `unfreeze` propagation leaves revoked capability
revoked; the `revoke-caps` issuance-time fence spares authority issued after
the record; a tenant-scoped `revoke-cap` record cannot revoke another
tenant's capability and the operator path refuses a locally registered
tenant mismatch; `grant()` while frozen registers authority that `evaluate`
still denies until `lift`.
`tests/h13-revocation-pg.test.ts` — migration DDL static invariants
(append-only privilege, no RLS, constrained scope, no secrets) and the live
scratch-DB suite (two-instance broadcast, `app_rw` UPDATE/DELETE refusal,
hostile-row refusal, and the audit-01 skip-and-count regression: a bad row
does not stall later rows and the cursor advances), skip-clean without
`DATABASE_URL`; verified live 2026-10-01 against `postgres:16` (ticket 19),
which proved the migration-4 sequence grant and the flush write-tracking fix.
`tests/h13-import-order.test.ts` — the channel module imports
cleanly when loaded first (audit 03 import-cycle regression).

**Test:** the two suites above; demo section 22 exercises a measured
engage-to-deny latency, a two-node interval-bounded broadcast, and a verified
preservation round trip (`npm run demo`, exits 0).

**Known limitations:** propagation is pull-based — a node that never issues a
decision or receives a REST request does not sync (default deployments route
everything through the PDP/REST, named honestly); a channel outage widens the
propagation window and is reported through `broadcastOk`/status counters
rather than hidden; in-memory freeze state is lost on restart unless the
Postgres channel replays it (cursor 0); the live multi-node Postgres proof
was run 2026-10-01 against a disposable `postgres:16` container (ticket 19):
the four live channel tests pass, and the run caught the migration-4 sequence
grant and the flush write-tracking defect (both fixed); single-target session
revocation reaches a node only when its sync runs; cross-process
`preserve`/`report` require the event-signing key to be shared
(`EVENT_SIGNING_PRIVATE_KEY_PEM` + `EVENT_SIGNING_PUBLIC_KEY_PEM` on the
signing node and the operator process) — with the default ephemeral key the
command fails closed with a `signature mismatch` and now says so; the global
view (`tenantId: '*'`) is authorized by the caller's own tenant's
`audit.export` capability and exposes only the events recorded with no tenant;
non-contiguous (filtered) bundles verify per-event authenticity rather than
chain linkage, so they prove each event is authentic and the live chain was
valid at preservation time, not that the event sequence is unbroken;
retention/legal hold is
out of scope (evidence is append-only and never deleted today; preservation
is an artifact, not a retention engine); the operator CLI mints audit
authority through the existing root issuance path (split operator identity is
the named upgrade).

**Residual risk:** a compromised operator with channel write access can freeze
legitimate work — denial of service is the accepted H15 trade, made loud and
recoverable (`lift`, counters, events). Incident response can still be slower
than the attack (the ROADMAP residual): the mechanisms shrink the window; they
cannot shrink the attacker's head start.

---

## Claim 36 — Failures are loud, per-dependency, and recoverable; degradation never widens authority (H15)

**Claim:** Every dependency fault on the decision path denies with its own
distinct reason AND an observed-health transition: a throwing policy engine
denies `evaluation-error`; an unwritable evidence store denies
`store-unavailable` (typed backend refusal) or `evidence-write-failure` (any
other failed write); an unusable, stalled, or backward clock denies
`clock-unavailable` (new). A fault can never produce an allow — degradation is
deny-only — and recovery is automatic and loud: the first successful call
after a fault marks the dependency `ok` and emits the recovery transition.
`HealthState` (`src/health.ts`) observes what the decision path actually
experiences (append succeeded/failed, engine returned/threw, clock read
valid/faulted) and emits one `process.emitWarning` per transition (down and
recovery) instead of one warning per denied decision. `ClockGuard` treats a
throw or non-finite reading as a clock fault always, and enables stall
(wall frozen while an injected monotonic reference advances) and backward-jump
detection only with that monotonic reference — deterministic test clocks
freeze and travel backward by design. `GET /healthz` reports
`{ idp, store, engine, clock }` when a `HealthState` is wired (the M14
`{ idp, store }` shape otherwise). Safety mechanisms degrade the same way:
`issue()` records the issuance event before registering the capability (a
store outage refuses the mint — no unaudited authority); `unfreeze` records
evidence before clearing the freeze (a lift that cannot be recorded stays
frozen — widening needs evidence); `revokeAll` completes the kill switch past
per-capability evidence failures and `IncidentService.engage` completes local
enforcement during a store outage, reporting `evidenceRecorded: false`
(narrowing applies first and reports missed evidence). The benchmark measures
`authorize()` p99 with persistence (SQLite-file `EventLog`) and without
(in-memory), two advisory SLO rows.

**Mechanism:** `src/health.ts` (ADR-027: `HealthState` + `ClockGuard`) plus
chokepoint edits in `src/pdp.ts` (`readClock`, `clockFaultDeny`, health marks
on engine/append outcomes, evidence-before-authority in `issue`, evidence-
before-`unfreeze`, resilient `revokeAll`), `src/incident.ts`
(`engage`/`lift` report `evidenceRecorded`, `IncidentActionResult` shape),
`src/rest-api.ts` (optional `health` dep extends `/healthz`), and the
benchmark/SLO catalog (`src/cli.ts`, `src/slo.ts`). Health details are short
fixed labels — never error messages, never secrets. Rate limiting is resolved
as deployment territory (reverse proxy), not built in-process.

**Threat model:** H15 (fail-closed availability — the failure modes of the
safety mechanisms themselves); ROADMAP H15 residual (an induced fault is a
DoS: make it loud, bounded, recoverable); TM-004 operations.

**Assumptions:** fail-closed stays the default; an operator watches the
warning stream or `/healthz` (alert routing is the operator's); the embedder
wires the monotonic reference in production (`new ClockGuard(Date.now, {
monotonic: () => performance.now() })` — DEPLOYMENT.md); the reverse proxy
owns request rate limiting.

**Evidence:** `tests/h15-fail-closed-availability.test.ts` — 24 cases (19
written red-first + 5 audit-follow-up regression cases): engine throw →
`evaluation-error` + `engine: unavailable` +
transition; engine recovery; typed store outage → `store-unavailable` (never
an unrecorded allow) + transition, and the untyped (full disk) variant →
`evidence-write-failure`; store recovery; one transition per outage, not one
per denied decision; throwing and non-finite clocks → `clock-unavailable`;
stalled and backward clocks under the strict guard, with automatic recovery;
the false-denial pin (frozen/backward clocks pass without a monotonic
reference); IdP outage keeps `idp-unavailable` for unauthenticated principals
while authenticated authority continues; `issue()` under a store outage
refuses and leaves nothing registered; `revokeAll` completes under evidence
failure; `engage` completes local enforcement with `evidenceRecorded: false`;
`lift` refuses when its evidence cannot be recorded and the freeze stays
engaged; `/healthz` reports the four statuses and tracks observed faults; the
M14 shape is unchanged without a `HealthState`; the structural invariant —
health state, transitions, and emitted warnings carry no secret values.
`tests/slo.test.ts` (benchmark integration) exercises the two new advisory
rows end to end.

**Test:** the suite above; demo section 23 injects store and clock faults
against a live stack and prints deny reason + health snapshot + recovery
(`npm run demo`, exits 0); `npm run benchmark` prints both decision-latency
p99 rows and exits 0.

**Known limitations:** `HealthState` is in-memory — a restart resets to `ok`
until the next observed fault re-marks it (the transition then fires again);
clock trend detection needs the monotonic wiring (the lenient guard still
catches throw/non-finite clocks); the engine-fault reason is shared with other
evaluation errors (split `engine-unavailable` when an on-call rotation needs
per-dependency alerting); health signals live outside the signed event chain
deliberately (a fault storm must not flood the evidence chain); alert
routing/paging is the operator's; rate limiting is the deployment's.

**Residual risk:** an adversary who can induce a dependency fault gets a
denial of service — the accepted ROADMAP trade, now loud, bounded, and
recoverable. The safety mechanisms themselves are protected by the same
contract: they complete what they can and report what they could not record.

**Audit follow-up (2026-10-02):** the session audit found the production
broadcast-sync hook bypassed the guarded clock read — a faulted clock crashed
`authorize`/`issue` instead of denying `clock-unavailable` (probe-proven on
both paths). Fixed: `syncBroadcast` try/catches its clock reads; `issue()`
records its clock-fault refusal; grant/consume/revoke/freeze use a
fault-tolerant `bookkeepingNow()` so a clock fault cannot disable the kill
switch or leave a single-use capability unconsumed; `clockFaultDeny` recovers
store health on its successful append; `queryAudit`'s clock-fault branch is
tested. 5 regression cases added (suite: 24).

---

## Claim 37 — Only short-lived, revocable credentials are honored; workload identity is derived and claim-minimal (H2)

**Claim:** `IdentityProvider.verifyToken` refuses any JWT that does not carry a
non-empty `sub`, finite `exp` and `iat`, and a non-empty `jti`; a positive
declared lifetime (`exp - iat`) at most `maxTokenLifetimeSec` (default 3 600 s
= 1 h; the configured ceiling is itself capped at 86 400 s = 24 h); an `iat`
no more than the clock tolerance in the future; and an `exp` no more than the
tolerance in the past. The tolerance is bounded (default 30 s, hard cap 60 s —
a config outside the bound throws `IdentityConfigError`) and is **actually
applied**: the old `clockToleranceSec` option is not a `jose` option
(`clockTolerance` is), so the configured tolerance had silently never applied
before H2. Missing or ill-typed claims produce the same fail-closed result as
a bad signature (no reason oracle to the caller). A revoked `jti` is rejected
immediately on the local node and across nodes on the H13 revocation channel
(`revoke-token` records consumed by `attachRevocationFeed` or routed by
`IncidentService.applyRecord`; `IncidentService.revokeToken` applies
local-first before broadcasting; CLI `incident revoke-token`). Workload
identity is derived from an already-verified parent by
`IdentityProvider.workloadAuth` (and `sessionAgent` through it): distinct
subject, `wl:<workload>:<parent jti>` token id, `issuedAt` = now, expiry
`min(parent.expiresAt, now + maxLifetimeSec)` (default 900 s), `amr: []`,
`claims: {}`, explicit `derivedFrom`. Raw JWTs are never stored on an
`AuthContext`; no event or error response contains a minted token or a token
payload claim.

**Mechanism:** `src/identity.ts` (`validateTokenClaims`; bounded config +
admission check in `verifyToken`; `workloadAuth`; `attachRevocationFeed`; the
jose `clockTolerance` wiring); `src/domain.ts` (`AuthContext.derivedFrom`);
`src/incident.ts` (`revoke-token` record action, `TokenRevoker`,
`IncidentService.revokeToken`, `applyRecord` routing); `src/cli.ts`
(`incident revoke-token`). Zero new runtime dependencies (ADR-028).

**Threat model:** TM-005 (token forgery/algorithm confusion — the lifetime and
claim contract); ROADMAP H2 failure modes (leaked long-lived token, clock skew
extending life, credential in a crash dump or event payload).

**Assumptions:** the IdP includes `sub`/`exp`/`iat`/`jti` (RFC 9068 requires
them for JWT access tokens) and issues short lifetimes; NTP with
authentication; credential revocation rides the H13 channel (Postgres across
processes, in-memory single-process).

**Evidence:** `tests/h2-short-lived-credentials.test.ts` — 31 cases: admission
contract (missing/ill-typed claims, non-positive lifetime, boundary ceiling,
future `iat`, expired beyond tolerance) plus a deterministic 2 000-case expiry
fuzz whose acceptance matches the declared predicate; end-to-end jose
verification (1 h verifies, 2 h refused, missing claims refused, the tolerance
regression — expired-by-10 s verifies, expired-by-45 s refused — future-issued
refused, config bounds throw); workload derivation (workload cap, parent cap,
empty claims/`amr`, derivation marker, expired parent denies
`unauthenticated-principal`, custom ceiling, argument validation);
revocation propagation (node A local-first rejection, node B via the feed, the
`applyRecord` path, target-less records ignored, feed outage keeps verification
available, REST 403 before principal mint); credential-in-log scanning (raw
token and payload canary absent from events, responses, and errors on success
and failure paths; no serialized `claims`).

**Test:** `tests/h2-short-lived-credentials.test.ts`; the full gate
(`npm run typecheck && npm test` — 653 tests / 634 pass / 0 fail / 19
Postgres-mode skips).

**Known limitations:** the revoked set is in-memory per process (the Postgres
channel is the durable coordination path); revocation propagation is
poll-bounded (1 s default); the window of validity (≤ 1 h default) and
in-memory exposure during token processing are the ROADMAP residuals; a stolen
valid token is replayable until expiry unless its `jti` is revoked; derived
workload contexts are in-process values, not IdP-issued credentials, so they
cannot cross a process boundary; SPIFFE/SPIRE attestation and
mTLS/`private_key_jwt` client auth are the named H2 skip-list items; the
ceiling applies to ASL as verifier — other consumers of the same IdP tokens
are unaffected.

**Residual risk:** a compromised IdP key can forge tokens this claim cannot
distinguish from legitimate ones (M2's accepted trust dependency); clock skew
is bounded, not eliminated; a channel outage delays revocation propagation (it
never extends a token's own expiry).

---

## Claim 38 — Cross-tenant isolation is probe-verified across every surface, and a v2 evidence key opens only for its tenant (H8)

**Claim:** Every REST route and every in-process query surface reachable by a
tenant enforces tenant isolation in both directions, and a cross-tenant attempt
leaves no foreign tenant marker or content in the caller's visible records or
responses. Specifically: an `evidence-key:v2:<tenant>:<level>` seal decrypts
only for that tenant — a capability naming another tenant's key id cannot open
it and cannot re-bind the key in the registry; capability-request
approval/denial requires a reviewer from the request's tenant; the H13 global
evidence view (`tenantId: '*'`) is authorized only by the caller's own tenant
audit capability and exposes only tenant-less events; and audit/export,
event-store, registry, session, capability-request, and persistence reads never
return another tenant's rows.

**Mechanism:** `src/pdp.ts` (`revealEvidence`: `tenantFromKeyId` check before
the lazy key registration, `openFor(principal.tenantId, …)` as a second
binding, one clean `tenant-mismatch` deny event in the caller's own tenant
without naming the foreign key); `src/seal.ts` (`tenantFromKeyId`);
`src/capability-request.ts` (`requireSameTenant` in `approve`/`deny`; `deny`
has no REST route, so the decision-surface check is its only tenant guard). The
existing guards are unchanged: PDP `resource.tenantId` check, `queryAudit`
`filters.tenantId` check, REST route tenant checks, Postgres `FORCE RLS`.
ADR-030.

**Threat model:** TM-003 (cross-tenant).

**Assumptions:** the probe's rows cover every tenant-facing surface at the
time of writing (a new surface must add a row); the planted markers are
representative of tenant data; the process itself is not compromised
(known-gap #7).

**Evidence:** `tests/h8-cross-tenant-probe.test.ts` — 23 cases (8 REST:
authorize, sessions, audit, capability requests, anchors, tasks, healthz,
static pages; 13 in-process: audit query/export, event-store reads plus the
`global-by-design` chain view, registry, tenant-wide session revocation,
capability-request review, retention-ledger tenancy, evidence-key binding, the
incident global view and preserve, log-scan; 2 Postgres-gated storage cases
that skip cleanly); plus the
evidence-seal extension in `tests/evidence.test.ts` (the cross-tenant decrypt
refusal, audited, without copying the foreign key id into the caller's
evidence). The red run — the wrong tenant decrypted globex content and the
cross-tenant review was accepted — is captured at `.scratch/h8/red.txt`.

**Test:** `tests/h8-cross-tenant-probe.test.ts`; `tests/evidence.test.ts`
(seal extension); `tests/tenant-rls.test.ts` (live-DB RLS proofs); the full
gate (`npm run typecheck && npm test` — 716 tests / 695 pass / 0 fail / 21
Postgres-mode skips).

**Known limitations:** the probe proves isolation in the directions and with
the markers it plants; it is not a proof of absence for unknown leak channels
(H14). The shared process remains in both modes — Stage-3 physical isolation is
the structural fix. SQLite mode stays app-level only. Legacy
`evidence-key:<level>` seals remain tenant-agnostic by design (no silent
re-encryption). Named residuals in ADR-030: principal-id-keyed low-level
helpers, one `CapabilityRequestService` per root, hardware side channels.

**Residual risk:** a memory-disclosure or serialization bug in the shared
process crosses the boundary; a deployment that does not accept the
shared-process residual must run per-tenant processes (Stage 3).

---

## Claim 39 — External anchoring and recorded legal holds make host-level evidence tampering detectable (H11)

**Claim:** A whole-log rewrite, tail truncation, selective line deletion, or
anchor edit is detected against external evidence — an operator-configured
anchor sink (HTTP witness or second file path) or an operator-held signed
checkpoint — even when the attacker holds the event-signing key and re-signs
the rewritten chain. Verification dispatches on multiple anchor sources: a
line that disagrees with the event at its seq fails binding, a source ahead of
the bundle head is tail truncation, two sources disagreeing at one seq is a
reported fork, and a bundle head no source anchors fails closed as
`unanchored`. A signed checkpoint binds `(seq, headHash)` and chains to its
predecessor; it refuses a truncated chain, a rewritten event at the bound seq,
a broken chain link, a same-seq fork, and a bad signature. Anchor publication
never blocks an evidence append, and a failing witness is loud (counters +
fixed-label error) rather than silent. Legal holds are signed
`evidence.hold`/`evidence.release` events replayed into a tenant-bound ledger;
a principal can only hold or release ranges in its own tenant, and no
update/delete path exists at any storage layer.

**Mechanism:** `src/anchors.ts` (`AnchorSink`,
`FileAnchorSink`, `HttpAnchorSink` — bounded queue, kick + `flushAnchors()`,
env-only bearer token never logged; `parseAnchorLines`,
`verifyAnchoredEvidence`, `createCheckpoint`/`verifyCheckpoint` signed with the
existing event key; `fetchWitnessHeads` shape-validates the witness response
and never echoes its body). `src/events.ts` fans every append out to the
configured sinks (a throwing sink is wrapped) and reports timestamp
regressions in `VerificationResult.timestampAnomalies`.
`src/rest-anchors.ts` rehydrates accepted federation heads from
`anchor.register` events. `src/retention.ts` (`RetentionLedger`, rehydrated
from the log; `evidence.hold`/`evidence.release` in `KnownAction`). The
CLI checkpoint/hold/release commands refuse fail-closed when the process key
cannot verify the chain (`chainKeyRefusal`, H13 parity — an ephemeral-key
process cannot append unverifiable records to the shared chain). ADR-031.

**Threat model:** TM-004 (evidence store as a target: whole-log rewrite,
anchor collusion, clock manipulation, selective deletion).

**Assumptions:** at least one anchor sink or checkpoint lives outside the
runtime's trust domain (filesystem ACLs/WORM mount, an operator-held file, or
a witness host); the witness token, when configured, is secret; the witness
operator does not collude with the attacker.

**Evidence:** `tests/h11-tamper-evident-evidence.test.ts` (39: sink fan-out +
failure isolation + queue bound + token-redaction + memory-world env exclusion
9; witness protocol 5;
anchor reconciliation — binding, truncation, gap, fork, unanchored tail,
timestamp anomalies 10; checkpoints — round trip, truncation, full re-signed
rewrite, tamper/wrong key, chaining/fork, signed eventCount mismatch 7;
federation head rehydration 1;
holds — record, release, rebuild, cross-tenant refusal, structural no-delete 5;
chain-key precondition — verifiable chain passes, foreign-key chain refuses
with the shared-key hint 2).
Plus the H8 probe's `retention-ledger-tenancy` row. The red run —
`ERR_MODULE_NOT_FOUND` before the module existed — is captured at
`.scratch/h11/red.txt`. Demo section 24 shows two anchor sources + a checkpoint
verifying, a re-signed truncation detected, a fork detected, and a hold
surviving a ledger rebuild (demo exits 0).

**Test:** `tests/h11-tamper-evident-evidence.test.ts`;
`tests/h8-cross-tenant-probe.test.ts` (the retention row); full gate 716 tests
/ 695 pass / 0 fail / 21 Postgres-mode skips.

**Known limitations:** a bundle with no source/checkpoint presented verifies
internally but is reported `unanchored` — external corroboration is only as
good as what the verifier is given. Checkpoints verify the **full dense chain
from seq 0**; a tenant slice must be anchored per-event (slice bundles verify
with `contiguous: false` semantics via `verifyBundle`). The HTTP witness
protocol has no paging above 100,000 heads (`ponytail:` upgrade path named).
Publication is best-effort: a witness outage reduces granularity and a queue
overflow drops the oldest points (counted). Clock anomalies are reported, not
fatal (a legitimate clock step exists). `evidence.hold` currently guards a
future prune path, not a live deletion operation — there is none.

**Residual risk:** an attacker who controls the store, the local anchor, every
witness, and the operator's checkpoints leaves no external evidence to
disagree with (H11's named residual); witness-operator collusion or a
coordinated split view is not detectable by reconciliation alone — multi-party
public transparency logs are the HARD-stage upgrade. Signing-key custody and
rotation remain ADR-008-family residuals.



---

## Claim 40 - Adversarial evaluation is reproducible, and corpus or decision drift fails loudly (H14)

**Claim:** `npm run adversarial` runs every enumerated lane - the 12-case
attack corpus plus the legitimate-task fixtures, each required to behave as
specified; a corpus+fixture digest comparing against a committed baseline; a
digest of the policy decision vector across every policy fixture scenario; and
a policy mutation lane, where every mutant of the baseline policy must be
killed by the golden decision set. Adding, removing, renaming, or editing a
case, any change to the decisions the baseline policy produces, or a mutant the
goldens cannot distinguish, fails the run with a non-zero exit until the
baseline is re-blessed by an explicit `--bless`. The run is reproducible: the
same tree digests identically across processes, and two engines built from the
same policy produce the same decision-vector digest.

**Mechanism:** `src/adversarial.ts` (`digestDirectory` — sorted names plus NUL
separators, so renames and re-concatenations cannot collide; `decidedVector` /
`digestDecisionVector`; `driftLane`, `differentialLane`, `corpusLane`,
`mutationLane`, `buildReport`). `src/mutation.ts` (`mutateRules`,
`evaluateMutants`, `summarize`) mutates each rule in the ways review misses and
kills a mutant when the golden set disagrees anywhere. `src/cli.ts`
`adversarial` command composes the existing `runAttackCorpus`, `loadFixtures`,
`simulate`, and `verifyGolden` primitives. Baseline at
`artifacts/adversarial-baseline.json` (committed, diffable); report at
`artifacts/adversarial-report.json` (per-run, gitignored).
`scripts/schedule-adversarial.ps1` registers an operator-local nightly run.

**Threat model:** TM-002/TM-003-adjacent — the risk this claim addresses is not
an attacker but the platform's own test suite silently drifting away from what
it was written to prove.

**Assumptions:** the committed baseline is reviewed when it changes; the
operator schedules the run (nothing in the repo enforces cadence); the corpus is
implementer-authored.

**Evidence:** `tests/h14-adversarial.test.ts` (16) and
`tests/h14-mutation.test.ts` (14). Determinism and drift sensitivity are proven
on temp dirs; the no-plaintext property is proven with a canary token.
End-to-end, a cloned corpus case passes every case while failing the drift lane
(SESSION 38); the first mutation run found 5 survivors, all real coverage holes
in the golden set, which were closed by adding scenarios rather than
allowlisting (SESSION 40), and weakening the oracle now lets a mutant survive so
the lane catches it.

**Residual risk:** this is evidence that *enumerated* attacks
still behave as specified - **not** evidence of safety. The corpus is written by
the implementer, so unknown-unknown attacks remain open. The mutation lane is
only as strong as the mutation operators written: a mutant we never generate is
a mutant we never catch, and a proven-equivalent allowlist entry is a judgement
call made by a human in a hurry. There is no external red team (operator
obligation, never an acceptance criterion), and no claim of *continuous*
evaluation - this repository
has no scheduler and its only remote is a local bare repo, so the schedule is
the operator's and a missed night is invisible except via
`scripts/schedule-adversarial.ps1 -Status`.

---

## Claim 41 - Policy evaluation is deterministic and order-invariant in effect; dead or shadowed rules are refused at load (H3)

**Claim:** Given the same rules and the same request, the engine returns the
same decision, independent of evaluation history and of which process built the
engine (500 seeded random contexts, two engines, identical results; repeat
evaluation stable; a denial does not change the next answer). The decision's
*effect* does not depend on rule declaration order under permutation (200
contexts) — matching deny wins, otherwise any matching allow wins, otherwise
default deny. A hash-verified policy bundle that carries a rule which can never
fire, or an allow whose every matching point is also denied, is **refused at
load**, before an engine exists. A committed versioned golden decision set binds
the full expected result (effect, ruleId, reason) to a policy hash, so any
semantic change fails until it is re-blessed deliberately.

**Mechanism:** `src/policy.ts` (`matchesRule` — the single matcher shared by the
engine's hot path and the analyzer; `compileRulePatterns` — the compiled cache,
deliberately required so a pattern can never silently degrade to a literal
comparison). `src/policy-analysis.ts` (`analyzePolicy`: `unreachable`,
`shadowed`, `ambiguous-allow`, `unknown-action`, over a rule-derived,
capped point set). `src/policy-config.ts` (`assertRulesShape` +
analysis inside `loadPolicyBundle`). `src/policy-testing.ts`
(`loadGolden`/`verifyGolden`/`goldenHash`). Goldens at
`tests/fixtures/policy/goldens/baseline-decisions.json`;
`npm run policy:analyze` / `npm run policy:golden`.

**Threat model:** TM-001/TM-003-adjacent — the risk is a policy that reads
correctly and grants nothing, or grants two things at once and credits whichever
was written first.

**Assumptions:** rules are finite and statically analysable (the ROADMAP's own
assumption); the golden set is reviewed when re-blessed; the analyzer's sampled
domain is representative of the traffic the policy actually sees.

**Evidence:** `tests/h3-policy-adversarial.test.ts` (21) — determinism fuzz,
permutation invariance, analyzer findings, bundle refusal on load, performance
bounds (2000 rules × 2000 decisions; compile cache stable on the decision path;
500-segment id bounded), golden verification, and the mutation-coverage test:
flipping or deleting **any** baseline rule is caught by the golden set.

**Residual risk:** the analyzer samples a rule-derived domain — it can miss a
conflict that exists only at a point it never generates, and it can never prove
absence of conflict. **Attribution** is order-dependent: when two allow rules
match the same point, the `ruleId` and `reason` recorded in evidence follow
declaration order (`ambiguous-allow` is a warning, not an error). Changing that
is an audit-visible semantic change and needs its own ADR. Policy authored
incorrectly remains a human error the analyzer only partly catches; semantics
too clever is untouched.

---

## Claim 42 - A session's data-flow label survives across steps, and revocation does not un-see data (H4)

**Claim:** Every step of a session carries a `TaintLabel` — the maximum
classification of everything it has touched, the resource ids that contributed,
and whether any contributor was attacker-influenceable. The label is carried
across steps within the session, so data read in step 1 is still labelled in
step 3 **even if the capability that justified the read has been revoked or
consumed by then**. A mutating write raises its target to at least this label
(the coarse session derivation remains a floor), so a session cannot launder
high-classification data into a public resource by losing the grant that exposed
it. Evidence records `{ classification, sources, untrusted }` per execution
event and never the content.

**Mechanism:** `src/taint.ts` (`combine` — max classification, union of sources,
OR of `untrusted`; no lowering operation; `taintFor`, `taintMetadata`).
`src/runtime.ts` (`AgentSession.carried`, seeded from ingested data in `run()`
and folded per step in `attempt()`; `ExecutionContext.resourceClassification`;
`ToolResult.taint` as a raise-only declaration; the raised classification is
`max(coarse derivation, label)`; `record()` writes the label into event
metadata). `src/sandbox-registry.ts` passes the sandbox resource label through.

**Threat model:** TM-002 (data injection). The PDP already stops injected
instructions from minting authority; this claim covers the other direction —
injected or merely sensitive *data* moving to a place it should not reach.

**Assumptions:** the target resource's registry classification is correct; a
tool that fetches foreign data declares it (undeclared output is trusted to be
the target's own data — see the residual).

**Evidence:** `tests/h4-dataflow.test.ts` (9). The laundering case is
constructed explicitly: a scoped session (empty content map), a phi read through
a tool, `authorization.revoke` of the justifying capability, then a write under
only a public capability — the target ends at `phi`. The end-to-end half runs
all four corpus documents through a hostile model: every step is denied,
executed false, marked `untrusted`, with the source id named.

**Residual risk:** the model's reasoning is unobservable, so the claim is about
a step's *inputs*, never "this request was caused by that document" — a
semantic deviation inside granted scope is the ROADMAP's named residual. An
undeclared tool output under-states provenance (`ponytail:` marker in
`src/runtime.ts`; a declaration becomes mandatory at H6's protocol boundary). A
tool that declares a *lower* label than the data it fetched is believed; the
label can still only raise.

---

## Claim 43 - A canary cannot leave in any cheap encoding, and a refusal never repeats what it caught (H7)

**Claim:** Every egress path inspects the bytes it is about to send. A payload
whose classification exceeds the destination ceiling is refused (this check runs
first and is authoritative), a payload carrying a planted canary value is
refused in the raw, base64 (standard and url-safe), hex, or url-encoded forms,
including when the whole body is base64/hex-encoded, and a payload over the byte
cap is refused. No refusal reason or finding detail contains the value it
caught — the verdict is safe to log, which matters because the alternative makes
the error message the leak.

**Mechanism:** `src/dlp.ts` (`scanForCanaries`, `tokenEncodings`, `inspectEgress`;
fixed-label reasons). `src/model-http.ts` inspects `prompt + context` before any
fetch and records `denyReason: dlp-refused` (a distinct reason, per H15).
`src/egress-proxy.ts` buffers request bodies up to the cap and inspects them
before forwarding.

**Threat model:** TM-002 (data injection) — the allowlisted-channel leak: the
destination is permitted, the PDP says yes, and the bytes are the attack.

**Assumptions:** the canary list is maintained, and the destination ceiling is
the operator's intended policy; both are configuration, not mechanism.

**Evidence:** `tests/h7-egress-dlp.test.ts` (14). Encoding coverage is
enumerated rather than sampled; the no-echo property is asserted by rendering
the whole verdict and searching it for every encoding of the token; the model
adapter test proves `fetch` is never called; the proxy test proves an allowlisted
host is still refused a canary body.

**Residual risk:** human-approved exfiltration (an operator clicking send is the
authorisation); steganography; semantic paraphrase and arithmetic encodings
beyond one decode pass; slow drip across many requests, because the cap is
per-request (`ponytail:` marker in `src/egress-proxy.ts`); a compressed body is
opaque to a byte scan; and a canary list that is not maintained stops being
evidence of anything. The proxy path is tested through `inspectBody`, not over a
live socket.

---

## Claim 44 - A tool cannot take scope from the request, and its resource use is bounded and recorded (H5)

**Claim:** A tool cannot act on authority that did not come from the decision:
`params` carrying `resourceId`, `tenantId`, `capabilityId`, `principal`, or
`approvals` is refused before the tool is invoked, so scope cannot ride in the
request. Every invocation is bounded by a `ToolQuota` — params are byte-checked
*before* the call, output and duration *after* — and a breach is recorded as a
failing `tool-quota` verification and an error result, not a silent success.

**Mechanism:** `src/runtime.ts` (`AUTHORITY_PARAM_KEYS`, `ToolQuota`,
`DEFAULT_TOOL_QUOTA`, `quotaVerification`, checks inside `AgentSession.attempt`).
`ExecutionContext` still holds no issuance handle, no `AuthorizationService`,
and no principal beyond the action's own (invariant 4, unchanged).

**Threat model:** TM-001 (compromised tool/model) — a tool that reads its
authority out of the request, or that exhausts the session by returning an
unbounded payload.

**Assumptions:** the quota is configured sensibly; the operator's verification
checks cover whatever the tool claims to have done.

**Evidence:** `tests/h5-malicious-tools.test.ts` (5). The smuggling test asserts
the tool is never invoked; the params test asserts an oversized request is
refused pre-invocation; the output and duration tests assert the breach appears
as a `tool-quota` failure in the step's verifications and as an error event.

**Residual risk:** sandbox escape, kernel vulnerabilities, and side channels
remain ADR-003's residual — `LocalSandbox` is explicitly in-process with no
isolation, and containment is Stage 3 (microVM). Duration and memory are
*detected*, not enforced, because synchronous in-process code cannot be
preempted; by the time a slow tool is measured, the damage is done. A tool that
lies about what it did is caught only by the verification checks the operator
configured. Cumulative session budgets are not built.

---

## Claim 45 - The tool schema is validated, params are closed, and tool output cannot be unlabelled (H6)

**Claim:** A tool declaration is validated when it is registered: empty fields,
actions outside the vocabulary, duplicate params, and injection signals in the
description are refused, so a schema cannot carry instructions into a prompt.
When a declaration lists params, exactly those keys are accepted with their
declared types and required ones present — an undeclared key is refused before
the tool runs. An output with no declared taint is treated as `UNKNOWN_TAINT`
(untrusted, ranked at the ceiling), so no tool result can be the one unlabelled
value in the data flow.

**Mechanism:** `src/tool-protocol.ts` (`validateDeclaration`, `assertDeclaration`,
`schemaInjectionSignals`, `validateParams`, `ToolProtocolError`).
`src/runtime.ts` (`Tool.declaration`, registry-time validation, param check in
`attempt`, `UNKNOWN_TAINT` for undeclared output).

**Threat model:** TM-001 (compromised model/tool) — a schema description that
carries instructions, params that smuggle scope, output that hides its origin.

**Assumptions:** the operator writes declarations honestly; a description
scanner (the document injection detector) is a filter, not an oracle.

**Evidence:** `tests/h6-tool-protocol.test.ts` (11) — injection-in-description
refusal, registry-time refusal, undeclared/typed/required param handling with
the tool proven never invoked, undeclared output at the ceiling, and the
`ExecutionContext` key set asserted to be action-scoped only.

**Residual risk:** a tool implementation that ignores the protocol holds the
process (ADR-003 containment residual); a declaration that lies about what the
tool does; description scanning inherits the detector's false positives and
negatives.

---

## Claim 46 - An artifact is snuffed, compared to its name, and quarantined rather than served (H9)

**Claim:** Every artifact is admitted through one point that sniffs its content
from magic bytes, compares that to what the name claims, and quarantines —
without throwing — when the bytes are executable, when content and name
disagree, when the payload exceeds the store ceiling, or when it carries a
canary. Quarantined artifacts are retained as evidence and are never returned by
`released()`. Artifacts are tenant-bound: a foreign tenant id reads as missing,
and the same id in two tenants does not collide.

**Mechanism:** `src/artifacts.ts` (`sniff`, `kindFromName`, `ArtifactStore.admit`
/`get`/`list`/`released`, key `tenantId\0id`). Ceiling and canary checks reuse
`src/dlp.ts` `inspectEgress` — an artifact is egress to disk, so it goes through
the same mediator as a network payload.

**Threat model:** TM-003 (tenant isolation) and TM-002 (data injection) — an
artifact as both a smuggling container and an exfiltration channel.

**Assumptions:** the store ceiling is the operator's intended policy; the canary
list is maintained.

**Evidence:** `tests/h9-artifacts.test.ts` (8) — an ELF named `.txt` quarantined,
a PNG named `.png` containing prose quarantined, an honest artifact released
with digest and provenance, a canary body quarantined with the record proving
the value is not echoed, and both tenant-bound cases.

**Residual risk:** zero-day malware (no scanner is shipped, by design);
polyglot files pass as their first magic; a released artifact of the right kind
can still carry hostile meaning; quarantined bytes consume storage.
