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

**Mechanism:** `ExecutionContext` (`src/runtime.ts:29`) is constructed by the
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

## Claim 5 — Expired and consumed capabilities are refused

**Claim:** A capability whose expiry has passed, or whose single-use has been
consumed, fails verification and cannot authorize an action.

**Mechanism:** `verifyCapability` expiry and `usedAt` checks; `markUsed` after a
successful execution; issuance refuses an expiry in the past.

**Threat model:** TM-001 (replay), TM-003.

**Assumptions:** a monotonic clock. A clock that runs backwards extends capability life.

**Evidence:** invariant 5 tests.

**Test:** `tests/invariants.test.ts` invariant 5; `tests/capability.test.ts`
single-use case.

**Known limitations:** clock is in-process and not authenticated; no replay cache
across processes; multi-node consumption is not atomic.

**Residual risk:** clock manipulation by an operator; race in a future
distributed deployment.

---

## Claim 6 — Capabilities cannot exceed their issuer's authority

**Claim:** A non-root issuer can only mint a capability that is a subset of its own
resources, actions, classification ceiling, and expiry.

**Mechanism:** `findOverreach` attenuation check at `src/capability.ts:190`;
issuers other than the authorization root must present their own authority.

**Threat model:** TM-001, TM-003.

**Assumptions:** the root principal is trustworthy; delegation chains are short.

**Evidence:** invariant 6 tests (four cases, including a valid attenuation).

**Test:** `tests/invariants.test.ts` invariant 6.

**Known limitations:** attenuation is checked against a declared authority
object, not a cryptographically chained delegation. A capability does not yet
carry its parent's signature.

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

**Known limitations:** in-memory buffering? **None** — appends are synchronous.
But there is no write-ahead durability guarantee against a crash between the
action and the event, and no external anchoring.

**Residual risk:** log destruction by an attacker with filesystem access.

---

## Claim 8 — The audit log is tamper-evident

**Claim:** Modifying any recorded event, or breaking the hash linkage, is detected by
`EventLog.verify()`.

**Mechanism:** SHA-256 over canonical JSON of each event including the previous
event's hash (`src/events.ts:45`).

**Threat model:** TM-004.

**Assumptions:** the verifier runs against a log the attacker has not fully
rewritten with recomputed hashes.

**Evidence:** invariant 8 tests; benchmark `hashChainValid`.

**Test:** `tests/invariants.test.ts` invariant 8.

**Known limitations:** detection, not prevention. No digital signatures per
event, no external timestamping, no append-only storage. Tail truncation
(deleting the newest N events) leaves a valid chain and is not detected. An
attacker with write access can recompute the whole chain.

**Residual risk:** high for an adversary with host access. Signatures and
anchoring are VERY HARD stage items.

---

## Claim 9 — Tenants cannot reach each other

**Claim:** A principal in tenant A is denied access to any resource in tenant B,
and a capability issued in tenant A cannot be used by a tenant B principal.

**Mechanism:** `src/pdp.ts:147` tenant equality check before policy;
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
- It does not claim authentication. No user is authenticated anywhere.
- It does not claim prompt-injection *prevention*. It claims injection cannot
  create authority.
- It does not claim the event log cannot be destroyed — only that tampering with
  its contents is detectable.
- It does not claim protection against a compromised host, a malicious
  administrator, or a malicious hardware/firmware supply chain.
- It does not claim HIPAA, SOC 2, ISO 27001, or any government authorization.
  See COMPLIANCE.md.
