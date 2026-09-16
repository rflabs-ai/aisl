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
session; tools receive it and nothing else.

**Threat model:** TM-001, TM-002.

**Assumptions:** the tool does not exploit a runtime vulnerability to escape.

**Evidence:** invariant 4 test enumerates context keys and asserts none match
`issue|authoriz|secret|grant|admin`.

**Test:** `tests/invariants.test.ts` invariant 4.

**Known limitations:** `LocalSandbox` provides no isolation, so a malicious tool
runs with the runtime's privileges. This claim is about the *interface*, not
about containment.

**Residual risk:** high until a real sandbox exists (ADR-003).

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
**and** a policy rule is denied.

**Mechanism:** `NetworkGateway` synthesizes a `network-destination` resource per
host and routes the request through the PDP; the customer rule constrains hosts.

**Threat model:** TM-001, TM-002.

**Assumptions:** host normalization is correct (lowercase, trailing dot,
whitespace stripped).

**Evidence:** invariant 10 tests including normalization bypass attempts; ATK-006.

**Test:** `tests/invariants.test.ts` invariant 10.

**Known limitations:** **the gateway makes a decision and opens no socket.** It
is not yet wired to a real proxy, so a component that reaches the network by
another path is not constrained by it. DNS resolution, IP literals, redirects,
and ports other than 443 are not yet modelled.

**Residual risk:** high until a real egress proxy enforces the decision.

---

## Claim 11 — Secrets require explicit authorization

**Claim:** An agent cannot obtain a secret value unless a capability naming that
secret and a policy rule permitting `secret.use` both exist, plus any required
approval.

**Mechanism:** `SecretBroker` routes through the PDP; baseline policy contains
no `secret.use` allow rule, so the default is denial.

**Threat model:** TM-001, TM-003.

**Assumptions:** secrets registered with the broker are the only secrets; values
live in process memory.

**Evidence:** invariant 11 tests (default deny, and an explicit break-glass path
that is allowed).

**Test:** `tests/invariants.test.ts` invariant 11.

**Known limitations:** values are stored in plaintext in memory, are not
envelope-encrypted, and are not bound to a KMS/HSM. Evidence records redact
values only via `SecretBroker.redact`, which is not yet called on every path.

**Residual risk:** memory disclosure; no rotation; no audit of value use
beyond the access event.

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
