# ROADMAP

Long-horizon plan, EASY -> MEDIUM -> HARD -> VERY HARD -> IMPOSSIBLE+ -> VISION
COMPLETE. Complexity estimates are honest, not padded. Status markers: **[DONE]**,
**[NEXT]**, **[ ]**.

Classification: **MVP** (required for the MVP definition of done), **P** (post-MVP),
**E** (enterprise), **HA** (high-assurance), **R** (research).

---

## Stage 0 — EASY (conventional engineering)

Code that a competent team writes without a security research budget. Marked done
where it exists today.

| Item | Purpose | Deps | Complexity | Class | Status |
| --- | --- | --- | --- | --- | --- |
| Repository foundation | buildless TS, typecheck, tests | — | S | MVP | **[DONE]** |
| Domain model | Principal / Resource / Action / Decision | — | S | MVP | **[DONE]** |
| Policy evaluator | default-deny, deny-overrides | domain | S | MVP | **[DONE]** |
| Capability model | issue / verify / constrain / expire | domain | M | MVP | **[DONE]** |
| Event log | chained, tamper-evident | domain | S | MVP | **[DONE]** |
| PDP + PEP | one decision path, one enforcement path | policy, capability | M | MVP | **[DONE]** |
| Resource registry + classification | what exists, how sensitive | domain | S | MVP | **[DONE]** |
| Model gateway port | model is replaceable | domain | S | MVP | **[DONE]** |
| Agent session | request -> decide -> execute -> record | PDP, sandbox seam | M | MVP | **[DONE]** |
| Verification plane | post-execution checks | runtime | S | MVP | **[DONE]** |
| Network gateway (decision) | egress deny by default | PDP | S | MVP | **[DONE]** |
| Secret broker (in-memory) | secrets denied by default | PDP | S | MVP | **[DONE]** |
| Developer CLI (demo/attack/benchmark) | reproducible evidence | all | S | MVP | **[DONE]** |
| Attack harness + corpus | adversarial tests from day one | scenario | M | MVP | **[DONE]** |
| Benchmark runner | measured, not claimed | harness | S | MVP | **[DONE]** |
| Architecture / threat / claims docs | claim discipline | — | M | MVP | **[DONE]** |
| REST API surface | real clients | PDP, session | M | P | **[NEXT]** |
| Project / task / session persistence | survive restart | Postgres | M | P | **[ ]** |
| Basic document ingestion | chunk, label, classify | registry | M | P | **[ ]** |
| Basic Git integration | read-only repo access | sandbox | M | P | **[ ]** |
| Minimal UI (task + evidence view) | operator usability | REST API | M | P | **[ ]** |
| Developer setup script | `curl | bash`-free reproducible env | — | S | MVP | **[ ]** |
| Trust-boundary parser tests | model output is hostile input to a parser | model gateway | S | MVP | **[DONE]** |
| Dependency admission policy | pinning, SBOM, review gate — **before the first runtime dep** | — | S | MVP | **[DONE]** |
| Assurance targets + SLOs | per-control measurable targets (ADR-014), tracked per release | benchmark | M | MVP | **[NEXT]** |

Nothing above is inflated to look hard. It is a foundation, not a product.

---

## Stage 1 — MEDIUM (deliberate systems engineering)

| Item | Purpose | Dependencies | Complexity | Class | Status |
| --- | --- | --- | --- | --- | --- |
| Granular RBAC | roles compose with capabilities | identity | M | MVP | **[ ]** |
| Policy testing framework | unit-test rules, simulate and diff changes | policy | M | MVP | **[NEXT]** |
| Approval workflow | separation of duties as a first-class object | identity, policy | M | MVP | **[DONE]** |
| Capability request flow | agent asks, human grants, narrow | approval, PDP | M | MVP | **[DONE]** |
| Classification propagation | labels flow to derived artifacts | registry, ingestion | L | P | **[ ]** |
| Secrets brokerage (real backend) | KMS-backed, dynamic, audited | ADR-008 | L | E | **[DONE]** |
| Network egress proxy | enforce what the gateway decides | ADR-009 | L | MVP | **[DONE]** |
| Container sandbox | real isolation for tools | ADR-003 | L | MVP | **[DONE]** |
| Sandbox lifecycle management | create, limit, destroy, attest | container | M | P | **[ ]** |
| Tenant isolation hardening | RLS, per-tenant keys | Postgres | L | E | **[ ]** |
| Model provider adapters | real providers behind the port | ADR-005 | M | P | **[ ]** |
| Verification pipeline | tests, linters, SAST on agent output | verification | M | P | **[ ]** |
| Structured telemetry (OTel) | observability without ad-hoc logs | — | M | P | **[ ]** |
| Postgres schema + migrations | multi-node control plane | ADR-010 | M | P | **[ ]** |
| Audit query + export API | customers read their own evidence | events | M | MVP | **[ ]** |
| Configuration management | versioned, reviewable, attributable | policy | M | P | **[ ]** |
| Backup + restore | availability of evidence | Postgres | M | E | **[ ]** |
| Hierarchical resource matching | "all docs under project X" — prefixes/globs, not exact ids | policy | M | P | **[ ]** |
| Capability revocation | revoke a capability and have it take effect everywhere | PDP | M | MVP | **[DONE (in-process); multi-node broadcast = H13]** |

---

## Stage 2 — HARD (substantial security engineering)

Each item lists attack surface, failure modes, assumptions, test methodology, and
residual risk, as required.

### H1 — Robust capability issuance (root of trust)

- **Attack surface:** the issuance function, the signing key, the root principal.
- **Failure modes:** over-broad issuance; key theft; root used for routine work;
  issuance not attributable to a human; **delegation chains asserted by the
  caller instead of proven** (today `issuerAuthority` is a declared object — a
  caller can overstate it; ADR-002). Chained delegation must carry the parent's
  signature so attenuation is enforced cryptographically, not by convention.
- **Assumptions:** at least one honest key custodian; dual control for root.
- **Test methodology:** key ceremony drills; issuance fuzzing (every field
  extreme); attempt every attenuation bypass in the harness.
- **Residual risk:** a custodian who is coerced or malicious.
- **Class:** MVP/HA.

### H2 — Short-lived credentials and workload identity

- **Attack surface:** credential issuance, transport, storage in memory, reuse.
- **Failure modes:** leaked long-lived token; clock skew extending life; credential
  left in a crash dump or an event payload.
- **Assumptions:** NTP with authentication; secrets never enter the event log.
- **Test methodology:** expiry fuzzing; credential-in-log scanning (a test that
  fails if any event contains a known secret value); revocation propagation tests.
- **Residual risk:** window of validity; in-memory exposure.
- **Class:** E.

### H3 — Policy evaluation under adversarial conditions

- **Attack surface:** rule set, condition evaluation, input size/shape.
- **Failure modes:** catastrophic backtracking; rule-order dependence; unbounded
  evaluation time; nondeterminism across versions; rule conflict ambiguity.
- **Assumptions:** rules are finite and statically analyzable.
- **Test methodology:** determinism fuzzing; conflict detection on load;
  performance bounds as tests; versioned golden decision sets.
- **Residual risk:** policy authored incorrectly; semantics too clever.
- **Class:** MVP.

### H4 — Prompt-injection-resistant architecture (data-flow enforcement)

- **Attack surface:** every place untrusted text crosses into a decision.
- **Failure modes:** implicit trust of tool output; taint lost through
  serialization; classification lost on derived content.
- **Assumptions:** taint tracking is complete; new code paths are reviewed for it.
- **Test methodology:** taint-propagation tests; "malicious corpus end-to-end"
  runs where the expected outcome is denial or in-scope action only.
- **Residual risk:** semantic deviation inside granted scope (unavoidable).
- **Class:** MVP/HA.

### H5 — Malicious tool handling

- **Attack surface:** tool code, tool output, tool-declared capabilities.
- **Failure modes:** sandbox escape; resource exhaustion; output that lies about
  what it did; tool requesting more scope at runtime.
- **Assumptions:** the sandbox holds; quotas are enforced by the kernel/cgroup.
- **Test methodology:** known-escape corpora; resource bomb tests; output
  inconsistency checks (verification plane); scope-expansion tests.
- **Residual risk:** kernel vulnerabilities; side channels.
- **Class:** MVP.

### H6 — Secure agent-to-tool protocols

- **Attack surface:** the transport and schema between session and tool.
- **Failure modes:** injection via tool schema descriptions; parameter smuggling;
  ambient authority in the tool process.
- **Assumptions:** tools are invoked with explicit, scoped parameters only.
- **Test methodology:** schema fuzzing; parameter confusion tests; assert the tool
  process holds no credentials the capability does not imply.
- **Residual risk:** tool implementations that ignore the protocol.
- **Class:** P/E.

### H7 — Data-flow enforcement and egress DLP

- **Attack surface:** outbound bytes: network, files, artifacts, logs, model calls.
- **Failure modes:** encoding/compression bypass; slow drip below thresholds;
  exfiltration via model prompt; exfiltration via error messages.
- **Assumptions:** all egress is mediated; the model call is itself an egress.
- **Test methodology:** canary-value exfiltration suite (unique tokens per
  classification, assert none appear at any egress); encoding variants; volume
  anomaly detection.
- **Residual risk:** human-approved exfiltration; steganography.
- **Class:** E/HA.

### H8 — Cross-tenant isolation (cryptographic and physical)

- **Attack surface:** shared process, shared database, shared caches, logs.
- **Failure modes:** a query missing a tenant predicate; a cache key collision;
  one tenant's data in another tenant's logs.
- **Assumptions:** some sharing is unavoidable in SaaS.
- **Test methodology:** automated cross-tenant probe in CI (every endpoint, every
  query); per-tenant key separation tests; log-scrubbing tests.
- **Residual risk:** hardware-level side channels; hypervisor bugs.
- **Class:** E/HA.

### H9 — Secure artifact handling

- **Attack surface:** files produced by agents, uploads, model artifacts.
- **Failure modes:** executing untrusted artifacts; storing malware; serving
  attacker-controlled content to other tenants; artifact as exfiltration channel.
- **Assumptions:** artifacts are untrusted until verified.
- **Test methodology:** type confusion tests; content/extension mismatch;
  scanning and quarantine workflow; artifact provenance assertions.
- **Residual risk:** zero-day malware; polyglot files.
- **Class:** P/E.

### H10 — Signed builds and supply-chain security

- **Attack surface:** dependencies, build pipeline, registry, developer laptops.
- **Failure modes:** malicious dependency; compromised CI; unsigned artifact
  deployed; lockfile drift.
- **Assumptions:** at least two maintainers; CI is isolated from dev credentials.
- **Test methodology:** SBOM generation and diff on every build; pinning with
  hash verification; provenance attestation (SLSA-style) verified at deploy;
  dependency update review gate.
- **Residual risk:** a trusted maintainer going rogue; compiler-level attacks.
- **Class:** E/HA.

### H11 — Tamper-evident evidence (signatures, anchoring, retention)

- **Attack surface:** the event store, the verifier, the anchor.
- **Failure modes:** whole-log rewrite; anchor collusion; clock manipulation;
  selective deletion.
- **Assumptions:** at least one append-only store the runtime cannot rewrite.
- **Test methodology:** anchor consistency checks; verifier against
  adversarially rewritten logs; retention and legal-hold tests.
- **Residual risk:** an attacker who controls both the log and the anchor.
- **Class:** HA.

### H12 — Secure updates

- **Attack surface:** update channel, signing keys, rollback behaviour.
- **Failure modes:** rollback to a vulnerable version; unsigned update; update
  as remote code execution with high privilege.
- **Assumptions:** versioned, signed, staged rollout; emergency rollback exists.
- **Test methodology:** signature verification tests; rollback prevention tests;
  staged rollout with automated canary and auto-halt.
- **Residual risk:** a signed but malicious release.
- **Class:** E/HA.

### H13 — Incident response mechanisms

- **Attack surface:** everything, under the assumption of an active incident.
- **Failure modes:** cannot revoke a session or a capability quickly; cannot
  freeze issuance; cannot reconstruct what happened; cannot preserve evidence.
- **Assumptions:** an on-call human exists and can act.
- **Test methodology:** game days measuring kill-switch latency, **capability
  revocation propagation (target <= 5 s)**, and evidence export completeness.
- **Residual risk:** incident response is slower than the attack.
- **Class:** MVP/E.

### H14 — Adversarial evaluation harness (continuous)

- **Attack surface:** the platform as a whole, tested continuously.
- **Failure modes:** corpus drift; tests that assert the wrong thing; coverage
  gaps mistaken for safety.
- **Assumptions:** attacks can be enumerated faster than they are invented (false,
  but useful).
- **Test methodology:** nightly corpus run; mutation testing on policy;
  differential runs across versions; external red team at defined intervals.
- **Residual risk:** unknown-unknown attacks.
- **Class:** MVP/HA.

### H15 — Fail-closed availability engineering

- **Attack surface:** the failure modes of the safety mechanisms themselves.
- **Failure modes:** a broken policy engine, a full disk, or a closed evidence
  store denies **everything, silently, per decision**. There is no health
  signal, no degraded mode, no budget, and no alerting. Fail-closed is correct
  and currently incompressible: one fault stops all legitimate work with no
  operator-visible difference from an attack.
- **Assumptions:** fail-closed stays the default; degradation must never widen
  authority.
- **Test methodology:** fault injection for each dependency (engine throws,
  store unwritable, clock stalled); assert deny + a distinct `denyReason` +
  an emitted health signal; measure decision latency p99 with and without
  persistence; define and test the degraded mode explicitly.
- **Residual risk:** an adversary who can induce the failure gets a denial of
  service. That is the accepted trade; make it loud, bounded, and recoverable.
- **Class:** MVP/E.

---

## Stage 3 — VERY HARD (high-assurance engineering)

Not MVP. Listed so the architecture is never painted into a corner.

| Item | What it buys | Prerequisite | Class |
| --- | --- | --- | --- |
| microVM isolation (Firecracker-class) | per-session kernel, no shared host kernel | container sandbox | HA |
| Hardware-backed key management (HSM/TPM) | keys that cannot be exfiltrated by software | secret backend | HA |
| Cryptographic attestation | prove what binary is running before it gets a key | measured boot, TPM | HA |
| Trusted execution (where justified) | memory encryption; narrow use, stated limits | threat model review | HA/R |
| Secure/measured boot | host integrity before workload start | hardware | HA |
| Reproducible builds | independent verification of shipped binaries | build pipeline | HA |
| Controlled update channels | air-gap-compatible, reviewed, signed | signed builds | HA |
| Network segmentation / enclaves | blast-radius containment | deployment model | E/HA |
| Offline deployment | no external dependency at runtime | packaging | E |
| Air-gapped deployment | controlled transfer of software and models | offline + bundle signing | HA |
| Customer-controlled keys (BYOK/HYOK) | vendor cannot read customer data | KMS integration | E/HA |
| Customer-controlled inference | data never leaves the customer boundary | model adapters, local models | E/HA |
| Multi-domain security architecture | formally distinct sensitivity domains | classification, DLP | HA |
| Cross-domain transfer controls | explicit, reviewed, logged downgrade/upgrades | multi-domain | HA/R |
| Formalized security invariants | machine-checked model of the PDP | stable semantics | HA/R |
| Continuous adversarial testing | standing red team, not a one-off | harness | HA |
| Sophisticated exfiltration resistance | volume, timing, and semantic controls | DLP, egress proxy | HA/R |
| Advanced provenance | content-level lineage for every derived artifact | taint tracking | HA |
| Disaster recovery with evidence continuity | rebuild without losing the chain | anchoring, backups | E/HA |
| High-assurance operational procedures | dual control, access reviews, drills | everything above | HA |

---

## IMPOSSIBLE+

Requirements that cannot be honestly guaranteed by software, or that depend on
assumptions outside our control. Documented so they never become marketing copy.

| Requirement | Why it cannot be guaranteed | Engineering approximation | Assumption required | Measuring / reducing residual risk |
| --- | --- | --- | --- | --- |
| Zero compromise in arbitrary environments | an environment we do not control can be hostile at any layer | reduce the probability and the blast radius; assume breach | the deployment environment is within spec | red-team findings over time; time-to-detect metrics |
| No future unknown vulnerability exists | vulnerabilities are unknown by definition | minimize code and dependencies; rapid patch pipeline; sandboxing | honest disclosure reaches us | dependency freshness; SBOM diffing; time-to-patch SLAs |
| A trusted human will never intentionally leak | humans have agency; software cannot stop a screenshot | least privilege, dual control, detection, offboarding | background checks, legal controls, training | anomaly detection on access patterns; access reviews |
| Physical security without controlling the physical environment | we do not own the datacenter or the laptop | full-disk encryption, tamper evidence, remote wipe | the customer's physical controls are real | customer attestation; device compliance checks |
| Security if the underlying hardware is malicious | we do not fabricate silicon | trusted supply chain, attestation, diversity of hardware | hardware provenance | hardware attestation; spot checks; supplier audits |
| Security if all administrators are compromised | admins hold the keys by definition | split knowledge, dual control, external anchoring, break-glass audit | at least one admin remains honest | cross-checks against externally anchored logs |
| Perfect semantic understanding by arbitrary models | no model has it | constrain authority so semantics cannot cause catastrophe | none | benchmark task-deviation rate; human review of sensitive actions |
| Zero hallucinations | generative models hallucinate by construction | verification plane; require evidence for consequential claims | none | verification pass rate; false-claim rate on benchmark tasks |
| Every possible future attack is prevented | the space of attacks is open-ended | defense in depth; fast detection and recovery | none | continuous red teaming; corpus growth rate vs. novel-attack rate |
| Absolute confidentiality against a compromised model provider | we do not run their hardware | don't send data there: customer-hosted or local inference | provider contract and telemetry | data-flow audits; egress canaries |
| Mathematical proof that the whole system is secure | the system is too large and changes too often | prove the small, stable core (the PDP) formally | the rest of the system is correctly modelled | scope the proof explicitly; never overclaim its coverage |

---

## Assurance targets (ADR-014)

**North star:** 99.9996%. It is a reminder of the direction and of how this
ends — build every control we know how to build, then stop and let independent
verifiers tell us where we are wrong. It is not a published property of the
system, and no single percentage can be: see ADR-014 and the defect bar in
SECURITY_PRINCIPLES.md. Obvious flaws — the kind that exist only because the
code was written wrong — are defects, not tradeoffs, and are never recorded as
accepted risk.

There is no single number for "how secure is this". A percentage like 99.9996%
(≈3.4 failures per million) cannot be computed for a system, defended to an
auditor, or falsified by a test — publishing one would violate this project's
own rule that every claim binds to a property, a mechanism, and a test. What we
publish instead is one target per control, each with a measurement.

| # | Property | Target | Measured by | Today |
|---|---|---|---|---|
| 1 | Unauthorized action denial | 100% of corpus requests | `unauthorizedActionDenialRate` | 20/20 |
| 2 | Cross-tenant denial | 100% | invariant 9, ATK-003 | 3/3 |
| 3 | Injection becoming authority | 0 successes | `promptInjectionSuccesses` | 0/4 |
| 4 | Decision audit completeness | 100% | `auditCompleteness` | 22/22 |
| 5 | Evidence chain integrity | valid on every run | `hashChainValid` | true |
| 6 | Secret values at rest in the store | 0 occurrences | store scan | 0 |
| 7 | False denial of legitimate work | <= 1% | `falseDenialRate` | 0/2 (corpus far too small to mean it) |
| 8 | Capability revocation propagation | <= 5 s | in-process revoke + immediate next-decision deny | immediate (in-process); multi-node = H13 |
| 9 | Decision latency p99 | <= 10 ms | not measured | — |
| 10 | Recovery from evidence-store failure | defined degraded mode | not implemented | denies everything silently |
| 11 | Independence of the security core from any single model | structural, by construction | model swap test | met |
| 12 | Unknown future vulnerability | **not measurable** | IMPOSSIBLE+ | — |
| **13** | **Unauthenticated principals reaching the PDP** | **0** | **invariant 13** | **0** |
| **14** | **Approvals with verified MFA** | **100%** | **invariant 13, MFA check** | **100%** |
| **15** | **Approval replay acceptance** | **0** | **single-use + expiry** | **0** |
| **16** | **Session revocation propagation** | **<= 5 s** | **SessionManager.revoke** | **immediate (in-memory)** |

Read row 1 honestly: 15/15 on a corpus written by the same person who wrote the
code is not evidence of a 10^-6 failure rate. Reaching a defensible
high-assurance number requires roughly: 10^5–10^6 automated adversarial trials
with a corpus authored by someone other than the implementer, an independent
red team, formal verification of the decision core (H-stage), and continuous
adversarial testing in production-like conditions. Until those exist, the
defensible statement is "these controls hold on this corpus", not a percentage.

---

## VISION COMPLETE

Any approved model — cloud, private, local, open-weight, customer-hosted —
plugged into a runtime whose security boundary does not move when the model
changes.

```text
        ANY APPROVED MODEL
                |
                v
        HIGH-ASSURANCE AGENT RUNTIME
        (identity, policy, capabilities)
                |
       +--------+--------+
       |        |        |
     CODE     DATA     SYSTEMS
       |        |        |
       +--------+--------+
                |
         VERIFICATION
                |
            EVIDENCE
```

Capability checklist for "complete": SaaS, customer-VPC, private cloud, on-prem,
offline, and air-gapped deployments; enterprise identity with MFA; granular
authorization; capability-based execution; sensitivity-aware domains with
explicit cross-domain transfer; hardened compute isolation; data and network
gateways; secrets brokerage; human approval; automated verification;
cryptographically verifiable evidence; continuous adversarial testing; signed
updates; disaster recovery; and documented operational procedures.

It still will not be a SCIF. Software does not create a SCIF; people, physical
controls, and accreditation do. The platform's job is to make the software part
of that equation defensible and testable.

---

## Next milestones (full format)

### M0 — Architectural foundation (done)

- **Purpose:** establish the authority boundary and prove it with tests.
- **Why it matters:** everything else is built on "the model cannot grant itself
  authority". If that is false, nothing above it is true.
- **Dependencies:** none.
- **Complexity:** M (done in one session).
- **Security significance:** defines invariants 1–12.
- **What becomes possible:** adversarial testing of a real enforcement path.
- **Acceptance criteria:** 70 tests green; 10/10 attack cases behave as required;
  demo walkthrough completes; `benchmarks/results.json` produced by a run.
- **Threats introduced:** none at runtime; the illusion of completeness.
- **Threats mitigated:** injection-as-authority, unauthorized access, cross-tenant
  reads, secret reads, egress, destructive actions, missing audit.
- **Tests required:** `tests/`, `security-tests/`, `security-attacks/`.
- **Evidence produced:** test output, demo output, benchmark JSON, this doc set.

### M1 — Real enforcement boundaries (done)

- **Purpose:** replace the three stubs that decide but do not enforce: sandbox,
  network, secrets.
- **Why it matters:** a decision with no enforcement behind it is a log entry.
- **Dependencies:** M0, container runtime, an egress proxy, a secret backend.
- **Complexity:** L.
- **Security significance:** converts claims 4, 10, 11 from interface-level to
  containment-level.
- **What becomes possible:** running untrusted tool code at all.
- **Acceptance criteria:** tool execution happens inside a container with no
  network except the proxy; the proxy denies everything not allowlisted; secrets
  are never present in the sandbox; the existing attack corpus still passes.
- **Evidence rule:** output is always sealed with a per-classification key and
  always digestable; content is readable only with an `evidence.decrypt`
  capability for that level, and the read is audited. The evidence store must
  **not** be mounted into the sandbox — an escape must not hand over the audit
  trail. The sealing master key must not live on the same host as the store.
- **Threats introduced:** container escape surface, proxy bypass, secret leakage
  into the sandbox, new operational complexity.
- **Threats mitigated:** malicious tool code, direct-socket exfiltration,
  in-process secret access.
- **Tests required:** escape corpus, egress canaries, secret-in-sandbox probes.
- **Evidence produced:** sandbox configuration, proxy logs, corpus results.

### M2 — Identity and approvals (done)

- **Purpose:** real humans, real authentication, real separation of duties.
- **Why it matters:** today a principal is a struct; approvals are objects with no
  authenticated author behind them.
- **Dependencies:** M0, an OIDC provider, MFA enforcement.
- **Complexity:** L.
- **Security significance:** makes attribution and separation of duties real.
- **What becomes possible:** trustworthy approval records, per-human audit.
- **Acceptance criteria:** no path to a Principal without authentication; MFA
  enforced for approval actions; approvals attributable and non-repudiable.
- **Threats introduced:** IdP dependency, session handling, token theft.
- **Threats mitigated:** impersonation, unattributable approvals.
- **Tests required:** authn bypass suite, session fixation/replay, MFA enforcement.
- **Evidence produced:** authentication events in the chain, approval records.

### M3 — Evidence hardening **[DONE]**

- **Purpose:** make evidence survive an attacker who controls the host.
- **Why it matters:** today the chain detects editing but not rewrite or deletion.
- **Dependencies:** M0, external anchor, key management.
- **Complexity:** L.
- **Security significance:** upgrades Claim 8 from detection to durability.
- **What becomes possible:** evidence a customer or auditor can verify independently.
- **Acceptance criteria:** per-event signatures; head hash anchored externally on
  a schedule; append-only storage; verifier runs offline against an export.
- **Threats introduced:** anchor dependency, key management complexity.
- **Threats mitigated:** log rewrite, selective deletion, repudiation.
- **Tests required:** rewrite detection, anchor reconciliation, offline verify.
- **Evidence produced:** signed bundles, anchor receipts.

Implementation: per-event Ed25519 signatures, append-only SQLite
(`BEFORE UPDATE/DELETE` triggers), head-hash anchor file (one line per append:
`<seq>:<eventHash>`), and a standalone `verifyBundle()` that operates on the
exported bundle without database access. The EventLog class exposes only
`append`, `all`, `forTenant`, `verify`, `bundle`, `anchor`, and `close` — a
structural test asserts the absence of `update()` / `delete()`. The 13 M3
tests cover tamper, tail truncation, anchor reconciliation, offline
verification, signature forgery, and the structural API check. Residual risk
remains (anchor rewrite by an attacker with host access) — see Claim 8 and
ADR-004.
