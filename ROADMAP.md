# ROADMAP

Long-horizon plan, EASY -> MEDIUM -> HARD -> VERY HARD -> IMPOSSIBLE+ -> VISION
COMPLETE. Complexity estimates are honest, not padded. Status markers: **[DONE]**,
**[NEXT]**, **[ ]**.

Classification: **MVP** (required for the MVP definition of done), **P** (post-MVP),
**E** (enterprise), **HA** (high-assurance), **R** (research).

---

## Vision

Build the **AI Operating System for Sensitive Organizations** — a high-assurance
agent runtime that lets an organization deploy capable AI against information it
currently cannot safely give to AI. The promise is not "our AI won't leak your
data"; it is:

> AI actions are constrained by enforceable policy, executed inside controlled
> environments, and accompanied by evidence.

The design target is defense-in-depth in the spirit of intelligence-community
SOC/SCIF environments, aimed at a **99.99996% (≈0.4 defects per million)**
reliability bar — a north star, never a published claim (ADR-014). The distilled
end state is [VISION COMPLETE](#vision-complete), below. The full original brief
— the product framing, the value proposition, and the honest "software does not
create a SCIF" caveat — lives in `initial-idea-CONTEXT.md` (§36 onward), which
is the source this roadmap distills.

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
| REST API surface | real clients | PDP, session | M | P | **[DONE]** (M14: ADR-019 — `node:http` whitelist router, zero new runtime dependencies; bearer-JWT authn over `IdentityProvider.verifyToken` + registered-principal resolver, tenant derived from the verified principal only, whitelist body/response parsing with size cap, fail-closed mapping, `GET /healthz` (H15); endpoints: authorize, sessions, capability-requests, audit, tasks — every endpoint routes through the one existing decision path; `src/rest-api.ts` + `src/rest-sessions.ts` + `src/rest-audit.ts`) |
| Project / task / session persistence | survive restart | Postgres | M | P | **[DONE]** (M12: `src/persistence.ts` — RLS'd `projects`/`tasks`/`agent_sessions` tables + tenant-bound CRUD API, upserted resumable session state; roundtrip + restart tests live) |
| Basic document ingestion | chunk, label, classify | registry | M | P | **[DONE]** (M15: ADR-020 — `src/ingestion.ts`: deterministic boundary-aware chunker (no model in the loop), chunk ids `doc/<id>/chunk/<n>`, every chunk a registry resource with the source id as `derivedFrom`, labels through the M11 machinery (max-by-rank, raise-only re-ingest), one `document.ingest` event per chunk with content sealed per tenant key — no plaintext in events; Claim 29) |
| Basic Git integration | read-only repo access | sandbox | M | P | **[DONE]** (M15: ADR-020 — `src/git-reader.ts`: verbs allowlisted at config time to `log`/`show`/`diff`/`status` (write/network verbs refused at construction), argv exec with no shell (CommandCheck posture), traversal/escape-hatch args refused before spawn, output flows through the ingestion path labeled with the repo's classification; Claim 30) |
| Minimal UI (task + evidence view) | operator usability | REST API | M | P | **[DONE]** (M15: ADR-020 — `tools/ui/index.html` static page served by the M14 server via exact-route `staticPages` (no directory serving, traversal nonexistent by construction), zero dependencies, vanilla `fetch` against `POST /v1/tasks` + `GET /v1/audit`, bearer JWT typed at runtime, no canary/secret/URL in served pages (secret-scan test), accessibility basics (semantic HTML, labeled inputs, keyboard-native controls); no new authorization surface) |
| Developer setup script | `curl | bash`-free reproducible env | — | S | MVP | **[DONE]** (M15: ADR-020 — `scripts/setup.ps1` + `scripts/setup.sh`: Node/git/npm checks, `npm install` + typecheck + tests, fail-closed nonzero exit on any failed check, offline (no remote fetches — pattern-scanned by test), optional Postgres-16 container bootstrap matching DEPLOYMENT.md) |
| Trust-boundary parser tests | model output is hostile input to a parser | model gateway | S | MVP | **[DONE]** |
| Dependency admission policy | pinning, SBOM, review gate — **before the first runtime dep** | — | S | MVP | **[DONE]** |
| Assurance targets + SLOs | per-control measurable targets (ADR-014), tracked per release | benchmark | M | MVP | **[DONE]** (M10: "Assurance targets" table below implemented as a gated `slo` block in `benchmarks/results.json`; `npm run benchmark` exits nonzero on a hard miss; `falseClaimRate` widened to 100 honest sessions) |

Nothing above is inflated to look hard. It is a foundation, not a product.

---

## Stage 1 — MEDIUM (deliberate systems engineering)

| Item | Purpose | Dependencies | Complexity | Class | Status |
| --- | --- | --- | --- | --- | --- |
| Granular RBAC | roles compose with capabilities | identity | M | MVP | **[DONE]** (M11: `Role` as data + `BASELINE_ROLES`, `AuthorizationService.issueForRole` role-templated issuance, `createPolicyEngine` cross-validates role-referencing allow rules at construction; Claim 24) |
| Policy testing framework | unit-test rules, simulate and diff changes | policy | M | MVP | **[DONE]** (M7: `src/policy-testing.ts`, JSON fixtures, `npm run policy:diff`; Claim 22) |
| Approval workflow | separation of duties as a first-class object | identity, policy | M | MVP | **[DONE]** |
| Capability request flow | agent asks, human grants, narrow | approval, PDP | M | MVP | **[DONE]** |
| Classification propagation | labels flow to derived artifacts | registry, ingestion | L | P | **[DONE]** (M11: `propagateClassification` + raise-only `raiseClassification`, write path lifts labels, events seal under `evidence-key:<derived>`; Claim 25) |
| Secrets brokerage (real backend) | KMS-backed, dynamic, audited | ADR-008 | L | E | **[DONE]** |
| Network egress proxy | enforce what the gateway decides | ADR-009 | L | MVP | **[DONE]** |
| Container sandbox | real isolation for tools | ADR-003 | L | MVP | **[DONE]** |
| Sandbox lifecycle management | create, limit, destroy, attest | container | M | P | **[DONE]** (M16: ADR-021 — `src/sandbox-registry.ts`: tenant-namespaced ids (`sandbox:<tenant>:<name>`) registered as `'system'` resources with the registry as the tenant authority (every lifecycle call re-checks the binding); sealed `sandbox.create`/`sandbox.destroy`/`sandbox.attest` events via `sealFor` + a SHA-256 limit-config digest — plaintext events carry only digest + keyId; `sandbox.execute` gated by the ordinary PDP path on a capability scoped to the sandbox resource id; limits ARE `ContainerSandboxOptions` with effective-vs-declared attested from one defaults source; idempotent destroy, no orphan on failed create, opt-in process-exit sweep; Claim 31) |
| Tenant isolation hardening | RLS, per-tenant keys | Postgres | L | E | **[DONE]** (M12: `FORCE RLS` + deny-by-default per-role policies on the control-plane tables — `app_reader` tenant-scoped, hostile queries read zero rows (live-DB tested, superuser not the proof); per-tenant evidence keys `evidence-key:v2:<tenant>:<level>`, no silent re-encryption; Postgres mode only — SQLite mode stays app-level; Claim 9) |
| Model provider adapters | real providers behind the port | ADR-005 | M | P | **[DONE]** (M13: `src/model-http.ts` — OpenAI-compatible `HttpModelAdapter` over injectable `fetch` with retry/backoff/timeout, output always through `parseModelOutput`; classification egress gate is default-deny and not bypassable; Claim 27) |
| Verification pipeline | tests, linters, SAST on agent output | verification | M | P | **[DONE]** (M13: `src/check-command.ts` — `CommandCheck`, argv-array exec with no shell, config-time allowlist refusal, artifact via stdin only, minimal env, timeout → fail; flows through `runVerifications`, no new authority) |
| Structured telemetry (OTel) | observability without ad-hoc logs | — | M | P | **[DONE]** (M13: `src/telemetry.ts` — `TelemetryPort` + `JsonlTelemetry`, zero-dep JSONL; emission failures swallowed and counted; `session.start/end` + `pdp.denyReasons` wiring; the PDP never reads it (Claim 28). OTel SDK adapter behind the same port when a collector exists — ADR-gated dependency) |
| Postgres schema + migrations | multi-node control plane | ADR-010 | M | P | **[DONE]** (M12: ADR-018 — `postgres@3.4.9` zero-transitive-dep driver, `EventStore` port over `EventLog` (SQLite default) and `PostgresEventLog` (`src/event-store-pg.ts`), forward-only hash-recorded migrations (ids 1–3) with tamper refusal, opt-in via `EVENT_STORE=postgres` + `DATABASE_URL`, fail-closed `store-unavailable` denyReason) |
| Audit query + export API | customers read their own evidence | events | M | MVP | **[DONE]** (M6: authorized, tenant-scoped, offline verifyBundle, Claim 21) |
| Configuration management | versioned, reviewable, attributable | policy | M | P | **[DONE]** (M11: `PolicyBundle`/`RoleBundle`, sha256 over `canonicalJson({version, rules|roles})` verified fail-closed, one `policy.load` event per load, `policy:diff` verifies versioned overlays; the review gate is git; Claim 26) |
| Backup + restore | availability of evidence | Postgres | M | E | **[DONE]** (M12: `tools/backup.ps1` — plain-SQL `pg_dump` (host pg_dump preferred, docker fallback), restore rehearsed in a test: restored chain `verify()` + signature check + `verifyBundle()` + persistence row parity all pass live) |
| Hierarchical resource matching | "all docs under project X" — prefixes/globs, not exact ids | policy | M | P | **[DONE]** |
| Capability revocation | revoke a capability and have it take effect everywhere | PDP | M | MVP | **[DONE (in-process); multi-node broadcast = H13]** |
| Output reliability layer | guard the text channel: evidence-bound claims, guardrails, fallback | verification, events | M | P | **[DONE]** (M7/M8: `src/guard.ts` D2–D5, ladder, sealed originals, Claim 23; M9: Escalate wired to M4, classification derived per session, second-pass guard) |

Planned milestone prompts (parallelization map lives in the M10 prompt and is
restated in each): `PROMPTS/M10-assurance-targets-and-slos.md` (the row above —
**done**; it set the SLO baseline every later milestone must not regress),
`PROMPTS/M11-authz-depth.md` (Granular RBAC, Classification
propagation, Configuration management — **done**; A/B subagents ran in
parallel on disjoint surfaces, C consumed A's role surface),
`PROMPTS/M13-runtime-realism.md` (model provider adapters, verification
pipeline, structured telemetry — **done**; ran concurrently with M11 on
disjoint module surfaces, zero new runtime dependencies),
`PROMPTS/M12-platform-shift.md`
(Postgres ADR-018 + schema/migrations + tenant isolation + backup/restore —
**[DONE]**; Phase 0: ADR-018 (driver `postgres.js` pinned as `postgres@3.4.9`,
schema, two-role RLS model, per-tenant key derivation, fail-closed
`store-unavailable`); Phase 1: `EventStore` port + `PostgresEventLog` +
migrations framework; Phase 2: B (RLS policies + per-tenant keys) ∥ C
(backup/restore + persistence) ran in parallel on disjoint surfaces. All
verified against a live Postgres container; SQLite default unchanged).
M10 ran first — it set the SLO baseline every later milestone must not regress.

Scoping for Stage 0's finish line: `PROMPTS/M14-rest-api.md`
(ADR-019 — the HTTP transport as a new trust boundary, `node:http` zero-dep,
authn/tenant/whitelist contracts, authorize + sessions + capability
requests + audit + tasks + healthz) then `PROMPTS/M15-stage0-cleanup.md`
(ADR-020 — document ingestion ∥ Git read-only, the M12 capability-request
API seam, setup script, minimal UI served by the M14 server). Both landed —
**Stage 0 is fully [DONE]**. `PROMPTS/M16-sandbox-lifecycle.md` (ADR-021 —
sandbox lifecycle: create, limit, destroy, attest) closed the last Stage 1
row. `PROMPTS/M17-federation-control-plane.md` (ADR-022 — control-plane as
the first federation client) runs parallel to Stage 2 H1; M18–M20 prompts
are written just-in-time per the M4–M16 convention.

---

## Stage 2 — HARD (substantial security engineering)

Each item lists attack surface, failure modes, assumptions, test methodology, and
residual risk, as required. All fifteen items are open **[ ]** (none started).
Status markers apply: **[DONE]** / **[NEXT]** / **[ ]**.

- **Working order** (pick list, AGENT-SESSION SESSION 19): ~~H1 [NEXT]~~
  **H1 [DONE]** (ADR-023) — it was the root of trust for everything above it.
  Next: H10, H12, H13, H15. **M17 (federation, ADR-022) runs as a parallel
  track** — disjoint surfaces; its dispatch phase uses the human-gated M4
  flow. The remaining ten (H2–H9, H11, H14) stay open [ ] until prioritized
  after those four clear.

### H1 — Robust capability issuance (root of trust) **[DONE]** (ADR-023)

- **Attack surface:** the issuance function, the signing key, the root principal.
- **Failure modes:** over-broad issuance; key theft; root used for routine work;
  issuance not attributable to a human; **delegation chains asserted by the
  caller instead of proven** (was: `issuerAuthority` was a declared object —
  any caller could overstate it; closed by ADR-023). Chained delegation carries
  the parent's signature so attenuation is enforced cryptographically, not by
  convention.
- **Assumptions:** at least one honest key custodian; dual control for root.
- **Test methodology:** key ceremony drills; issuance fuzzing (every field
  extreme); attempt every attenuation bypass in the harness.
- **Residual risk:** a custodian who is coerced or malicious.
- **Class:** MVP/HA.
- **Closed:** ADR-023 — the fourth parameter of `issueCapability` is the
  issuer's own signed capability (`parent`); authority is derived, never
  declared; the chain link is recorded (`provenance.delegatedFrom`) and
  tamper-evident; service-level custody refuses revoked/unregistered parents
  and audits each refusal. The session audit closed the remaining bypasses the
  same day: the subset check covers ALL six dimensions (constraints subset —
  narrowing legitimate; single-use parents are leaf authorities) and parent
  validity runs for the root too. 32 H1 tests
  (`tests/h1-signed-delegation.test.ts` + rewritten invariant 6). Residual:
  symmetric key (known-gap #4), no depth limit (cycles cannot escalate).

### H2 — Short-lived credentials and workload identity — *structurally necessary at federation (ADR-022)*

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

### H8 — Cross-tenant isolation (cryptographic and physical) — *structurally necessary at federation (ADR-022)*

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

### H13 — Incident response mechanisms — *structurally necessary at federation (ADR-022)*

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

## Federation integration milestones (ADR-022)

ASL is the single enforcement plane for five sibling repos; **no code merges**;
integration exclusively via the M14 REST seam, one client at a time. Full
reasoning in `DECISIONS.md` ADR-022; each row carries the structural
rationale (why the client's own core promise requires it).

| Milestone | Client | Why structurally necessary | Gate | Status |
| --- | --- | --- | --- | --- |
| M17 | control-plane | its "external verification decides" thesis rests on a writable JSONL log with zero sandboxing — anchoring + capability-gated dispatch close H11/H13 exposure without changing its semantics | none unshipped (M4 flow + M14 API + M16 sandbox all landed) | **[ ]** |
| M18 | project-raven | self-building always-on agent: unsigned self-update is RCE by design (H10/H12); static device key (H2); unattended fail-closed (H13/H15) | H10/H12 partially | **[ ]** |
| M19 | home-agent | web→model→shell injection path (H4); unclassifiable personal-data egress (H7); LSM memory tamper-evidence (H11) | M13 machinery exists | **[ ]** |
| M20 | engineering-OS | retire its regex-gated evidence log into ASL's signed EventLog — two evidence planes is the failure mode to avoid | M17 anchor pattern | **[ ]** |

creative-os integrates nothing: it holds the human Decision records that gate
dispatch (SUGGESTION != CANON) and reads audit through the ordinary client
path. Its capture-and-refinement surface is the reason the stack exists, not
a component that needs enforcement.

The federation itself pulls H8 (cross-tenant), H2, and H13 forward — those
three are annotated above. Gate: before any non-personal tenant joins, H8
must close or its residual be explicitly accepted per deployment.

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

**North star:** 99.99996% (≈0.4 defects per million). It is a reminder of the
direction and of how this
ends — build every control we know how to build, then stop and let independent
verifiers tell us where we are wrong. It is not a published property of the
system, and no single percentage can be: see ADR-014 and the defect bar in
SECURITY_PRINCIPLES.md. Obvious flaws — the kind that exist only because the
code was written wrong — are defects, not tradeoffs, and are never recorded as
accepted risk.

There is no single number for "how secure is this". A percentage like 99.99996%
(≈0.4 defects per million) cannot be computed for a system, defended to an
auditor, or falsified by a test — publishing one would violate this project's
own rule that every claim binds to a property, a mechanism, and a test. What we
publish instead is one target per control, each with a measurement.

One measurable target per control, evaluated on every `npm run benchmark` run:
results land in `benchmarks/results.json` under `metrics.slo` —
`{ pass, hardFailures, targets: [{ id, metric, target, measured, gate, pass }] }`
— and the benchmark **exits nonzero** when any `hard` target misses. The
implemented catalog lives in `src/slo.ts` (`SLO_TARGETS`) and matches this table
exactly (`tests/slo.test.ts` pins the ids). Latency is **reported, not gated** —
a noisy CI machine must not fail the build.

| Control | Metric (exact benchmark key) | Target | Gate |
|---|---|---|---|
| Unauthorized adversarial action denial | `adversarial.unauthorizedActionDenialRate` | = 1 | hard |
| Attack corpus behaves as required | `adversarial.corpusPassRate` | = 1 | hard |
| Cross-tenant denial (ATK-003, within the corpus) | `adversarial.corpusPassRate` | = 1 | hard |
| Prompt-injection-driven request granted | `adversarial.promptInjectionSuccesses` | = 0 | hard |
| Legitimate task success | `legitimate.legitimateTaskSuccessRate` | = 1 | hard |
| False denial of legitimate work | `legitimate.falseDenialRate` | ≤ 0.01 | hard |
| Decision audit completeness | `evidence.auditCompleteness` | = 1 | hard |
| Evidence chain integrity | `evidence.hashChainValid` | = true | hard |
| False claim on honest output | `evidence.falseClaimRate` | ≤ 0.01 | hard |
| Guard-corpus floor (denominator credibility) | `evidence.totalLegitimateResponses` | ≥ 100 | hard |
| Audit query latency p99 | `evidence.auditQueryLatencyP99Ms` | reported | advisory |
| Audit export latency p99 | `evidence.auditExportLatencyP99Ms` | reported | advisory |
| Policy diff latency | `evidence.policyDiffLatencyMs` | reported | advisory |
| Guard latency p99 | `evidence.guardLatencyP99Ms` | reported | advisory |

`hard` = `npm run benchmark` exits nonzero on miss; `advisory` = reported every
run, never gates. Every rate carries its denominator in the same JSON
(`adversarial.cases`, `adversarial.requests`, `legitimate.requests`,
`evidence.expectedDecisions`, `evidence.totalLegitimateResponses`) — no
percentage without a denominator, no composite score (ADR-014). The
`falseClaimRate` denominator is the legitimate-fixture guard verdicts plus the
100-session honest R1 corpus (`evidence.honestCorpusSessions`); its ≤ 0.01
target is the documented false-denial budget, not an inverted measurement.

Gated by the test suite (`npm test`), not the benchmark — same bar, different
harness:

- Unauthenticated principals reaching the PDP: 0 (invariant 13).
- Approvals with verified MFA: 100% (invariant 13, MFA check).
- Approval replay acceptance: 0 (single-use + expiry).
- Secret values at rest in the store: 0 occurrences (sealing tests scan the store).
- Model independence of the security core: structural, by construction (model swap test).
- Capability revocation propagation: ≤ 5 s — immediate in-process (M4 tests); multi-node broadcast = H13.
- Session revocation propagation: ≤ 5 s — immediate in-memory (SessionManager tests).

Not yet measured (named so the gap cannot hide; ADR-014's honesty rule):

- Decision latency p99 ≤ 10 ms — the benchmark measures component latencies
  (advisory, above), not the end-to-end decision path.
- Degraded mode for evidence-store failure — not implemented (H15); today a
  store failure denies everything silently.
- Unknown future vulnerabilities — not measurable (IMPOSSIBLE+); reduced by
  corpus growth, red teaming, and dependency freshness, never claimed as zero.

Read the first row honestly: 20/20 adversarial requests denied on a corpus
written by the same person who wrote the code is not evidence of a 10^-6
failure rate. Reaching a defensible high-assurance number requires roughly:
10^5–10^6 automated adversarial trials with a corpus authored by someone other
than the implementer, an independent red team, formal verification of the
decision core (H-stage), and continuous adversarial testing in production-like
conditions. Until those exist, the defensible statement is "these controls hold
on this corpus", not a percentage.

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

## Milestone specifications (full format)

M0–M3 are specified in full format below and are **done**. M4–M16 were run the
same way and also all landed — their full-format specifications live in
`PROMPTS/M*-*.md`, and the completion evidence (counts, commits, benchmark
results) lives in `CURRENT_STATE.md` and `AGENT-SESSION.md`.

Stage 0 (EASY) and Stage 1 (MEDIUM) are fully closed as of M15/M16. The open
frontier is Stage 2 (HARD), above.

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

### M17 — Federation: control-plane as first client (ADR-022)

- **Purpose:** make control-plane the first federation client — anchored
  evidence + capability-gated dispatch across repos, no code merge.
- **Why it matters:** control-plane's "external verification decides" thesis
  rests on a writable JSONL log and unsandboxed workers; the federation
  closes both without changing its semantics.
- **Dependencies:** M14 REST API, M4 capability-request flow, M16 sandbox
  lifecycle — all shipped. Runs **parallel** to Stage 2 H1 (disjoint
  surfaces; dispatch uses the human-gated M4 flow, so signed delegation is
  not a prerequisite).
- **Complexity:** M.
- **Security significance:** the first cross-repo trust boundary — REST
  clients become bearer-token principals, one tenant per project.
- **What becomes possible:** every dispatched worker is capability-scoped and
  every control-plane verdict is tamper-evident from outside its repo.
- **Acceptance criteria:** tampered control-plane log detected after the
  anchor cycle; dispatch refused without human approval; no plaintext project
  content in ASL events; ASL never mints authority; both repos' gates green.
- **Threats introduced:** availability coupling (ASL down → dispatch fails
  closed), bearer-token handling inside control-plane.
- **Threats mitigated:** self-verifying agents, unanchorable evidence,
  unscoped worker authority.
- **Tests required:** anchor tamper detection; capability-request denial
  without approval; sealed-event secret scan on the federation path.
- **Evidence produced:** anchor receipts in control-plane state, ASL audit
  export showing federation events. Full prompt: `PROMPTS/M17-federation-control-plane.md`.
