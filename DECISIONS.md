# DECISIONS

Architectural decision records. Newest last. Superseding a decision means adding
a new ADR that references the old one, never editing history silently.

---

## ADR-001: Policy engine — in-process policy-as-data evaluator

**Context:** Authorization decisions are needed on every agent action. Candidates:
Open Policy Agent / Rego, Cedar, or a purpose-built evaluator.

**Decision:** A small, pure, in-process evaluator over a typed rule set
(`src/policy.ts`), behind a `PolicyEngine` port.

**Alternatives:**
- **OPA/Rego** — mature, expressive, CNCF-graduated. Requires deploying a Go
  sidecar or binary; every decision becomes a network call or FFI; Rego is
  expressive enough to become unauditable; partial-evaluation bugs are a real
  class of CVE.
- **Cedar** — formally verified core, decidable, deterministic, no I/O, designed
  for exactly this. Best long-term fit. JS consumption requires a WASM build
  (`@cedar-policy/cedar-wasm`) that is early-stage, and the authoring/validation
  toolchain is Rust-first.

**Reasoning:** The PDP is the one component that must always answer. Putting a
network hop or a young dependency in front of it trades a real availability and
trust-boundary cost for expressiveness we do not yet need. Default-deny and
deny-overrides are ~40 lines and are tested directly. The port keeps Cedar
swappable.

**Security implications:** No new trust boundary in the decision path. Fail-closed
by construction — an unreachable sidecar cannot be a failure mode we do not have.

**Tradeoffs:** We own correctness. No formal verification, no battle-tested
parser, no ecosystem of policy tests.

**Future migration path:** When policy sets exceed ~50 rules, or when a customer
requires independently auditable policy, implement `PolicyEngine` over Cedar
(WASM or a Rust sidecar) and keep the same `EvaluationContext` shape. Rule
translation is mechanical; the call sites do not change.

---

## ADR-002: Capability model — signed, attenuated, single-use-capable

**Context:** Authority must be scoped, provable, and non-forgeable, and must not
exceed the issuer's own authority.

**Decision:** Capabilities are plain objects (`src/capability.ts:39`) with issuer,
subject, tenant, resources, actions, classification ceiling, expiry, optional
single-use, constraints, provenance, and an HMAC-SHA256 signature over canonical
JSON.

**Alternatives:** unsigned structs (forgeable by anything with a reference);
macaroons (caveat chains — more powerful, more machinery); JWT (token
ecosystem baggage, alg-confusion risk); full certificate chains (heavy for
in-process use).

**Reasoning:** An unsigned capability held by an untrusted process is not a
capability, it is a suggestion. HMAC gives integrity and issuer authentication
with `node:crypto` and zero dependencies. Attenuation is checked explicitly
against a declared issuer authority.

**Security implications:** A holder cannot widen its own capability. Forgery
requires the signing key. Signature verification is constant-time.

**Tradeoffs:** HMAC is symmetric — any holder of the key can mint. There is no
per-issuer asymmetric signing, and no chained (parent-signature) delegation yet.

**Future migration path:** Asymmetric signing with per-tenant keys from a
KMS/HSM (ADR-008), plus a `parentSignature` field to make delegation chains
cryptographically provable rather than declared.

---

## ADR-003: Sandbox — seam first, isolation later

**Context:** Agent-generated and tool code must eventually run isolated. Today
there is no isolation and pretending otherwise is worse than admitting it.

**Decision:** `Sandbox` interface (`src/runtime.ts:62`) with `LocalSandbox`,
which executes in-process and is documented as providing **zero** isolation.

**Alternatives:** start with Docker (present on this machine) or gVisor/Firecracker
now; or hard-code execution inline with no seam.

**Reasoning:** The enforcement seam is the architectural asset. Once every
execution flows through `sandbox.run()`, the backend is replaceable without
touching authorization. Building containers now would add an ops dependency, a
daemon, and a false sense of containment before the policy surface is stable.

**Security implications:** **Negative.** Arbitrary code currently runs with the
runtime's full privileges. This is an accepted, documented gap.

**Tradeoffs:** No protection against malicious tool code or generated code today.

**Future migration path:** M1.5 container backend (non-root, read-only rootfs,
no network namespace except a proxy, seccomp, memory/CPU/PID limits, ephemeral
per task) -> high-assurance: Firecracker/microVM per session with no shared
kernel and attested boot.

---

## ADR-004: Event integrity — hash chain now, signatures later

**Context:** Evidence must be tamper-evident.

**Decision:** Each event carries `previousEventHash` and `eventHash = SHA-256(
canonical JSON of the event including the previous hash )`. `verify()` recomputes.

**Alternatives:** per-event digital signatures; Merkle tree with an anchored root;
external append-only log; blockchain (no).

**Reasoning:** Detects the realistic failure — someone edits or removes a record —
at the cost of one hash per event. Signatures would additionally prove *who*
wrote an event, but there is no key infrastructure to hold them yet, and
fabricating a signature infrastructure prematurely is exactly the kind of
fake assurance this project must avoid.

**Security implications:** Modification and reordering are detected. Deletion of
the whole log, or a full recomputation by an attacker with write access, is not.

**Tradeoffs:** Integrity is internal-consistency only. No non-repudiation.

**Future migration path:** Per-event Ed25519 signatures chained to a signed head,
periodic publication of the head hash to an external anchor (WORM storage,
transparency log, or customer-held witness), and append-only storage.

---

## ADR-005: Model gateway — narrow port plus whitelist parser

**Context:** Model providers are untrusted and their responses are attacker-
influenced JSON.

**Decision:** `ModelPort` with a single `complete()` method; all responses pass
through `parseModelOutput` (`src/model.ts:42`), which constructs a fresh object
from a field whitelist and drops everything else.

**Alternatives:** trust the SDK object; validate with a schema library (adds a
dependency); cast and hope.

**Reasoning:** The whitelist is the boundary: unknown fields from a hostile
provider cannot reach the runtime, so an "authority" field invented by the
provider is discarded rather than ignored-with-a-warning.

**Security implications:** Compromised provider output degrades to "wrong text",
not "extra authority".

**Tradeoffs:** Adding a legitimate field to `ModelOutput` requires a code change.

**Future migration path:** Provider adapters (OpenAI, Anthropic, Bedrock, local
llama.cpp/vLLM) behind the same port, plus provider-side controls: no training
retention, data-residency pinning, request/response redaction, and per-provider
egress allowlists.

---

## ADR-006: Identity — deferred, deliberately

**Context:** The brief requires OIDC/OAuth2/MFA/SSO/service/workload identity.
None of it exists yet.

**Decision:** Ship principals as typed data with an explicit `kind`, and build no
authentication. Document the absence as an open boundary (B10/identity).

**Alternatives:** bolt on a local user table and password auth (worse: fake
assurance); adopt an IdP SDK now (premature before the authorization model is
stable).

**Reasoning:** Authorization is the hard part and it is independent of how a
principal proved who it is. Adding passwords now would create the illusion of
authentication while the real work — capability scope — was still unsettled.

**Security implications:** **Currently anyone who can construct a Principal can
act as one.** Acceptable only because nothing is deployed.

**Tradeoffs:** The MVP demo cannot demonstrate real authentication.

**Future migration path:** OIDC for humans with MFA enforced at the IdP;
workload identity via SPIFFE/SPIRE or cloud workload identity federation;
short-lived service tokens; agent identities derived per session from the
launching human or service, never global.

---

## ADR-007: Tenant isolation — logical now, physical later

**Context:** Multi-tenant is required; strong isolation is a VERY HARD stage item.

**Decision:** Enforce isolation logically at the PDP (tenant equality) and inside
the engine (`@tenant-isolation`), in one shared process.

**Alternatives:** separate process/DB/schema per tenant now (operational cost,
premature); row-level security only (a single bug exposes everything).

**Reasoning:** Two independent checks in the decision path give defense in depth
cheaply. Physical separation buys little until there is something to separate —
and it should be driven by contract, not by optimism.

**Security implications:** Isolation is one memory-safety or serialization bug
deep. Stated openly in TM-003 and Claim 9.

**Tradeoffs:** Not sufficient for adversarial multi-tenant SaaS today.

**Future migration path:** Per-tenant encryption keys, per-tenant database
schemas or databases, per-tenant sandbox instances, and eventually per-tenant
compute with cross-tenant transfer only through an explicit, reviewed,
logged cross-domain mechanism.

---

## ADR-008: Secrets — broker seam, plaintext in memory

**Context:** Agents must not read secrets unless explicitly authorized.

**Decision:** `SecretBroker` gated by the PDP; baseline policy grants no
`secret.use` rule, so denial is the default. Values are held in plaintext in a
Map.

**Alternatives:** wire HashiCorp Vault or cloud KMS now; inject secrets into the
prompt (never — explicitly forbidden by the brief).

**Reasoning:** The gate is the security property; the storage backend is not.
Default-deny plus one tested break-glass path proves the control without
standing up a KMS.

**Security implications:** Values are readable by anything with process memory
access. Evidence does not yet redact on every path.

**Tradeoffs:** No rotation, no expiry, no envelope encryption, no audit of use
beyond the access decision.

**Future migration path:** KMS/HSM-backed envelope encryption, per-tenant keys,
short-lived dynamic credentials, brokered injection into tool calls (the agent
never sees the value), and mandatory redaction of all recorded outputs.

---

## ADR-009: Network egress — decide now, proxy later

**Context:** Arbitrary outbound access must be impossible.

**Decision:** `NetworkGateway` synthesizes a resource per host and routes the
request through the PDP. It **opens no socket**.

**Alternatives:** actual HTTP proxy now; iptables/nftables rules; no control at all.

**Reasoning:** A decision-only gateway cannot be bypassed by having a bug in the
socket path, because there is no socket path. It also means the policy surface
is proven before the dangerous component exists.

**Security implications:** Today nothing can egress, because nothing can connect.
That is honest but it is not yet enforcement against a component that opens its
own connection.

**Tradeoffs:** Does not constrain code that reaches the network directly.

**Future migration path:** Deny-by-default egress proxy with the session having
no route to the internet except through it; DNS pinning; IP-literal blocking;
per-session TLS interception with policy on destination and payload class;
egress volume limits to blunt slow exfiltration.

---

## ADR-010: Deployment — Node + SQLite, Postgres later, Kubernetes never-by-default

**Context:** The brief warns against making Kubernetes mandatory because the
product is enterprise.

**Decision:** Single Node process, `node:sqlite` for evidence, everything else in
memory. Postgres is a planned swap, not a current dependency.

**Alternatives:** Postgres from day one (not installed here; adds ops burden with
no security benefit at this scale); microservices (more boundaries to secure
before the first one works); Kubernetes (operational complexity for a
single-process workload).

**Reasoning:** Fewer moving parts means fewer boundaries to trust. One process,
one trust domain, zero runtime dependencies is the strongest position from which
to add complexity deliberately.

**Security implications:** Single point of failure; no horizontal scaling; SQLite
file is the evidence store and must be protected like one.

**Tradeoffs:** Not multi-node; not highly available.

**Future migration path:** Postgres for multi-node **state** with row-level
security; object storage or WORM for **evidence**; packaging for customer VPC and
air-gapped installs (signed bundles, no runtime network fetches).

**Evidence is not state.** The evidence store (append-only, hash-chained, must
survive process death, one writer) and the application state store (queryable,
transactional, multi-writer, tenant-isolated) have different requirements and
must never be the same technology by accident. Today there is only evidence in
SQLite and no state store at all. When Postgres arrives it takes state; the
evidence store stays a local append-only sink that is anchored externally.
SQLite is deliberately retained for single-node, on-prem, and air-gapped
deployments, where "no server to run" is a feature.

---

## ADR-011: Prompt injection — structural, not filter-based

**Context:** The brief explicitly warns that prompt filtering is insufficient.

**Decision:** Injection resistance comes from the data/authority split. A
detector (`src/registry.ts:95`) exists for telemetry only; **its output is never
an input to authorization**.

**Alternatives:** input sanitization, instruction-hierarchy prompts, LLM-based
injection classifiers as a gate.

**Reasoning:** A filter is a race against an adversary who writes the text. A
structural boundary — no path from text to authority — does not care how
convincing the text is.

**Security implications:** Injection attempts are visible in the evidence
(`session.injection-signal` events) and are harmless to authorization.

**Tradeoffs:** The agent may still be *misled* into legitimate-but-wrong actions
inside its granted scope.

**Future migration path:** Keep the split as the control; add detectors only as
telemetry and for human review queues; measure injection-driven task deviation in
the benchmark as a usability metric, never as a security metric.

---

## ADR-014: No single security percentage; per-control assurance targets

**Context:** The project's ambition is expressed as "as close to 99.9996% secure
as possible". That number (≈3.4 failures per million, the Six Sigma figure) is a
legitimate aspiration and an unusable metric: it has no denominator, no defined
failure event, and no test that could falsify it. Publishing it would break the
rule this project was founded on — every claim must bind to a property, a threat
model, a mechanism, a test, and evidence.

**Decision:** Refuse the single number. Publish one measurable target per
control instead (ROADMAP.md, "Assurance targets"), each with a named
measurement, and report current values on every run via
`npm run benchmark`. Where a target is unmeasurable (unknown future
vulnerabilities), say so in IMPOSSIBLE+ rather than assigning it a number.

**Alternatives:** adopt the percentage as a marketing figure (rejected —
indefensible under audit); adopt a qualitative maturity model (useful later, but
it hides whether a specific control works); derive a composite score from the
per-control numbers (rejected — averaging distinct controls produces a number
that means nothing and ages badly).

**Reasoning:** The instinct behind 99.9996% is right: make unauthorized access
extraordinarily difficult, and prove it. The way to prove it is per-control
measurement with growing evidence, not a single figure that no test can fail.
A composite percentage would also create pressure to keep it high rather than
to report honestly.

**Security implications:** None directly. Indirectly large: it keeps the
evidence honest, which is what makes the other twelve claims credible.

**Tradeoffs:** Harder to summarise for a buyer than one number. Some customers
will ask for the number anyway; the answer is the table plus the test suite.

**Future migration path:** As the corpus grows past ~10^5 trials with
independent authorship, and as formal verification of the decision core lands,
per-control rates become statistically meaningful and can be published with
confidence intervals. At that point a composite reliability figure for the
*decision core* — never for the whole system — may become defensible.

---

## ADR-013: Evidence confidentiality — seal at rest, decrypt by clearance

**Context:** Evidence must be reconstructable by a cleared reviewer, but the
evidence store is an unencrypted SQLite file that anyone with the file can read.
Two earlier options were both wrong: writing content in the clear (secrets
concentrated in the weakest store) and dropping content above a ceiling
(evidence could not answer "what was accessed").

**Decision:** Always seal output content before it is written, with one AES-256-GCM
key per classification level derived by HKDF from a master key (`src/seal.ts`).
Store the plaintext digest so anyone can verify integrity. Decryption is an
ordinary authorization: `evidence.decrypt` on a synthetic key resource
(`evidence-key:<classification>`), granted by capability and audited like any
other decision.

**Alternatives:** one key for everything (simpler, but no granularity between
reviewers); per-tenant keys now (needs KMS we do not have); application-level
access control on the store only (protects the file, not backups and copies);
drop content above a ceiling (loses reconstructability).

**Reasoning:** The requirement is "cleared reviewer can, attacker with a copy
cannot". Sealing satisfies both without inventing a second authorization system —
clearance is just a capability, so it is issued, scoped, expires, and is audited
by the machinery that already exists. Reading the evidence becomes evidence.

**Security implications:** An attacker who obtains the evidence file — or a
backup of it — gets ciphertext and digests. A reviewer needs a capability for
that specific level; the attempt is denied and logged otherwise. Because
`authorize()` fails closed, an unavailable evidence store denies reveals too.

**Tradeoffs:** The master key is an environment variable with no rotation, no
HSM, and no separation from the host. **A master key stored next to the database
degrades this to obfuscation** — it defends against a copied or stolen file, not
against an adversary who owns the host. Rotation is not implemented: re-sealing
history is a migration, not a flag.

**Future migration path:** KMS/HSM-held master key with envelope encryption,
per-tenant data keys, key rotation with re-seal tooling, and — for the
high-assurance tier — hardware-backed keys so the runtime never holds the master
key at all.

---

## ADR-012: Language and runtime — TypeScript on Node, zero runtime dependencies

**Context:** The control plane should be strongly typed; the project must stay
auditable for a decade.

**Decision:** TypeScript executed directly by Node 24's type stripping, `node:test`
for tests, `node:sqlite` and `node:crypto` for storage and hashing. No runtime
dependencies; `typescript` and `@types/node` are dev-only.

**Alternatives:** Go or Rust (stronger guarantees, slower to evolve, would
marginalize the control-plane ecosystem); Python (weaker typing at the
boundary); a framework-based TS stack (dependencies whose update cadence we do
not control).

**Reasoning:** Every runtime dependency is a supply-chain trust decision. Zero is
achievable here and is worth more than convenience. Erasable-syntax-only keeps
the runtime buildless.

**Security implications:** Smallest possible dependency attack surface. Memory
safety is the runtime's, not ours — a real limitation versus Rust.

**Tradeoffs:** No framework; more hand-rolled plumbing; weaker type guarantees
than Rust for the parts that will eventually need them.

**Future migration path:** If formal verification or memory safety becomes a
requirement for the PDP specifically, rewrite *that module* in Rust behind the
same interface — the seam already exists.
