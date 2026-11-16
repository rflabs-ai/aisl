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

**Decision:** `Sandbox` interface (`src/runtime.ts:64`) with `LocalSandbox`,
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

## ADR-004: Event integrity — hash chain, per-event Ed25519 signatures, head-hash anchor [superseded by M3]

**Context:** Evidence must be tamper-evident, and ideally tamper-resilient
against an attacker with host access.

**Decision (M0):** Each event carries `previousEventHash` and
`eventHash = SHA-256( canonical JSON of the event including the previous hash )`.
`verify()` recomputes.

**Decision (M3 — supersedes the M0 partial position):** Each event also carries
an Ed25519 signature over the canonical body (everything except `eventHash` and
`signature`). The SQLite store is protected by `BEFORE UPDATE/DELETE` triggers
that raise `security_events is append-only`, and a head-hash anchor file
receives one `<seq>:<eventHash>` line per append. A standalone `verifyBundle()`
verifier parses an exported bundle and checks the hash chain, the signatures
(when a public key is provided), and the head against the anchor content —
no database access required.

**Alternatives:** per-event digital signatures only (no anchor — still
vulnerable to a complete rewrite); Merkle tree with an anchored root
(heavier, same property); external append-only log only (single point of
failure); blockchain (no).

**Reasoning:** Ed25519 gives per-event non-repudiation with one signer key
and zero dependencies (`node:crypto`). The anchor file is the simplest
external witness: any attacker who rewrites the chain must also rewrite the
anchor consistently, which raises the bar from "edit one row" to "edit one
row and one file in lock-step". Append-only triggers are belt-and-braces
against direct SQL tampering.

**Security implications:** modification, deletion, reordering, recomputation,
and tail truncation (when the bundle is reconciled against the anchor) are
detected. Per-event signatures prove who wrote each event. An attacker with
host access to both the SQLite store *and* the anchor file can still rewrite
both consistently; this is why the anchor is meant to live on a witness the
runtime does not control (customer WORM bucket, transparency log, separate
storage tier). See Claim 8 for the residual risk.

**Tradeoffs:** The Ed25519 key is held in process memory unless
`EVENT_SIGNING_PRIVATE_KEY_PEM` is supplied. Key rotation requires
re-signing history (a migration, not a flag), same caveat as ADR-013's
sealing master key. The anchor file is just a flat text file — no
tamper-proofing on its own; tamper-proofing comes from it living on a
different trust domain than the SQLite store.

**Future migration path:** HSM/TPM-backed key custody with envelope
encryption of the signing key at rest; periodic publication of the head
hash to an external transparency log (Certificate Transparency, sigstore,
or a customer-held WORM bucket); signed-key bundles for cross-process
verification; offline verifier that takes a public-key bundle and anchor
content from a customer-controlled store.

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

## ADR-006: Identity — deferred, deliberately [SUPERSEDED by ADR-016]

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

## ADR-016: Identity — OIDC with MFA, structural enforcement [supersedes ADR-006]

**Context:** ADR-006 deferred identity because the authorization model was
unstable. It is now stable (M0, M1). The capability model already assumes
identity that did not exist — `Approval.approvedBy` was an unauthenticated
string, and any code could construct a `Principal`. M2 makes identity real.

**Decision:** OIDC for humans with MFA enforced at the IdP. Agent identity
derived per session from the launching human, never a global credential.
Principal carries an `AuthContext` from the IdP; the PDP rejects any principal
without valid auth. Approvals require an authenticated human with MFA. Uses
`jose` (ADR-015) for JWT/JWK verification.

**Alternatives:**
- **Hand-rolled JWT verification** — rejected: defect by the bar.
- **No auth, just typed data** — this is ADR-006, superseded.
- **SPIFFE/SPIRE for workload identity** — deferred to HARD stage; agent
  identity derived from human session is sufficient for MVP.

**Reasoning:** The PDP needs to know *who* is asking, not just what they hold.
A single guard in `authorize()` rejects unauthenticated principals — one
check, not per caller. OIDC is the standard; MFA is non-negotiable for
approval actions.

**Security implications:** The IdP is a new trust dependency. A compromised
IdP can issue valid tokens. The runtime cannot distinguish stolen tokens from
legitimate ones — that is the IdP's job.

**Tradeoffs:** First runtime dependency (jose); IdP dependency for all
authentication; no offline authentication.

**Future migration path:** SPIFFE/SPIRE for workload identity; short-lived
service tokens; hardware-backed keys (HSM/TPM) for the IdP; IdP-attested
MFA for agent sessions; token replay detection via a revocation cache.

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

**Correction (2026-09-24):** the ambition figure was recorded as 99.9996% — a
dropped digit. The stated vision (`initial-idea-CONTEXT.md`) is 99.99996%
(≈0.4 defects per million); that number is the SSOT and has been corrected
throughout this doc set. The architectural implication versus the Six Sigma
figure (≈3.4 per million) is unchanged: still an aspiration, never a published
claim.

**Context:** The project's ambition is expressed as "as close to 99.99996%
secure as possible". That number (≈0.4 defects per million) is a
legitimate aspiration and an unusable metric: it has no denominator, no defined
failure event, and no test that could falsify it. Publishing it would break the
rule this project was founded on — every claim must bind to a property, a threat
model, a mechanism, a test, and evidence.

**Decision:** Adopt 99.99996% as an internal **north star**, never as a published
claim. Publish one measurable target per control instead (ROADMAP.md,
"Assurance targets"), each with a named measurement, and report current values
on every run via `npm run benchmark`. Where a target is unmeasurable (unknown
future vulnerabilities), say so in IMPOSSIBLE+ rather than assigning a number.

**The defect bar (recorded here because it governs every ADR below):** a
security failure caused by writing the code wrong — client-supplied identity,
a cast that hides a type error, a value read before it exists, a fallback that
silently disables a control, one path that skips authorization — is a **defect,
not a tradeoff**. It gets fixed at the root and gets a regression test that
fails without the fix. It is never written down as accepted risk. A tradeoff is
a choice between two working designs, and it carries a stated cost.

**Alternatives:** adopt the percentage as a marketing figure (rejected —
indefensible under audit); adopt a qualitative maturity model (useful later, but
it hides whether a specific control works); derive a composite score from the
per-control numbers (rejected — averaging distinct controls produces a number
that means nothing and ages badly).

**Reasoning:** The instinct behind 99.99996% is right: make unauthorized access
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
*(Amended by ADR-015: `jose` admitted as the first runtime dependency for
JWT/JWK verification, under the dependency-admission policy.)*

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

---

## ADR-015: First runtime dependency — `jose` for OIDC/JWT verification

**Context:** M2 requires OIDC token verification (RS256/ES256 signature check,
JWKS key retrieval, claim validation). ADR-012 established zero runtime
dependencies. This ADR admits the first one and records the admission policy.

**Decision:** Accept `jose` (panva/jose, ~230 KB, zero transitive dependencies)
as a runtime dependency for JWT/JWK operations. The dependency admission policy
(ROADMAP EASY row) requires:

1. The dependency must be named in an ADR with rationale.
2. It must have no transitive runtime dependencies.
3. It must be pinned in `package.json` with a lockfile.
4. It must be reviewed by at least one maintainer before merge.
5. An SBOM must be generated and diffed on every build (H10).
6. The dependency must not introduce a native compilation step.

**Alternatives:**
- **Hand-roll JWT verification** using `node:crypto` directly — rejected: the
  defect bar in SECURITY_PRINCIPLES.md makes hand-rolled token verification a
  defect, not a simplification. JWT/JWKS has a long history of implementation
  pitfalls (alg:none, key confusion, JKU injection, kid injection) that a vetted
  library already addresses.
- **`jsonwebtoken`** — mature but larger, transitive dependencies, deprecated
  maintainer status.
- **`oidc-client`** — full OIDC client SDK; we need only token verification, not
  a full OIDC flow.

**Reasoning:** `jose` is the smallest well-audited JWT library with zero
transitive dependencies, native ESM support, and comprehensive JWKS handling.
It is the standard choice for Node.js JWT verification in 2024-2026.

**Security implications:** The dependency becomes part of the trust surface.
`jose` handles signature verification, key management, and claim validation —
getting any of these wrong is a critical vulnerability. Using a vetted library
is explicitly required by the defect bar; hand-rolling is the defect.

**Tradeoffs:** First runtime dependency breaks the zero-dependency property.
The lockfile pins the exact version; updates require review.

**Future migration path:** None expected — `jose` is the standard Node.js JWT
library. If a hardware-backed key operation is needed (HSM/TPM), `jose`
supports WebCrypto which can be backed by hardware.

---

## ADR-017: Role model — roles narrow issuance, they never mint it

**Context:** M11 (Granular RBAC, Stage 1). `Principal.roles` was a free string
list that policy rules could match but that had no definition and no effect on
capability issuance. The alternatives were a full RBAC engine (roles as
authority sources, role hierarchies, permission matrices) or leaving roles as
untyped strings.

**Decision:** A role is data: `{ id, tenantId, actions, maxClassification,
description? }` (`src/policy.ts`, `BASELINE_ROLES`, `ROLE_TABLE_VERSION`). It
is a NARROWING TEMPLATE over issuance, never a source of authority:
`AuthorizationService.issueForRole` builds the `IssueRequest` through
`issueRequestForRole` and delegates to the ordinary `issue()` pipeline, so the
issuer-kind allowlist, tenant match, and attenuation (ADR-002, invariants 2/3/
4/6) apply unchanged. An issuance request exceeding the role (action outside
the set, classification above the ceiling) throws; an omitted classification
defaults to the role ceiling. `createPolicyEngine` cross-validates allow rules
that reference roles at construction and refuses any that grant beyond the
role (including wildcard action sets) with `PolicyCompilationError`. Role
tables load as versioned, hash-verified bundles (see `src/policy-config.ts`).

**Alternatives:**
- **Roles as authority sources** (RBAC engine: a role GRANTS its holder
  rights) — rejected: it duplicates the capability model's job and creates a
  second path to authority. Here a capability still names explicit resources,
  and the role only bounds what an issuer may mint.
- **Role hierarchies / inheritance** — deferred: no operator has outgrown a
  flat table; inheritance adds a widening path that is hard to audit.
- **ABAC over principal attributes** — the policy conditions already cover
  the needed cases (`param-equals`, `network-host-in`); attributes remain
  matchable via future conditions without a role rework.

**Reasoning:** The invariant that matters is "roles narrow authority; they
never mint it." A widening template is exactly how over-privileged RBAC ships:
the role looks like an organization chart but functions as a privilege
escrow. Throwing on over-reach (instead of silently capping) makes the
over-privileged request visible at the call site, and cross-validation at
engine construction keeps the rule set and the role table from drifting apart.

**Security implications:** Issuance through a role cannot exceed the role
(Claim 24, tested structurally for the whole baseline table). The role table
itself is configuration: it loads through the versioned-bundle mechanism, so
tamper is refused and loads are audited (Claim 26). A role defined too widely
makes wide mints legitimate — the platform constrains scope, not judgment.

**Tradeoffs:** No inheritance, no per-role approval routing, no dynamic role
CRUD; tables are code-adjacent data with a version bump on shape change.
Cross-validation only covers roles present in the constructed table.

**Future migration path:** Per-tenant role tables via `RoleBundle`;
inheritance only if a flat table measurably fails; role-based approval
routing through the M4 request flow; signed bundles (H10/H12).

---

## ADR-018: Postgres control plane — dual EventStore backend, RLS, per-tenant keys

**Context:** M12. ADR-010 deferred Postgres ("planned swap, not a current
dependency"); the ROADMAP rows it named — Postgres schema + migrations,
tenant isolation hardening (RLS, per-tenant keys), backup + restore, and the
Stage-0 project/task/session persistence row — are now due. This is the
second runtime dependency ever admitted (after `jose`, ADR-015), so the
ADR-015 admission policy governs: named here, no transitive runtime deps,
pinned with a lockfile, reviewed before merge, SBOM diffed on build (H10),
no native compilation step.

**Decision:**

### Driver: `postgres.js` (npm `postgres`), pinned

- **Zero transitive runtime dependencies** (ADR-015 item 2). `node-postgres`
  (`pg`) pulls `pg-connection-string`, `pg-protocol`, `pg-types` and others —
  it fails the policy as written.
- Native ESM, tagged-template parameterization (every value is a bound
  parameter by construction), and a multiplexed single socket, so **no
  pooling library and no pool tuning** — the constraint "no pooling library"
  is met by the driver, not ignored.
- Pinned in `package.json` + lockfile; one SBOM line added per build (H10).

### Dual backend behind an `EventStore` port

The port is **the existing public surface of `EventLog`** (`src/events.ts`):
`append`, `all`, `forTenant`, `query`, `exportFor`, `verify`, `bundle`,
`anchor`, `close` — extracted as an interface. Two implementations:

1. **`EventLog`** (unchanged) — SQLite (`node:sqlite`) + in-memory. Remains
   the default for single-node, on-prem, air-gapped, and every test run
   without `DATABASE_URL`. Not a rewrite, not deprecated.
2. **`PostgresEventLog`** (`src/event-store-pg.ts`) — same surface over
   Postgres. On connect it runs forward-only migrations and verifies the
   chain (resume parity: refuse to append onto a broken chain, like
   `EventLog.resume()`).

The construction seam is `src/scenario.ts` (the single `new EventLog` call
site); no other caller changes. `verifyBundle()` and the audit-query API are
untouched — they operate on exported bundles and the port surface.

SQLite stays the **default embedded/test backend**. Postgres is **opt-in**:
the backend flips to `PostgresEventLog` only when `EVENT_STORE=postgres`
AND `DATABASE_URL` are set — an ambient `DATABASE_URL` alone must not flip
every in-process world to a store that needs migration and async readiness
(appends before ready fail closed). Postgres tests skip cleanly when
`DATABASE_URL` is unset (mirror the container-sandbox fallback pattern).
No ORM; raw SQL through the port. **No query federation
and no read replicas** — one runtime role, one writer.

### Schema (implementation must match this or amend this)

```sql
-- Migration bookkeeping. Forward-only; hash of the migration file recorded.
migrations(id INTEGER PRIMARY KEY,
           hash TEXT NOT NULL,
           applied_at TIMESTAMPTZ NOT NULL);

-- Parity with the SQLite security_events table (src/events.ts).
security_events(seq BIGINT PRIMARY KEY,
                tenant_id TEXT NOT NULL,
                timestamp BIGINT NOT NULL,
                event_hash TEXT NOT NULL,
                event TEXT NOT NULL);   -- TEXT, parity with src/events.ts:227:
                -- verify() re-hashes the PARSED object, so the column must
                -- round-trip byte-stably; JSONB normalization would not.
CREATE INDEX security_events_tenant_seq ON security_events (tenant_id, seq);
-- Append-only: app role has INSERT/SELECT only; UPDATE/DELETE revoked;
-- BEFORE UPDATE/DELETE triggers raise, mirroring the SQLite triggers.

-- Capability request flow (M4) persistence.
capability_requests(id TEXT PRIMARY KEY,
                    tenant_id TEXT NOT NULL,
                    principal TEXT NOT NULL,
                    status TEXT NOT NULL,        -- pending|approved|denied|expired
                    requested JSONB NOT NULL,
                    created_at TIMESTAMPTZ NOT NULL,
                    expires_at TIMESTAMPTZ NOT NULL,
                    decided_at TIMESTAMPTZ,
                    decided_by TEXT);

-- Project / task / session persistence (Stage-0 row).
projects(id TEXT PRIMARY KEY, tenant_id TEXT NOT NULL,
         name TEXT NOT NULL, created_at TIMESTAMPTZ NOT NULL);
tasks(id TEXT PRIMARY KEY, tenant_id TEXT NOT NULL,
      project_id TEXT NOT NULL REFERENCES projects(id),
      status TEXT NOT NULL,
      payload JSONB NOT NULL,
      created_at TIMESTAMPTZ NOT NULL,
      updated_at TIMESTAMPTZ NOT NULL);
agent_sessions(id TEXT PRIMARY KEY, tenant_id TEXT NOT NULL,
               task_id TEXT NOT NULL REFERENCES tasks(id),
               principal TEXT NOT NULL,
               state JSONB NOT NULL,           -- everything needed to resume
               created_at TIMESTAMPTZ NOT NULL,
               updated_at TIMESTAMPTZ NOT NULL);
```

All application tables are forward-only, versioned, and recorded (row in
`migrations` + one `policy.load`-style `store.migrate` event). No destructive
step — schema changes are additive columns, never rewrites.

### Row-level security: the database enforces tenant isolation

Three non-superuser roles (no `superuser`, no `bypassrls`, no `createrole`;
schema owner is a separate `app_ddl` role used only by the migration runner):

- **`app_rw`** — the runtime role. On `security_events` it holds INSERT and
  **global SELECT**: `resume()`, `verify()`, and `bundle()` must read the
  whole hash chain across all tenants (src/events.ts:257/406/453), so RLS
  must not filter event reads for the process that signs every event.
  On tenant tables it has full RLS-governed access.
- **`app_reader`** — the audit-query path. Tenant-scoped SELECT on
  `security_events` (same policy shape as below); hostile cross-tenant reads
  through this role return **zero rows** — the database denies, not app code.
- Every role: UPDATE/DELETE revoked on all tables; triggers as belt-and-braces.

Every tenant-scoped table gets `ENABLE ROW LEVEL SECURITY` +
`FORCE ROW LEVEL SECURITY` and deny-by-default policies:

```sql
ALTER TABLE tasks ENABLE ROW LEVEL SECURITY;
ALTER TABLE tasks FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON tasks
  USING      (tenant_id = current_setting('app.tenant_id', true))
  WITH CHECK (tenant_id = current_setting('app.tenant_id', true));
```

The runtime sets the context **per transaction** (`SET LOCAL
app.tenant_id = $1`). `current_setting(..., true)` returns NULL (→ `false`)
when unset, so a hostile query that skips the tenant context reads **zero
rows** — the database denies, not app code. App-code tenant checks remain
(defense in depth, ADR-007) but are no longer the only control.

Exception: `security_events` carries a **global** hash chain (`seq` is
world-order, one signer). `app_rw` reads it unfiltered and appends (see the
role list above — the chain is world-order, one signer, and the runtime has
no UPDATE/DELETE to give up); `app_reader` gets the tenant-scoped policy.
The boundary, stated honestly: RLS proves cross-tenant denial at the
reader/tenant-table surface; the runtime role can read every event because
it is the signer and the chain verifier — that trust is the existing
"runtime process is not compromised" assumption (CURRENT_STATE), unchanged
by this ADR.

### Per-tenant evidence keys (extends ADR-013, no re-encryption)

`src/seal.ts` HKDF info string gains the tenant:
`evidence:<tenantId>:<classification>` (same master key, same SALT). Sealed
records carry a **versioned keyId**: new seals use
`evidence-key:v2:<tenantId>:<classification>`; the legacy
`evidence-key:<classification>` format keeps opening under the old
global-tenant derivation. `open()` dispatches on keyId shape. **No silent
re-encryption** of existing sealed data — old records decrypt as they
always did; the migration path is an operator-run re-seal tool, documented,
not a flag.

### Fail-closed (H15)

An unreachable, unauthenticatable, or mid-migration Postgres denies every
decision that needs the store with the distinct `denyReason:
'store-unavailable'` (new union member in `src/domain.ts`, beside
`'idp-unavailable'`, mapped by a typed `StoreUnavailableError` from the
backend) and one loud health event — no silent fallback to in-memory, no
retry-until-allow. The degraded mode is explicit and operator-visible, per
H15's methodology.

Append semantics around readiness: appends issued **before the store is
open** fail closed with the typed error — a PG-mode runtime must construct
its world through the ready-gated factory (`buildWorldAsync`), which awaits
connect/migration/chain-verification **before any bootstrap append
happens**, so no decision and no bookkeeping can precede a verified store.
Queueing pre-open appends was tried and rejected: a buffered append's seq is
assigned before the chain loads, colliding with rehydrated rows. The
`denyReason: 'store-unavailable'` + loud health signal covers the genuine
outage path (unreachable, unmigrated, failed write).

### Connection and secret handling

`DATABASE_URL` from the environment (production: secret-broker injection
per ADR-008); never logged — connection errors log reason + a redacted
endpoint, never the URL. Password never appears in the event log (H2 scan
covers it).

### Backup + restore

`pg_dump`-based backup script; restore is **rehearsed in a test**, not
assumed: restore into a scratch database, run the existing `verify()` chain
check, assert valid. Anchor-file continuity (M3) documented in
DEPLOYMENT.md — the anchor is outside the dump by design.

**Alternatives:**
- **`pg` / `pg-promise`** — mature but transitive dependencies fail ADR-015
  item 2 as written; could be admitted with an amended policy, but
  `postgres.js` covers the need with a smaller surface.
- **Postgres-only (drop SQLite)** — rejected: it breaks the single-process
  air-gapped install that is ADR-010's feature and would rewrite a working,
  tested evidence backend.
- **App-level tenant checks only, no RLS** — rejected by this milestone's
  charter: one missing `WHERE` clause must not expose every tenant.
- **Citus / sharding / read replicas** — no second node exists to justify
  them (ponytail: add when one does).

**Reasoning:** The evidence plane's invariants (chain, signatures,
append-only) are backend-independent — they live in the event objects, not
in SQLite. Making Postgres a port implementation rather than a rewrite keeps
the audit path, the SLO baseline (M10), and the air-gapped install intact
while the database adds what SQLite cannot: real RLS, concurrent writers,
and operational backup tooling. `postgres.js` is the only driver class that
meets the dependency policy without amendment.

**Security implications:** Cross-tenant reads become a database-enforced
property (tested against hostile queries, not app discipline). New attack
surface: the database itself — connection string custody, role management,
RLS policy drift (migration framework owns it, versioned). Fail-closed now
has a third distinct reason. Per-tenant keys shrink blast radius of a
master-key leak per tenant and bind decryption to tenant identity.

**Tradeoffs:** One more runtime dependency to review and SBOM. Postgres mode
is only tested when a database exists (skipped otherwise — a CI gap to name
honestly). RLS adds a failure mode app SQLite mode does not have (context
not set → empty reads); mitigated by fail-closed tests on both backends.

**Future migration path:** Per-tenant databases/schemas (physical
isolation, ADR-007's endgame) when a customer requires it; KMS-held master
key (ADR-013 path) with per-tenant envelope keys; revocation broadcast over
LISTEN/NOTIFY or a queue (H13); object-storage anchoring of the head hash
(M3 path). Multi-node active-active and pooling tuning stay out until a
second node runs.

---

## ADR-019: REST API surface — `node:http` transport as the platform's network trust boundary

**Context:** M14. The platform has never had a network ingress: every
decision surface so far is in-process (PDP, `AuditQueryService`,
`CapabilityRequestService`, `AgentSession`). The minimal UI (ROADMAP row 39)
and real customer integrations need an HTTP surface. This is the first
network trust boundary the platform admits, so AGENTS rule 4 applies: one
structural invariant test per boundary (identity headers cannot mint a
principal; a request tenant field cannot override the principal's tenant).
Defect-class requirement per SECURITY_PRINCIPLES.md: input validation at
this boundary is not a tradeoff.

**Decision:**

### Transport: Node builtin `node:http`, no framework

Express/Fastify are runtime dependencies whose middleware ecosystem we do
not control — rejected under ADR-012's supply-chain posture. **Zero new
runtime dependencies.** Routing is a **whitelist of literal method+path
pairs**; there is no route pattern language beyond `:param` segments. An
unhandled method+path combination is not "404 with a body" — the server
closes the connection (nothing to advertise).

The server binds loopback by default; TLS terminates at the deployment
(reverse proxy / load balancer, DEPLOYMENT.md). TLS-in-process remains a
documented gap (known-gap #8 updated honestly: a transport now exists;
in-process TLS does not; it is the operator's termination job).

### Identity contract

`Authorization: Bearer <JWT>` **only**. The principal is derived from jose
token verification through `IdentityProvider.verifyToken` (ADR-016) plus a
deployment-configured resolver from the verified `AuthContext` to a
registered `Principal`. **Never from client-supplied `X-*` identity
headers** (the egress-proxy test already proves that pattern in
`src/egress-proxy.ts`). No token → 401; garbage/expired/revoked token → 403;
both carry `denyReason: 'unauthenticated-principal'` — fail closed.

### Tenant derivation

The tenant comes from the verified principal only. A request field that
names a tenant (e.g. a `tenantId` audit-query parameter) is passed to the
underlying service as-is and **validated against the principal's tenant by
the same in-process path** (`queryAudit` denies with `tenant-mismatch` and
appends the deny event — invariant 7 parity: the REST surface must produce
exactly the events the in-process path produces, never fewer, never
extra-side-channel).

### Request parsing = whitelist parser

`parseModelOutput` style (src/model.ts:42): a fresh object is constructed
from a field whitelist; unknown fields from a hostile client are **dropped,
not ignored-with-a-warning**. Wrong-typed required fields are structured
rejections (400), never crashes. Body size is capped (1 MiB) and rejected
with a **distinct status (413) before parsing**. Garbage JSON → 400
structured rejection, server keeps serving.

### Response construction = whitelist too

Every response is a freshly constructed object from explicit fields — no
stack traces, no database URLs, no token contents beyond what
`identity.ts` already records. `denyReason` surfaces as a structured code
on 403. Error text is never echoed from exceptions; handler failures map
to a fixed body.

### Fail-closed mapping

- The PDP returning a deny (including `evaluation-error` — the PDP converts
  its own internal errors to denies, invariant 12) is `403 { denyReason }`
  — never an allow-shaped response.
- An unexpected throw inside a handler → `500 { error: 'internal-error' }`
  plus an appended deny event with `denyReason: 'evaluation-error'` (token
  contents and raw error text never included).
- An unhandled path closes the connection.

### Health + named non-goals

- `GET /healthz` → `{ idp, store }` (H15's first operator-facing health
  endpoint since M2): IdP health status and evidence-store status; no
  secrets, no internals.
- **Rate limiting: NOT in scope** (H15/deployment territory) — named so the
  gap cannot hide. CORS: not needed (same-origin loopback/deployment).
  No WebSockets, no streaming.

### Endpoint contract (implementation must match this or amend this)

| Method + path | Purpose | Path through existing code |
| --- | --- | --- |
| `GET /healthz` | operator health | none (reads IdP + store status) |
| `POST /v1/authorize` | PDP decision surface | `AuthorizationService.authorize()` unchanged |
| `POST /v1/sessions` | create bound session | `SessionManager.create()` (MFA required at IdP) |
| `DELETE /v1/sessions/:id` | revoke session | `SessionManager.revoke()` (immediate propagation) |
| `POST /v1/capability-requests` | agent submits request | `CapabilityRequestService.submit()` (M4) |
| `GET /v1/capability-requests` | reviewer's pending list | `CapabilityRequestService.all()` filtered to tenant + pending |
| `POST /v1/capability-requests/:id/approvals` | human approves (narrowing allowed; MFA enforced) | `CapabilityRequestService.approve()` — the mint stays exactly what M4 mints |
| `GET /v1/audit?...` | tenant-scoped evidence query | `AuditQueryService.query()` unchanged (≤ 90 days, ≤ 1000 enforced at service boundary) |
| `POST /v1/tasks` | execute a task, return trace summary | the ONE existing `AgentSession.run()` path; no new execution path |

**Alternatives:**
- **Express/Fastify** — dependency + uncontrolled middleware supply chain
  (rejected, ADR-012 posture).
- **OpenAPI codegen / schema validation libs** — new dependency; the
  whitelist parsers are the validation (defect-bar compliant, ~100 lines).
- **Trusting `X-Forwarded-*`/`X-Principal-*` identity headers** — the
  exact pattern the egress-proxy tests refuse; rejected structurally.

**Reasoning:** The API is a translation layer over existing, tested
decision paths — every endpoint routes into code that already enforces
authn, tenant, and evidence rules. The trust boundary is therefore narrow:
parse hostile bytes into whitelist objects, bind them to a verified
principal, and let the PDP decide. The defect bar is met by construction:
a field that is not whitelisted cannot reach the runtime.

**Security implications:** New attack surface: the network listener
itself (request flooding — rate limiting is out of scope and named;
parser bugs — bounded by whitelists and the size cap; TLS is not
in-process — loopback bind + deployment termination). The structural
invariant test asserts identity headers cannot mint a principal and that
no endpoint obeys a client-supplied tenant.

**Tradeoffs:** Hand-rolled routing and parsing (we own correctness);
single-threaded request handling (no clustering — one writer is the
Postgres-mode constraint anyway, ADR-018); no CORS/rate limiting/streaming
until a real deployment demands them.

**Future migration path:** Rate limiting + connection budgets (H15);
TLS-in-process if a deployment cannot terminate at a proxy; OpenAPI
description generated from the route table when a customer integration
demands it.

---

## ADR-020: Stage-0 closure — document ingestion, read-only Git, setup script, minimal UI

**Context:** M15. Four ROADMAP rows remain before Stage 0 is done: basic
document ingestion (chunk, label, classify), basic Git integration
(read-only repo access), a developer setup script, and the minimal UI.
The M12 seam (`capability_requests` has a table but no API methods) folds
in here as the same control-plane surface. Zero new runtime dependencies:
Git integration shells out to the installed `git` CLI (the `CommandCheck`
precedent), and the UI is static HTML served by the M14 server.

### Document ingestion

- **Chunking is deterministic.** Fixed-size windows with boundary
  awareness (last paragraph/space boundary inside the window; hard cut
  only when no boundary fits). No model in the loop — chunking must be
  reproducible byte-for-byte from the same input.
- **Chunk ids are deterministic:** `doc/<documentId>/chunk/<n>`. The same
  document always produces the same chunk ids; re-ingestion re-raises, it
  never forks new ids.
- **Labels reuse the M11 machinery, not a new one.** Every chunk carries
  the source document's id as `derivedFrom` and its label is
  `propagateClassification` over the source label(s) — max by rank,
  raise-only on re-ingest via `ResourceRegistry.raiseClassification`.
  Chunks are registry resources, capability-scoped like any resource; a
  derived label feeds ceilings, never grants (invariant 3: hostile
  document content mints no authority).
- **Ingestion is an event.** One `document.ingest` event per chunk with
  the derived label and a SHA-256 digest; chunk content is sealed with
  `sealFor` (one key per tenant + classification, ADR-018). No plaintext
  content in events beyond what sealing already does (Claim 13).

### Git integration: read-only only

- **Allowed verbs are an allowlist at config time:** `log`, `show`,
  `diff`, `status`. Anything outside the set — every write or network
  verb (`commit`, `push`, `fetch`, `clone`, `submodule`, ...) — is
  refused when the reader is constructed, not at exec time.
- **argv only, never a shell string** (the `CommandCheck` posture,
  ADR-013-era `src/check-command.ts`). Fixed argv `[git, verb, ...args]`,
  minimal environment (no ambient secrets), timeout → failure.
- **The repo root is a configured boundary.** Traversal is refused at the
  trust boundary: arguments that name paths outside the root (absolute
  paths, `..` segments) or escape hatches (`--no-index`, `--git-dir`,
  `--work-tree`, `-C`) are refused before spawn.
- **Output is untrusted content.** Git output enters as a document
  through the ingestion pipeline above, labeled with the repository's
  classification; the agent's use of it is gated by the ordinary PDP
  path (a read capability per the ordinary issuance path). No write, no
  push, no fetch, no submodules, no network remotes.

### Setup script: no `curl | bash`

`scripts/setup.ps1` + `scripts/setup.sh` are plain, reviewable files in
the repo. They check the Node version against `engines.node`, run
`npm install`, `npm run typecheck`, and `npm test`, print what they
checked and the next steps, and exit nonzero on the first failed check
(fail-closed applies to tooling). No remote fetches, no pipe-to-shell,
no sudo. They optionally bootstrap the disposable Postgres container from
DEPLOYMENT.md's M12 workflow. The environment is reproducible offline.

### Minimal UI: static HTML served by the M14 server

One static HTML file (`tools/ui/index.html`) — inline CSS/JS, vanilla
`fetch` against `/v1`, zero dependencies, no bundler, no framework, no
`node_modules`. Served by the same `node:http` server as exact registered
routes (`GET /ui`, `GET /`); there is no directory serving and no
parametrized path, so traversal does not exist by construction. The page
is a client of the API: task view posts `POST /v1/tasks`, evidence view
calls `GET /v1/audit` — both authorized by the same bearer-JWT contract
(ADR-019); **no new authorization surface** (the PDP rules do not
change), and the UI shows the trace — it never bypasses the guard. The
bearer token is typed by the operator at runtime; no canary, secret, or
URL is embedded in any served page (secret-scan test). Accessibility
basics are not a simplification target: semantic HTML, labeled inputs,
keyboard reachability.

### Capability-request persistence (M12 seam closure)

`PersistenceStore` gains `createCapabilityRequest` /
`getCapabilityRequest` / `listCapabilityRequestsForTenant` /
`updateCapabilityRequestStatus` — raw tagged-template SQL over the
existing migration-3 `capability_requests` table, tenant-bound like every
other method (RLS context per transaction). The REST capability-request
routes mirror to the store when one is wired (opt-in; absent store →
in-memory behavior unchanged, so the M14 surface does not regress).

**Alternatives:**
- **Model-assisted chunking / embeddings** — nondeterministic, pulls a
  model into the labeling path; rejected until a workflow demands it.
- **libgit2 / isomorphic-git** — a runtime dependency plus a C-native
  surface for four read verbs; the git CLI is already installed and the
  argv posture is already proven. Rejected under ADR-012.
- **`curl | bash` setup** — the exact pattern the row rejects; the repo
  is the review gate.
- **A framework-built UI** — dependencies, build step, and a second
  authorization surface for a two-view page. Rejected.

**Security implications:** New hostile-input surfaces: document content
(data only, no authority — invariant 3 tested), git output (same), git
arguments (allowlist + traversal refusal at config/spawn time), and one
static page (no secrets in served content, tested). Ingestion events
carry sealed content only. The UI adds no new decision path — it renders
what `/v1` already returns.

**Tradeoffs:** CLI-git means git must be installed (dev machines have
it; a deployment that cannot install git cannot use the row — named
honestly). Deterministic chunking is coarse (no semantic boundaries).
The UI is deliberately spare: two views, no state, no i18n.

**Future migration path:** Write-side git only behind an ADR with
full-scan review; richer ingestion (OCR, embeddings) when a real
workflow demands it; UI growth (policy view, approval queue) driven by
operator need, still zero-dep and server-served.

---

## ADR-021: Sandbox lifecycle — create, limit, destroy, attest (M16)

**Context:** M16. M13 shipped the container sandbox
(`src/container-sandbox.ts`, ADR-003 migration path) — Docker-backed
isolation with memory/CPU/PID limits, non-root, read-only rootfs,
no network — but the sandbox is created once and left running: there is
no lifecycle around it. ROADMAP row 61 is the last open Stage-1 row.
The lifecycle is a wrapper over the existing plumbing, not a
reimplementation: zero new runtime dependencies, attestation reuses
`sealFor` (ADR-018 per-tenant keys), limits reuse the existing
`ContainerSandbox` constructor options.

### Decisions

- **Create — synchronous, embedder-held, minimal env.** `SandboxRegistry.create`
  spawns the sandbox synchronously and returns a `SandboxHandle` to the
  embedder/runtime — the agent never receives the handle, only a PDP-gated
  capability. The sandbox id is caller-chosen and namespaced:
  `sandbox:<tenantId>:<sandboxId>`; the ResourceRegistry is the authority for
  which tenant a sandbox belongs to (registered as type `'system'`,
  classification `'public'` — sandbox metadata is not a data label, same
  posture as `audit-log`). Duplicate ids refuse. Spawn environment stays the
  `CommandCheck` precedent: the sandbox executes serialized tool functions, not
  shells; nothing inherits ambient env (the Docker path runs a fixed image, the
  fallback runs in-process under the runtime's own posture).
- **Limit — the existing `ContainerSandboxOptions` ARE the config record.**
  `SandboxLimits` is that type re-exported; no parallel vocabulary. Defaults
  live in one place (`effectiveLimits`, exported so the destroy attestation can
  record limits *actually applied* vs *declared* without duplicating defaults).
  Fail-closed posture is unchanged: limits are enforced by the kernel/cgroup
  when Docker is present; without Docker the kind string says `fallback/...`
  so a caller expecting isolation can detect the degradation.
- **Destroy — deterministic, idempotent, swept.** `destroy` drops the active
  handle and records `sandbox.destroy` (sealed payload: pid, duration,
  effective vs declared limits). Destroy on an unknown id refuses; destroy on
  an already-destroyed sandbox is a no-op (the exit sweep and an explicit
  destroy must not race into a throw). The current sandbox is ephemeral per
  invocation (`docker run --rm`, tmpdirs removed in `finally`), so there is no
  long-lived container to kill — the sweep's job is evidence: every active
  sandbox gets a destroy event on process exit (`installExitSweep()`,
  `beforeExit` + SIGINT/SIGTERM), and a create that throws never leaves a
  half-registered handle (register-after-successful-spawn ordering).
- **Attest — sealed events, digest-only plaintext.** `sandbox.create`,
  `sandbox.destroy`, and `sandbox.attest` events carry
  `metadata.sealed = sealFor(tenant, payload, 'public')` (Claim 13 machinery;
  the lifecycle is not a data-label boundary, but sealing keeps the
  tamper-evident invariant) and a SHA-256 digest of the limit config via
  `canonicalJson`. The plaintext event log shows only the digest and key id —
  same posture as `document.ingest` (Claim 29). The sealed payload records the
  sandbox's own process metadata: pid, kind (honest about fallback), limits,
  timestamps.
- **Capability — the PDP gates every execute.** The agent's authority over a
  sandbox is a `Capability` with action `sandbox.execute` scoped to the sandbox
  resource id; `SandboxRegistry.execute` authorizes through the ordinary
  `AuthorizationService.authorize` path (which appends its own decision event)
  before `runTool`. No new issuance path, no new decision path.

**Alternatives:**
- **Long-lived per-tenant containers** — the current per-invocation
  `docker run --rm` model already bounds blast radius; a daemon-style sandbox
  adds a lifecycle (health, restart, IPC) nothing consumes yet.
- **A parallel limit vocabulary** — drift with `ContainerSandboxOptions` for
  zero benefit; re-export instead.
- **New crypto for attestation** — `sealFor` + the event chain already provide
  tenant-bound tamper evidence; new machinery would be unaudited surface.

**Security implications:** New event actions (`sandbox.create/destroy/attest`)
are sealed and digest-carrying; execute is PDP-gated and audited; tenant
binding is delegated to the ResourceRegistry (the authority) and re-checked on
every lifecycle call; no ambient secrets reach the sandbox; the exit sweep
prevents unaccounted teardown. The sandbox execution itself is unchanged —
`ContainerSandbox` behavior is untouched except for the defaults extraction.

**Tradeoffs:** The attested pid is the runtime's own pid (the sandbox has no
resident process to attest — image digests arrive when a long-lived sandbox
model exists). `installExitSweep` installs process-level signal handlers and
is opt-in so test processes are not wired to it by accident.

**Future migration path:** per-sandbox action policy (which tools a sandbox may
run), multi-tenant sandbox sharing, snapshot/restore, remote attestation
(HSM-backed), and a microVM backend (Firecracker/gVisor) when a deployment
cannot trust the host kernel — each behind its own ADR.

---

## ADR-022: Federation — one enforcement plane, five state planes

**Context:** A portfolio audit (2026-09-27) profiled the five sibling repos and
asked which Stage 2/3 controls each project's own core promise structurally
requires. Findings, compressed:

- **control-plane** (orchestrator: dispatches agent workers, runs external
  verification, "agent claims are never treated as truth"): its thesis rests
  on a *plain writable JSONL event log* and it sandboxes nothing — an
  unsandboxed agent can rewrite its own verdicts. Structurally requires H5
  (sandbox), H11 (tamper-evident evidence), H13 (kill switch for N-way
  fan-out), H2 (short-lived client credentials).
- **project-raven** (always-on Pi agent, self-building via headless OpenCode
  that rewrites its own repo): unsigned self-update is remote code execution
  by design. Structurally requires H12 (secure updates), H10 (signed builds),
  H2 (static device key), H13/H15 (unattended fail-closed operation).
- **home-agent** (daily-driver personal assistant over Ollama/OpenJarvis):
  web search results → model → tool loop is a live injection path into shell
  exec, and personal material egress is unclassifiable. Structurally requires
  H4, H5, H7, and H11 for its LSM memory (poisoned memory = persistent
  compromise). Security posture is a prose doc + config — no claims ledger,
  no invariant tests.
- **engineering-OS** (markdown-spec build protocol): its evidence log
  (`engine/logger.ts`, regex-gated append-only WAL) IS the product — without
  signatures/anchoring, "no invented state" is unenforceable against a
  compromised chat. Structurally requires H11, H14 (the runtime graduation
  test it names as a gap is exactly H14).
- **creative-os** (SUGGESTION ≠ CANON; human Decision record gates truth):
  lowest-privileged system by design — capture-and-refinement playground
  whose Decision records happen to gate the stack. Requires nothing today;
  when `ModelRuntime` lands, H11-aligned hashing for the source store.

Three of the five already reference ASL: `control-plane/project-registry.yaml`
registers ai-security-layer, engineering-OS, and home-agent as managed
projects; creative-os ADR-0001 names the trio (creative state / execution
state / enforcement); engineering-OS's sibling fence lists several as
read-only.

**Decision:** The five projects stay five repos — no code merges, ever. ASL
is the single enforcement plane (PDP, capabilities, classification, sandbox
lifecycle, signed EventLog); the siblings remain state planes. Integration
exclusively via the M14 REST seam (`/v1/authorize`, `/v1/sessions`,
`/v1/capability-requests`, `/v1/audit`, `/v1/tasks`), one client at a time:

1. **M17 — control-plane first**: its event log head-hash is anchored into
   ASL's evidence plane (the M3 anchor pattern across repos); dispatches
   become capability requests approved by the human operator through the
   ordinary M4 flow; ASL never mints authority itself.
2. **M18 — project-raven**: self-build runs through the M16 sandbox
   lifecycle; the self-update pipeline adopts H10/H12 (signed builds,
   verified updates) before it modifies its own repo unattended.
3. **M19 — home-agent**: its egress fence becomes a client of the ASL egress
   gate + M13 classification machinery (same idea, stronger enforcement);
   LSM memory anchoring follows.
4. **M20 — engineering-OS**: retire `engine/logger.ts` into ASL's signed
   EventLog — two evidence planes is the failure mode to avoid.

creative-os integrates nothing: it holds the Decision records that gate
dispatch and reads audit through the ordinary client path.

**The federation pulls H8/H2/H13 forward.** The moment several projects share
one ASL as tenants with very different ceilings (personal journal vs this
repo's own source), cross-tenant isolation (H8, known-gap #7), short-lived
client credentials (H2), and incident-response kill switches (H13) become
structurally necessary for the *federation* even where no individual project
needed them. Gate: H8 must close (or its residual be explicitly accepted per
deployment) before any non-personal tenant joins.

**Alternatives:**
- **Merge the codebases** — rejected: the trust story depends on a small,
  auditable surface; merging imports every sibling's dependencies and attack
  surface into the enforcement plane.
- **Grow engineering-OS's evidence log in parallel** — rejected: two evidence
  planes means two tamper stories, one of them untested.
- **Per-project bespoke security** — rejected: that is how home-agent and
  raven ended up with prose-only security. One enforcement plane, tested
  once, beats five untested copies.

**Reasoning:** M17 does not depend on H1: its dispatch phase uses the
human-gated M4 capability-request flow (agent asks, human grants), which
already works over the M14 API — signed delegation (H1) is not a prerequisite.
But the federation *amplifies* H1's importance: cross-repo capability issuance
is exactly where "declared, not proven" `issuerAuthority` hurts most, so H1
stays the priority security-core track and runs parallel to M17 (disjoint
surfaces — H1 touches `src/capability.ts` issuance; M17 touches integration
and config).

**Security implications:** New trust boundary — cross-repo REST clients are
bearer-token principals, one tenant per project. Availability coupling: ASL
down means dispatch fails closed (accepted; loud per H15's direction). No
plaintext project content crosses into ASL events (sealed per ADR-018 keys).

**Tradeoffs:** control-plane gains a dependency on a running ASL; the
siblings' security posture is now only as strong as their integration (a
client that bypasses ASL is out of scope of this ADR and must be named in its
milestone's non-goals).

**Future migration path:** M18–M20 in order; prompts written just-in-time per
the M4–M16 convention. Non-personal tenants wait for H8. Automated multi-hop
delegation between projects waits for H1.

---

## ADR-023: Signed delegation — attenuation from a held capability, not a declared object

**Context:** H1 (root of trust), known-gap #11, Claim 6's limitation. A
non-root issuer presents `issuerAuthority` — a plain object the caller
supplies — and `findOverreach` checks the request against it. Nothing proves
the object is real: any caller with a reference to `issueCapability` can
declare authority it does not hold and mint within it. ADR-002 named the
migration path: "a `parentSignature` field to make delegation chains
cryptographically provable rather than declared."

**Decision:** The fourth parameter of `issueCapability` becomes
`parent?: Capability` — the issuer's own signed capability — replacing the
declared `IssuerAuthority` entirely. For a non-root issuer:

1. The parent is required. No parent → refuse.
2. The parent's HMAC signature is re-verified; a tampered parent refuses.
3. The parent must be held BY the issuer: `parent.subject === issuer.id` —
   you can only delegate what you hold, proven by a signed artifact issued to
   you. Presenting someone else's (necessarily stronger) capability refuses.
4. The parent must be same-tenant, unexpired at `now`, and unconsumed
   (`usedAt === undefined` — spent single-use authority does not propagate).
5. The attenuation authority is DERIVED from the parent's own fields; the
   existing `findOverreach` subset check is unchanged.
6. The child's `provenance.delegatedFrom` records the parent's `{ id,
   signature }`, set by `issueCapability` itself (caller-supplied values are
   overridden) and covered by the child's own signature — the chain link is
   tamper-evident, and each hop is walkable by id.
7. `AuthorizationService.issue`/`issueForRole` add custody: the parent must
   be registered with the service and not revoked (stateful checks the pure
   function cannot make).

**Alternatives:**
- **Verify a caller-declared authority object** — incoherent: a declared
  object has nothing to sign; verification of a signature-less artifact is
  theater.
- **Asymmetric per-issuer keys now** — the correct end-state (chains portable
  across processes), but it requires ADR-008's KMS work; within one process
  the HMAC parent already removes the declared-object bypass. Key theft
  remains known-gap #4 and is unchanged by this ADR.
- **Macaroons / caveat chains** — more machinery, no current consumer.

**Reasoning:** The defect was the declared seam, not the subset check. Removing
the seam — authority may only be *derived* from a signed artifact the issuer
holds — makes overstatement impossible without forging the signature, and the
custody checks close the stolen-but-never-registered and revoked-parent holes.

**Security implications:** Attenuation is now enforced on a signed artifact;
delegation is traceable (`delegatedFrom`) and tamper-evident; expired, spent,
cross-tenant, foreign-subject, revoked, and unregistered parents all refuse.
No PDP hot-path change — the chain is checked at the only place authority is
created (issuance), not at every use.

**Tradeoffs:** Callers must hold the actual `Capability` object rather than a
hand-built plain object. Issuance from a service principal now requires that
its capability was genuinely minted through the runtime — by design.

**Residual risk:** The HMAC key is symmetric and process-wide (known-gap #4);
every hop still attenuates strictly, so a delegation cycle cannot escalate,
but no explicit depth limit exists — `ponytail: no chain-depth limit; every
hop attenuates so cycles cannot escalate — add depth/loop detection only if a
non-attenuating hop ever exists`.

**Addendum (2026-09-27, session audit):** the first cut left two gaps, both
ticketed by the audit and closed the same day. (a) The subset check now covers
ALL held dimensions: a child must carry every parent constraint (it may narrow
network hosts further — intersection semantics; no false denial of legitimate
narrowing), and a single-use parent cannot delegate at all (a single-use
capability is a leaf authority — it exists to be consumed once). (b) Parent
validity is checked whenever a parent is present, including for the root, so
no chain link is ever recorded from an unvalidated parent. Service-level
custody refusals (revoked/unregistered parent) are audited as
`capability.issue` deny events before the throw. Tests 24 → 32.

**Future migration path:** Per-issuer asymmetric keys (ADR-008) make chains
portable across processes (M17 federation multi-hop delegation); chain-depth
policy if workloads demand long chains.

---

## ADR-024: Signed builds and the supply-chain gate — the source tree is the artifact (H10)

**Context:** H10. The dependency admission policy (ADR-015) exists on paper —
named-in-ADR, zero-transitive, pinned-with-lockfile, review gate, SBOM diffed
on build (item 5), no native compilation (item 6) — but item 5 was enforced by
session discipline, not by code: there is no SBOM artifact, no diff gate, no
hash verification of the dependency set, no build signing, no provenance
attestation, and `package.json` carries `^` ranges (the lockfile pins; the
manifest does not). TM-004 records "add a malicious dependency" as
detected/limited by policy; a malicious *update* to an already-trusted dep is
the recorded residual.

**Decision:** Four controls, all in code, zero new dependencies.

1. **The artifact of record is the source tree.** There is no compiled binary
   — TypeScript ships as source and the process is the runtime. The build
   input set is every git-tracked file except `artifacts/*` (outputs). Its
   identity is `treeDigest = sha256(canonicalJson([[path, blobSha], ...]))`
   over `git ls-files -s`, excluding `artifacts/`. Blob SHAs hash committed
   content, so the digest is platform-independent (CRLF checkouts cannot
   break or forge a manifest across machines) and binds the commit, not the
   working tree.
2. **SBOM as a review artifact.** `ASL-SBOM v1` is generated from
   the lockfile (`npm-shrinkwrap.json`; npm never publishes
   `package-lock.json`, so the shrinkwrap is the one that ships): every package entry as
   `{ name, version, resolved, integrity, direct, dev }`, canonically sorted,
   hash `sha256(canonicalJson(sbom))` (the Claim 26 primitive). The committed
   baseline `artifacts/sbom.json` is diffed by the gate: byte drift fails with
   the added/removed/changed list and instructions to regenerate the baseline
   and name the admission ADR in the same PR. The SBOM diff IS the dependency
   review gate — every dependency change becomes a reviewable artifact.
3. **Pinning with hash verification.** Exact versions only in `package.json`
   (range characters `^ ~ * > < x` refuse); every lockfile package entry must
   carry a `sha512-` integrity value; `resolved` must be
   `https://registry.npmjs.org/...`; the runtime dependency set must equal the
   code-enforced `ADMITTED_RUNTIME_DEPS` (`jose` — ADR-015, `postgres` —
   ADR-018). A new runtime dep fails the gate until an admission ADR and the
   allowlist change land in the same reviewed PR.
4. **Signed build manifest (SLSA-shaped provenance).** An Ed25519 signature
   (node:crypto — no dependency) over the canonical manifest
   `{ type, version, gitHead, source: { treeDigest }, dependencies:
   { sbomDigest, runtimeDeps }, gate: { typecheck, tests, supplyChain },
   issuedAt, issuedBy }`, written to `artifacts/build-manifest.json` +
   `.sig`. `build sign` runs the full gate (typecheck + tests +
   supply-chain gate) and refuses to sign on any failure. `build verify`
   recomputes both digests from the live repo, demands the recorded gate
   fields are `pass`, and verifies the signature fail-closed with distinct
   reasons (tampered payload / stale tree / stale dependencies / gate not
   passed / wrong key / missing manifest). Deploy discipline
   (DEPLOYMENT.md): verify before start.

Keys: `BUILD_SIGNING_PRIVATE_PEM` / `BUILD_SIGNING_PUBLIC_PEM` env vars (the
ADR-008 posture). `build keygen` writes dev keys to gitignored `.build-keys/`
and prints paths, never key material. No production key ships in this change:
issuing one is a key ceremony (DEPLOYMENT.md), and the unsigned interim state
is honest — the gate runs, the manifest is "not issued".

**Alternatives:**
- **Sigstore/cosign/in-toto/SLSA tooling** — rejected: runtime or CI
  dependencies that would fail the admission policy they exist to enforce.
  The manifest is deliberately ASL-SBOM-shaped and small; upgrading to
  standard formats is a mechanical rewrite when a verifier demands it.
- **CycloneDX/SPDX exact conformance** — the format was never the control;
  the diff and the signature are. Declaring conformance without the tooling
  would be an overclaim.
- **Digest the working tree bytes** — rejected: platform-dependent (CRLF),
  forgeable by a dirty tree, and not bound to a commit. Blob SHAs bind the
  git index.
- **Hash the lockfile only** — insufficient: it misses the source tree, which
  for a source-artifact project is the payload an attacker actually wants to
  modify.

**Reasoning:** The gate turns ADR-015's prose into checks that refuse. Each
violation names the dep and the rule; each refusal names the reason. The
manifest is the first artifact in the repo that binds "what the gate approved"
to "what is on disk" under a signature, which is the seam every later
supply-chain upgrade (CI provenance, transparency log, controlled update
channels H12) extends rather than replaces.

**Security implications:** Closes the enforcement gap between the admission
policy and the repository. Does NOT close: signing-key custody (env var,
known-gap #4 family), a maintainer with repo-write replacing the allowlist
and regenerating everything in one reviewed-but-coerced PR (the ADR-015
"trusted maintainer" residual), or a compromised machine running the gate.
The gate raises the cost of a malicious dependency from "edit a JSON file"
to "forge a reviewable diff AND land an ADR in the same PR".

**Tradeoffs:** One more pre-commit step (fast: fs reads + hashing). Exact
pins move update burden to humans (deliberate — every bump is a diff).
Signing requires the gate to run first (release-time cost, by design).

**Residual risk (ponytail):** signing key in an env var, no transparency log,
no CI — `ponytail: no CI in-repo; gate runs at pre-commit + release sign —
wire `npm run supply-chain` into CI when a pipeline exists; transparency-log
publication is H11/Stage-3`. Residual accepted: a trusted maintainer going
rogue (ROADMAP H10 residual) is unchanged by any software control here.

**Future migration path:** CI wiring; transparency-log publication of the
manifest + SBOM (H11); key custody per ADR-008; H12 consumes the manifest as
the update-verification primitive (signed updates verify the manifest
signature, not a hash somebody pasted in a chat).

---

## ADR-025: Secure updates — signed channel, anti-rollback mark, sticky canary (H12)

**Context:** H12. H10 (ADR-024) signs a build manifest, but nothing consumes
it as an *update* decision: there is no release channel, no persisted
high-water mark, and no rollout state. Any signed artifact from the past
verifies forever — an attacker who replayed an old, legitimately signed
release (or an old, hash-valid M11 policy bundle) would be refused by nothing.
ROADMAP records the failure modes outright: rollback to a vulnerable version,
unsigned update, update as remote code execution with high privilege. M18
(project-raven — a self-building agent that rewrites its own repo) has
"unsigned self-update is RCE by design" in its gate column pointing at H12.

**Decision:** Five controls, one module (`src/updates.ts`), zero new
dependencies, chained onto the H10 manifest.

1. **A signed update descriptor is the update artifact of record.**
   `{ type: 'asl-update', version: 1, releaseVersion, channel, stages,
   manifest, manifestSignature, issuedAt, issuedBy }`, Ed25519 over
   `canonicalJson(descriptor)` with the H10 release key. It embeds the build
   manifest and its H10 signature, so verification chains into
   `verifyManifest` — the live tree/SBOM digests and gate fields are
   recomputed, never trusted from the descriptor. `releaseVersion` is a
   monotonic integer (the M11 bundle pattern): ordering must be decidable
   offline, without a registry or semver comparator.
2. **Rollback prevention is a persisted high-water mark.** `UpdateState`
   (code-written only, atomic temp-file+rename so a crash cannot truncate
   it) records `highWaterMark`. `apply` requires
   `releaseVersion > highWaterMark` and raises it. A perfectly signed,
   perfectly stale descriptor is still refused (`rollback-blocked`) —
   signature validity and replay validity are separate checks, and only the
   conjunction applies. The mark never lowers.
3. **Emergency rollback exists, and is signed and single-use.** A rollback
   grant `{ type: 'asl-rollback-grant', version: 1, targetVersion,
   fromVersion, generation, reason, issuedAt, issuedBy }` signed with the
   release key moves `current` back only when `fromVersion` equals the
   current version **and** `generation` equals the state's monotonic
   `rollbackGeneration` — success increments it, so a used grant stays used
   even if its `fromVersion` becomes current again through another rollback
   (replay fails `grant-mismatch`). It never lowers `highWaterMark`: the
   version you rolled back *from* stays burned, so the emergency path cannot
   itself become the replay path. (Audit 01, 2026-10-01: the version match
   alone was replayable after re-arrival at `fromVersion`; the generation
   closes it.)
4. **Staged rollout with canary and sticky auto-halt.** The descriptor
   declares `stages` (ascending percentages; the first is the canary). `apply`
   installs and lands the rollout at canary; `promote` advances exactly one
   stage per explicit passing health signal; a failing signal marks the
   rollout `halted` and halted is sticky — only a new signed descriptor or a
   rollback grant resolves it. Nothing reaches `promoted` without an explicit
   pass. Cohort selection (which instances are the canary) is the deployer's;
   this module gates the promotion, not the scheduling.
5. **One fail-closed chain, distinct reasons.** structure → descriptor
   signature → inner manifest → anti-rollback → state write, each refusal
   named: `not-an-update`, `bad-stages`, `bad-version`, `bad-signature`,
   `no-verification-key`, `manifest-rejected:<inner>`, `rollback-blocked`,
   `not-a-rollback-grant`, `bad-grant-signature`, `grant-mismatch`,
   `halted`. Keys are the existing `BUILD_SIGNING_*` env vars — one release
   key signs builds and updates; key separation is a ceremony decision
   (ADR-008), not a code decision.

**Alternatives:**
- **Semver compare with a remote channel** — rejected: ordering needs a
  registry or a full comparator (a dependency or a bug surface), and there is
  no transport in this repo to host one. An integer mark is the M11 pattern
  and decides offline.
- **Verify signature only, no state** — this is exactly the H10 gap H12
  closes: signatures prove origin, not freshness. A valid old signature is
  the rollback attack.
- **Git-only rollback (`git revert` + re-sign)** — rejected: deployed
  instances need an *authorization* artifact they can verify, not an
  instruction to trust whatever is currently in the repo.
- **Built-in health probes / canary scheduler** — rejected: the repo is a
  single library-instance; inventing a probe registry and fleet scheduler
  with no fleet would be speculative machinery. The promotion gate takes an
  explicit health signal the caller supplies.
- **Lower the mark on rollback "to allow retry"** — rejected: that converts
  the emergency path into the replay path, the exact failure mode ROADMAP
  names. Retries use a new descriptor.

**Reasoning:** H10 proved *what* is running; H12 decides *whether it may
change*. The two signatures (descriptor, embedded manifest) make the chain
end in recomputed live digests, so verification never rests on a value
somebody transported. The high-water mark is the only mutable state, which
keeps the attack surface of the control itself to "one integer that never
goes down".

**Security implications:** Closes unsigned-update and rollback replay for
anything that adopts the seam (M18's raven updater is the first consumer).
Does NOT close: a *signed but malicious* release (ROADMAP's stated residual —
a compromised release key signs anything; custody is ADR-008/Stage-3 HSM),
a compromised machine applying a descriptor before this module sees it, or
truthfulness of the caller-supplied health signal (garbage-in on canary
promotion; per-instance attestation is a later seam).

**Tradeoffs:** One more state file per instance to custody and back up (lose
it and the mark resets — an attacker who can delete state can replay, which
is why the state path is code-written and the file must live on storage the
update process does not share write access with an untrusted tenant).
Sticky halt means a false-negative health signal stops rollout until a new
descriptor — deliberate: stopping is cheap, shipping is not.

**Residual risk (ponytail):** caller-supplied health signal, no transport,
one release key, no descriptor log — `ponytail: health is caller-supplied
bool and canary cohorts are the deployer's; wire per-instance attested
health and a descriptor transparency log when a second instance or a
release endpoint exists (H11/Stage-3)`. Residual accepted and named: a
signed-but-maintainer-rogue release (H10 residual, unchanged here).

**Future migration path:** remote channel transport + descriptor publication
when a release endpoint exists; separate update key after a key ceremony;
H11 anchoring of applied-descriptor records; M18 raven consumes
`verifyUpdate`/`applyUpdate` as its self-update gate.

---

## ADR-026: Incident response — kill switch, revocation channel, evidence preservation (H13)

**Context:** H13. ROADMAP names the failure modes under an active incident:
cannot revoke a session or a capability quickly; cannot freeze issuance; cannot
reconstruct what happened; cannot preserve evidence. Today: in-process
capability revocation is immediate (M4 `revoked` set, `capability-revoked`),
session revocation is immediate in-memory (M2), audit export is authorized and
offline-verifiable (M6), and the event chain is signed and anchored (M3). What
does not exist: a tenant/global kill switch, a freeze on issuance, cross-node
propagation (two processes sharing Postgres each keep their own in-memory
revocation set), bulk revocation, an incident preservation artifact, or an
answer to M6's silent 1000-event export cap. ADR-022 pulls H13 forward at
federation: control-plane dispatch and M18's unattended raven need an operator
kill switch that reaches a **running** node, not just the calling process.

**Decision:** One module pair — `src/incident.ts` (channel port + in-memory
backend + `IncidentService`) and `src/incident-store-pg.ts` (Postgres channel +
migration 4) — plus two chokepoint edits in `src/pdp.ts` and bulk methods on
`src/session-manager.ts`. Zero new runtime dependencies.

1. **The kill switch is one operator action enforced at the two chokepoints.**
   `IncidentService.engage(scope)` freezes issuance, revokes every registered
   capability in scope, and revokes sessions in scope. Freeze is checked in
   `AuthorizationService.evaluate()` first (deny with the distinct
   `denyReason: 'incident-frozen'`, ordinary decision event) and at the top of
   `issue()` (refusal + a `capability.issue` deny event, the H1 custody-refusal
   pattern). `lift` clears the freeze only: revoked capabilities stay revoked.
   Freeze is reversible; revocation is not.
2. **Revocation coordination is a separate multi-writer channel, not the event
   log.** The hash chain is single-writer by construction, and the kill switch
   must be publishable from an operator CLI process and from one node to
   another. `revocation_channel` (migration 4) is append-only
   (`app_rw` INSERT/SELECT, no UPDATE/DELETE grants) and carries records
   `{ seq, action, scope, tenantId?, targetId?, reason, at }` where action is
   `freeze | unfreeze | revoke-caps | revoke-sessions | revoke-cap |
   revoke-session`. It is control-plane data: no secrets, no claim content.
   The evidence of record stays each node's signed event log (the local
   `incident.engage` event; the resulting `incident-frozen` /
   `capability-revoked` deny events everywhere). The `RevocationChannel` port
   has an in-memory backend (default single node; a shared instance is the
   multi-node test seam) and a Postgres backend (the real multi-node/CLI
   story, live-tested only when `DATABASE_URL` exists).
3. **Propagation is pull-on-decision and bounded by the channel interval.**
   `IncidentService.sync(force)` pulls `since(cursor)` and applies records
   idempotently in seq order. `authorize` syncs throttled (default interval
   1000 ms — inside the ROADMAP ≤ 5 s target); `issue` syncs forced (issuance
   is rare and a post-freeze mint must not slip through a throttle window).
   A fresh node replays from cursor 0, so a restart reconstructs freeze state
   and revocations from the channel. A channel outage never blocks local
   enforcement: the failure is counted, surfaced in status, and recorded as
   `broadcastOk: false` on the engage event.
4. **Evidence preservation is a first-class artifact.** `IncidentService.
   preserve` pages the ordinary authorized audit export (page size 1000,
   cursor on seq — removing M6's silent truncation), verifies the slice
   offline with the event public key, checks the live global chain and the
   anchor head, writes an `ASL incident bundle v1` file (tenant, requested and
   actual seq bounds, events with signatures, head `previousHead`,
   `chainValid`, `anchorMatch`, `digest`), and appends one `incident.preserve`
   event carrying digest + head + counts only — never event content.
   `reconstruct` summarizes the same authorized slice: decision counts by
   reason and action, revocation/freeze events, actors, first/last timestamp.
5. **No new authority path.** Engage/lift/preserve/reconstruct call existing
   services (authorization, sessions, audit query); the CLI is an operator
   surface over the local world, and in Postgres mode its channel publish
   reaches the running node. No REST route is added until a client calls one
   (M17/M18 precedent).

**Alternatives:**
- **Ride the event log as the broadcast.** Rejected: the chain is
  single-writer, and a second writer racing the chain would corrupt the
  tamper-evidence that makes the log trustworthy. Revocation coordination and
  evidence are different planes; they stay separate.
- **Push (SSE/`LISTEN`/webhooks).** Rejected: a second process, a second
  runtime dependency surface, and a reconnect story for a target that 1 s
  polling already meets. Pull-on-decision has no daemon to keep alive.
- **Poll every request with no throttle.** Rejected: a DB round-trip per
  decision, for a state that changes in an incident. Throttled on the hot
  path, forced on issuance gets both latency bound and no throttled mint.
- **Durable local freeze state (a file).** Rejected: a second source of truth
  that can drift from the channel; the channel *is* the state, and cursor-0
  replay reconstructs it. The in-memory backend is explicitly single-node —
  restart durability is the Postgres channel's property, named as such.
- **Publish per-capability revocations to the channel.** Rejected: a
  kill-switch record should be one small control-plane row, not a fan-out of
  thousands; `revoke-caps` is scope-level and each node applies it to its own
  registry, so the node's local audit shows exactly what that node killed.
- **Unbounded export in M6's service.** Rejected: the M6 service boundary
  (≤ 1000 per page) is deliberate; H13 pages through it in `preserve` instead
  of weakening the service for every caller.
- **Sign the incident bundle with a separate key.** Rejected for now: the
  bundle's integrity chains back to the per-event signatures and the anchored
  head that are already verified inside it; a separate custody key is an
  ADR-008 ceremony, not a code decision.

**Reasoning:** Incident response is a *control*, and a control that cannot be
measured against a latency target is a promise. The design makes three
properties testable and distinct: the kill switch is immediate locally, the
broadcast is bounded cross-node, and the preserved artifact is independently
verifiable offline. It reuses what already exists (one issuance path, one
decision path, one authorized export) rather than inventing an emergency
authority path — the incident itself is exactly when a parallel path would be
abused.

**Security implications:** Closes the incident-response failure modes as
mechanisms: freeze + bulk revoke (tenant/global), cross-node propagation
within the poll bound, single-target revocation, restart reconstruction from
the channel, an unbounded-during-incident preservation artifact, and a
reconstruction summary. Does NOT close: a compromised operator with channel
write access (they can freeze legitimate work — denial of service is the
accepted H15 trade; make it loud), a channel outage wider than the sync
interval (bounded by polling, not prevented), or an incident that is faster
than the on-call human (the ROADMAP residual, unchanged).

**Tradeoffs:** One more Postgres table and one more in-memory map; a forced
channel read on issuance (rare path); the channel carries tenant ids and
operator reasons, so it must not carry secrets — reason text is operator-typed
and treated as non-secret. Frozen state on a single in-memory node is lost on
restart (documented; Postgres replay is the durable story). Local-first
engage means a channel outage still kills the local node and reports the
broadcast failure rather than refusing the operator's emergency action.

**Residual risk (ponytail):** poll-based propagation and a non-enforcing
remote client — `ponytail: pull-on-decision with a 1 s interval and a
Postgres channel; a push transport or a second-node integration test when a
real second node exists; the operator CLI mints audit.export authority for
preserve through the existing root path — split operator identity from root
when an operator service exists`. Residual accepted and named: an adversary
who can write the channel can freeze; incident response is slower than the
attack (ROADMAP H13 residual).

**Future migration path:** push/`LISTEN` transport and a dedicated operator
identity service; legal-hold/retention policies over the preservation
artifacts; H11 external anchoring of preserved bundle digests; federation
clients (M18+) consume the kill switch over the channel or a REST route when
one is actually needed.

**Addendum (session-audit fixes, 2026-10-01):** four corrections the same-day
audit proved by probe, all consistent with the decisions above:

1. **A rejected channel row never stalls the cursor.** `PostgresRevocationChannel.load`
   skips rows `parseChannelRow` refuses, records the rejection through
   `health()`, and advances `maxSeq` past them. The table is append-only, so
   without the skip one hostile (or future-version) row would halt all
   revocation propagation on every node forever.
2. **The global-incident evidence view is `tenantId: '*'`.** Global-scope
   events are recorded with `tenantId: ''` (no tenant owns them); `'*'`
   reaches exactly those events through the ordinary authorized window,
   gated by the caller's own tenant `audit.export` capability. Tenant
   isolation is unchanged — no other tenant's events are reachable.
3. **Filtered bundles record `contiguous: false`.** A slice of events with
   gaps (global view, or one tenant interleaved with another) cannot pass
   linkage verification. `preserve` records whether the slice is an unbroken
   chain; `verifyIncidentBundle` verifies contiguous slices with the full
   linkage walk and non-contiguous slices per-event (hash + signature + the
   recorded live-chain state + anchor head).
4. **Operator CLI commands build a bootstrap-free world** (`buildWorld({ bootstrap: false })`):
   `incident status|engage|lift|revoke-cap|revoke-session|preserve|report`
   must not mint fixture capabilities or append fixture events to a shared
   (Postgres) evidence chain, and refusals print a diagnosable line rather
   than a stack trace.

**Addendum 2 (audit follow-ups 10–19 + live-Postgres run, 2026-10-01):** the
remaining audit nit tickets and the first live run of migration 4:

1. **Single-target records are tenant-scoped.** `revoke-cap` applies the same
   `inScope` rule as `revoke-caps` (pdp.ts); a target registered to another
   tenant is skipped, an unregistered target is still revoked (revocation
   ahead of registration is the safe direction). `revokeCapability` refuses a
   locally registered tenant mismatch with `IncidentInputError` (audit 12).
2. **`flush()` awaits in-flight work.** The pool runs queries on separate
   connections, so a bare `SELECT 1` did not order behind a publish; the
   channel tracks pending inserts/refreshes and `flush()` awaits them before
   health is read. Without this the CLI's broadcast check could pass before a
   failed write surfaced (audit 19, live PG).
3. **Migration 4 grants the real sequence name.** `BIGSERIAL` on
   `revocation_channel.seq` names the sequence `revocation_channel_seq_seq`;
   the original `GRANT ... ON SEQUENCE revocation_channel_seq` aborted the
   migration on a live server (audit 19). The static DDL test now pins it.
4. **`grant()` stays the embedder rehydration seam.** It bypasses the
   issuance freeze and channel force-sync by design; `evaluate()` still
   refuses to use registered authority while frozen, and `lift` restores
   nothing revoked (audit 16, documented + regression-tested).
5. **The owner `DELETE /v1/sessions/:id` is node-local.** Cross-node session
   revocation is the incident path (`incident revoke-session`); the REST
   route does not publish to the channel (audit 13, named in DEPLOYMENT and
   the route's ceiling note).
6. **`benchmarks/results.json` is committed at milestone boundaries only**;
   a rerun for a local check leaves it uncommitted (audit 17). In PG mode the
   benchmark expects a fresh chain — on a reused database `auditCompleteness`
   exceeds 1 by construction (live-run observation, ticket 19).

---

## ADR-027: Fail-closed availability — loud degradation, observed health, clock guard (H15)

**Context:** H15. ROADMAP names the failure modes of the safety mechanisms
themselves: a broken policy engine, a full disk, or a closed evidence store
denies **everything, silently, per decision** — no health signal, no degraded
mode, no budget, no alerting, and no operator-visible difference from an
attack. The pieces that exist are partial: `idp-unavailable` + `IdPHealth`
(M2), `store-unavailable` + a per-deny warning for typed Postgres failures
(M12), `GET /healthz` → `{ idp, store }` (M14). Still silent or missing:
engine faults (`evaluation-error`, no health signal), non-typed store write
failures (`evidence-write-failure`, no aggregated health), a stalled or
non-monotonic clock (nothing — and expiry checks silently stop working, which
**widens authority**), a decision-latency budget, and alerting semantics.
Two ordering defects surfaced while mapping the seams: `issue()` registers
authority **before** appending its issuance event (a store outage leaves
unaudited authority live in the map), and a store outage during `IncidentService.
engage` aborts the kill switch mid-way (`freeze`'s evidence append throws
before `revokeAll` runs).

**Decision:** Degraded mode is explicit, per-dependency, deny-only, loud,
bounded, and recoverable. Zero new runtime dependencies.

1. **The degraded-mode matrix (deny-only — degradation never widens
   authority):**
   - **IdP unreachable** (unchanged, M2): unauthenticated principals deny
     `idp-unavailable`; `authorization`-kind bootstrap principals and
     principals holding valid auth contexts continue; `idp` status stays
     probe-based (`IdPHealth`).
   - **Store unavailable**: every decision that must be recorded denies —
     `store-unavailable` for a typed `StoreUnavailableError` (store down),
     `evidence-write-failure` for any other failed write. No decision is ever
     made unrecorded (invariant 7 is the fail-closed floor).
   - **Engine broken**: every capability-checked decision denies with the
     existing distinct `evaluation-error` reason; the health signal names the
     dependency (below), so no new union member is needed.
   - **Clock fault**: every decision denies `clock-unavailable` (new
     `DenyReason` member) — time-based checks (capability expiry, auth
     expiry, approval expiry) cannot be trusted, and a stalled clock must not
     silently extend authority past `expiresAt`.
2. **`HealthState` (`src/health.ts`) — observed, not probed.** The PDP marks
   `store` / `engine` / `clock` `ok | unavailable` from what it actually
   observes on the decision path (append succeeded/failed, engine
   returned/threw, clock read valid/faulted). Recovery is observed the same
   way — a working call marks the dependency `ok` again. Transitions emit one
   loud signal (default `process.emitWarning`), **once per transition** — the
   M12 per-deny warning becomes transition-based so an outage produces an
   alert, not thousands of lines (alert fatigue is silence). IdP health stays
   with `IdentityProvider` (probe-based, already operator-visible).
3. **`ClockGuard` (`src/health.ts`) — the clock is a dependency.** Wraps the
   decision clock. Lenient (default): a throw or non-finite reading is a
   clock fault. Trend detection (stall: wall frozen while an injected
   monotonic reference advances past `stallAfterMs`; backward jump) is
   enabled only when a monotonic source is supplied — deterministic test
   clocks legitimately freeze and travel backward, so trend detection is
   opt-in and cannot break the M10 false-denial budget. Production wiring:
   `new ClockGuard(Date.now, { monotonic: () => performance.now() })`.
   The guard is consulted once per decision (`authorize`, `queryAudit`) and
   per `issue`; a faulted read denies before any authority is examined.
4. **Evidence before authority.** `issue()` appends the issuance event first
   and registers the capability only after the append succeeds. A store
   outage refuses the mint loudly (typed refusal naming the store failure) —
   unaudited authority cannot exist (closes the ordering defect).
5. **The kill switch survives its own dependencies.** `engage` completes
   freeze + `revokeAll` + session revocation even when evidence appends fail
   (each safety action applies its state before its event; `revokeAll`
   continues past per-capability evidence failures instead of aborting the
   loop). Missed evidence is reported honestly (`evidenceRecorded: false` on
   the engage result), never silently dropped — local enforcement during an
   outage is the point.
6. **`GET /healthz` body → `{ idp, store, engine, clock }`** when a
   `HealthState` is wired (`RestApiDeps.health`); embedders without one keep
   the M14 `{ idp, store }` shape. Additive, no secrets, no internals.
7. **The decision-latency budget is measured, not assumed.** The benchmark
   measures `authorize()` p99 with persistence (SQLite-file `EventLog`) and
   without (in-memory `EventLog`) — `evidence.decisionLatencyP99WithPersistenceMs`
   / `evidence.decisionLatencyP99WithoutPersistenceMs`, two **advisory** SLO
   rows per ADR-014 (latency never fails the build on a noisy machine).
8. **Rate limiting stays deployment territory** — the named M14 non-goal is
   resolved as such: the REST seam binds loopback behind a deployment reverse
   proxy (DEPLOYMENT.md) that owns request rate limits; no in-process limiter
   is built (no client asks, zero-new-deps discipline). The in-process
   "budget" is the latency budget above plus the fail-closed deny floor.

**Alternatives:**
- **A distinct `engine-unavailable` reason.** Rejected: `evaluation-error`
  is already the distinct deny reason for a failed evaluation; the health
  signal carries the dependency identity. Split the reason later if
  operators need to alert on it separately.
- **Keep the per-deny `process.emitWarning` (M12 behavior).** Rejected: an
  outage emits one warning per denied decision — thousands of lines is
  alert fatigue, which is silence by another name. One loud event per
  transition (down and recovery) is the operator signal.
- **Always-on clock trend detection.** Rejected: deterministic test clocks
  (`createClock`) freeze by default and jump backward deliberately (H13
  replay tests); always-on detection would manufacture `clock-unavailable`
  denies and burn the M10 false-denial budget. Trend detection is opt-in via
  the injected monotonic source; the lenient guard (throw/NaN) is always on.
- **In-process token-bucket rate limiting at the REST seam.** Rejected:
  deployment territory (reverse proxy), no client has asked for it, and it
  would be a second enforcement point to keep consistent. Named ceiling.
- **Rollback of the registered capability when `issue()`'s append fails.**
  Rejected in favor of append-first ordering: rollback is a second failure
  path to get right; evidence-before-authority removes the window entirely.

**Reasoning:** Fail-closed is correct and incompressible — the fix is not to
deny less, it is to make the denial **distinguishable, observable, and
reversible**. Every fault class gets the same three-part contract: a deny with
its own reason, a health signal that fires on the transition (not per
decision), and automatic recovery the moment the dependency works again. The
two ordering defects are the same lesson as the matrix: safety mechanisms must
degrade the same way the decision path does — fail closed, complete what they
can, and report what they could not record.

**Residual risk (ponytail):** an adversary who can induce a dependency fault
still gets a denial of service (the accepted ROADMAP trade — loud, bounded,
recoverable); `HealthState` is in-memory (a restart resets to `ok` — the next
observed fault re-marks it, and `/healthz` + the warning stream are the live
signals); clock trend detection needs the embedder to wire the monotonic
source (named in DEPLOYMENT); rate limiting is the deployment's; the engine
fault reason stays shared with other evaluation errors (`ponytail:
evaluation-error covers engine faults; split engine-unavailable if operators
need per-dependency alerting — trigger: a real on-call rotation complaining`).

**Future migration path:** per-dependency alert routing off the transition
stream; a health event in the signed event log (currently the loud signal is
process warnings + `/healthz`, deliberately outside the evidence chain to keep
fault storms from flooding the chain); split `engine-unavailable` if needed.

---

## ADR-028: Short-lived credentials — enforce at the verification seam; workload identity is derived (H2)

**Context:** H2. ROADMAP names the credential failure modes: a leaked
long-lived token; clock skew extending life; a credential left in a crash dump
or an event payload. Test methodology: expiry fuzzing, credential-in-log
scanning, revocation-propagation tests. `IdentityProvider.verifyToken`
(`src/identity.ts`) is the single credential-accepting seam: `jose` verifies
signature/iss/aud and `exp` when present, produces an `AuthContext`, and the
PDP's one guard (`isAuthenticated`) rejects expired or missing auth (M2).
REST clients present IdP bearer tokens; the federation client's token lives in
a long-lived secrets posture (M17). H13 built the cross-node revocation channel
but it carries only capability/session/freeze records. Four gaps surfaced at
seam-mapping:

1. **No lifetime ceiling.** A correctly signed token with a year-long `exp` is
   accepted — ASL has no opinion on how long a credential may live. `exp - iat`
   is never inspected; an `exp`-less token skips jose's expiry check and only
   fails later at the PDP; a `jti`-less token is unrevecable.
2. **The skew tolerance is silently ignored.** `verifyOptions.clockToleranceSec`
   is not a `jose` option (`jose` expects `clockTolerance`), so the configured
   30 s default has never applied — effective tolerance is 0, and the config
   has no upper bound. TM-005's "clockTolerance is bounded" describes a config
   that does not work.
3. **Workload identity inherits the human's credential shape.**
   `IdentityProvider.sessionAgent` reuses the human's full `AuthContext`
   verbatim: the agent principal carries the human's `jti`, the full JWT
   payload in `claims`, and the human's full validity. There is no workload
   ceiling and no explicit derivation record.
4. **Token revocation is per-process in-memory only** (`revokedTokens` Set). A
   revoked token stays valid on every other node (and on this node after
   restart).

**Decision:** Short-lived credentials are enforced as a **verification
contract** at the single credential seam — ASL remains a verifier, never a
token issuer — and workload identity is derived, capped, and claim-minimal.
Zero new runtime dependencies (`jose` only).

1. **Admission contract (`validateTokenClaims`, pure + exported).** An accepted
   token MUST carry: `exp` finite number (seconds), `iat` finite number, `jti`
   non-empty string, `sub` non-empty string; lifetime `exp - iat > 0` and
   `<= maxTokenLifetimeSec` (default 3 600 s = 1 h; the configured ceiling is
   itself capped at 86 400 s = 24 h so "short-lived" cannot be configured
   away); `iat` not in the future beyond `clockToleranceSec`; not expired
   beyond tolerance. Missing/ill-typed claims return `undefined` — the same
   fail-closed value as a bad signature (REST stays
   `unauthenticated-principal`; no oracle). Internal rejection codes
   (`claims-lifetime-exceeds-ceiling`, …) exist for tests/operators and never
   carry claim values.
2. **Bounded tolerance, actually wired.** Fix the drift: pass `jose`'s real
   `clockTolerance` option from the same bounded config (default 30 s, hard
   cap 60 s; a config outside the bound throws `IdentityConfigError` at
   construction). Total accepted life is therefore
   `min(declared lifetime, maxTokenLifetimeSec) + clockToleranceSec`.
   Authenticated NTP stays the assumption; the H15 `ClockGuard` stays the
   PDP-side stall/backjump detector.
3. **Workload identity is derived, never a global credential.**
   `IdentityProvider.workloadAuth(parent, workloadId, now, { maxLifetimeSec?
   = 900 })` mints an `AuthContext` from an already-verified parent with a
   distinct `subject`, `tokenId = wl:<workloadId>:<parentJti>` (derivation
   lineage), `issuedAt = now`, `expiresAt = min(parent.expiresAt, now +
   ceiling)`, `amr: []`, `claims: {}` (never the parent's raw payload), and an
   explicit `derivedFrom` marker. `sessionAgent` routes through it: an agent
   cannot outlive the launching session or the workload ceiling and cannot
   carry the human's payload. The PDP guard is unchanged — a derived context
   still has to be unexpired.
4. **Revocation propagates on the H13 channel.** New `revoke-token` record
   action. `IdentityProvider.attachRevocationFeed(feed)` pulls records on each
   `verifyToken` with its own monotonic cursor (throttled, default 1 s, forced
   on first call) and adds `targetId` to the revoked set —
   `IncidentService.revokeToken(jti, tenantId, reason, actor)` applies
   local-first when an `identity` (`TokenRevoker`) is wired, then publishes,
   then audits (`incident.revoke`); `applyRecord` routes incoming
   `revoke-token` records to the local IdP when wired. Because `jti` is
   required, every accepted credential has a revocation handle; propagation is
   bounded by the poll interval (H13's ≤ 5 s target), and a node that has not
   synced still rejects what it revoked locally.
5. **Credential hygiene.** The raw token string is never stored on
   `AuthContext`; derived contexts carry no parent payload; event metadata
   carries only the `jti` identifier (like session ids today); rejection
   reasons and config errors carry limit numbers, never claim values. Tests
   scan the full event log for the raw token on both success and failure
   paths.

**Alternatives:**
- **ASL as a local token issuer / client-credentials broker.** Rejected:
  creates a second trust root and a key-custody problem where the IdP already
  is the issuer; ASL verifies, it does not mint identity (ADR-022: "ASL never
  mints authority itself").
- **SPIFFE/SPIRE workload identity (ADR-016's deferred path).** Still
  deferred: requires attestation infrastructure, not a zero-dependency
  change; named in the H2 skip list. Derived workload identity closes the
  "global credential" gap without pretending to be platform attestation.
- **mTLS / `private_key_jwt` client authentication.** Transport/IdP-side
  work; skip list.
- **IdP introspection per request (RFC 7662).** A network hop on the
  verification path and an availability coupling; the H13 channel already
  gives bounded propagation.
- **Clamp tolerance to zero (today's effective behavior).** Rejected: real
  deployments have clock skew; a bounded 30 s default (60 s cap) is standard
  and now actually applied. The lifetime ceiling is unaffected by tolerance.
- **Tenant-scoped token revocation.** A `jti` has no tenant until principal
  resolution; the trust domain is the IdP issuer/audience, so a `revoke-token`
  record applies deployment-wide. The record's `tenantId` is coordination and
  evidence metadata.
- **Require `auth_time`/MFA on workloads.** Wrong axis: approvals already
  require an authenticated MFA human; workloads never approve.

**Reasoning:** The verifier decides what it honors, regardless of what the IdP
is willing to issue. A short ceiling makes leakage bounded; a revocation
channel makes the residual window interruptible; a bounded skew makes both
claims true rather than aspirational; a derived workload identity keeps
non-human principals from inheriting human credential material. The mechanism
is deliberately verification-side: no new trust root, no IdP changes, no new
dependencies. Honest boundary: an attacker who can forge tokens with a
compromised IdP key is unaffected by this ADR (M2's accepted trade).

**Residual risk (ponytail):** the window of validity (≤ 1 h default) and
in-memory exposure during token processing are the ROADMAP residuals; an
attacker holding a valid short-lived token can replay it until expiry unless
its `jti` is revoked; revocation is poll-based (a channel outage widens the
window but never extends a token's own expiry); the revoked set is in-memory
per process (the Postgres channel records are the durable coordination path,
replayed through the feed cursor on nodes that attach it); `jti`/`sub`/`iat`
are now required claims, so an IdP that omits them needs configuration
(`ponytail: strict claim contract; add a configurable claims profile if a
real IdP cannot supply exp/iat/jti/sub — trigger: a deployment whose IdP
cannot`); IdP-side issuance (client-credentials flows for services) is
deployment configuration, not ASL code.

**Future migration path:** SPIFFE/SPIRE or platform workload attestation when
infrastructure exists; durable per-token revocation storage (the Postgres
channel is the current answer); introspection / CAEP push for sub-second
revocation; hardware-backed IdP keys (ADR-016); pin the JWKS source (TM-005
residual).

---

## ADR-029: M18 federation — project-raven: local verified update, sandbox-local self-build, device principal, offline-first

**Context:** M18. Raven is an always-on agent (WSL VM today, Pi later) whose
`raven-builder.path` triggers a headless OpenCode self-build on a
`builder/<ts>` branch inside a systemd sandbox (tickets 21/23: `conf/` and
`secrets/` hidden, `memory/` read-only, integrity manifest, timeout, never
`main`). Its upgrade path has **no network remote**: hosts sync from the
Windows checkout through a local `win` remote
(`git fetch win && git reset --hard win/main && git clean -fd`) with **no
verification of what is fetched** — the exact RCE path ADR-022 names. Raven
has zero ASL contact points today. H10/H12 (signed manifest + update
descriptor, anti-rollback), H13/H15 (kill switch, degraded modes), and H2
(ADR-028: verification-seam credential contract) have landed. Raven is a
personal tenant, so ADR-022's H8 gate does not apply.

**Decision:** Four parts; the ASL side stays consume-only (issuing tooling
only, no new REST surface).

1. **The update check runs locally, before `reset --hard`; ASL is the issuing
   plane.** At release points the operator issues a signed update descriptor
   (H12 format) embedding the H10 build manifest (source `treeDigest`, SBOM
   digest, gate fields) for raven's tree, and commits it **into the tree it
   describes** (descriptor path excluded from the digest, like `artifacts/` in
   ASL). The descriptor therefore distributes atomically with the commit via
   the existing `win` fetch — no new distribution channel. Raven's upgrade
   flow becomes: `git fetch win` → compute the tree digest **of the fetched
   `win/main` commit** (`git ls-tree`, blob SHAs — no checkout) → verify the
   descriptor signature against the release public key pinned in `conf/env`
   (`RAVEN_UPDATE_PUBKEY`), the descriptor→manifest chain, the manifest gate
   fields, the digest match, and the anti-rollback high-water mark
   (`run/update-state.json`) → only then `reset --hard` + `git clean -fd`.
   Any failure refuses the update and leaves the running tree untouched
   (fail closed; logged loudly). Node is required for verification (present
   where the builder runs); a host without it refuses updates until
   provisioned — never silently skips the check.
2. **Self-build stays sandbox-local; no new ASL REST sandbox route.** The
   ticket-23 systemd sandbox is the M16-equivalent constraint set. Phase 2
   adds local, reviewer-readable evidence to `run/builder.log` (task digest,
   before/after tree state, exit) — an ASL anchor of builder evidence is
   deferred until raven actually calls an ASL feature (M17-pattern anchoring
   when the thin client lands; the prompt's skip list already names the REST
   sandbox-exec route).
3. **Raven's principal: one tenant, `device:raven-<host>`, and no ASL
   credential is needed for the update path (it is fully local).** When the
   first ASL-calling feature lands, raven registers as that device principal
   and presents IdP-issued short-lived bearer tokens satisfying ADR-028's
   admission contract; until the IdP client-credentials flow exists
   (ADR-028's skip list / deployment work), a static device secret is the
   documented residual — the federation table already flags "static device
   key (H2)". No authority without a human: the builder never merges
   (`builder/` branches are reviewed), and updates apply only whole-tree
   states from the human-controlled Windows checkout.
4. **Offline-first, never brick.** The update path makes no ASL call, so ASL
   availability cannot affect it; verification failure stops the update, not
   the agent (H15's degrade-loudly shape at raven scale). Future
   ASL-dependent features follow the same rule: unavailability blocks only
   that feature, loudly.

**Alternatives:**
- **ASL returns a verification verdict over REST.** Rejected: the tree check
  must run against the host's fetched tree; a remote verdict about an unseen
  tree is faith, not verification. It would also add an availability coupling
  for zero benefit — raven has no ASL contact today.
- **Copy-sync with checksums.** Rejected: checksums are integrity, not
  authenticity — the exact gap ADR-022 names.
- **Signed git tags / `git verify-commit`.** Considered: reuses git's own
  machinery, but bolts a second signing-key system onto a pipeline whose
  release artifacts are already ASL manifests (treeDigest/SBOM/gate fields),
  and raven fetches from a local checkout, not a tag-pushing remote. Not
  chosen; revisit if a network remote appears.
- **ASL-hosted release channel (raven pulls descriptors from ASL).** Rejected:
  no network remote exists today; a descriptor committed in-tree is atomic
  with the tree it describes and survives offline.
- **Wire ASL anchor for builder evidence now.** Rejected (YAGNI): no client
  calls one; the local reviewable log is the evidence until the thin client
  lands.

**Reasoning:** One trust anchor (the release key) and one parity contract (the
tree-digest canonical form). The digest is computed where the tree lands; the
descriptor travels with the tree; the refusal is fail-closed; the running
agent is never bricked. Everything else — ASL anchors, workload credentials,
ASL dispatch — is deliberately deferred until raven actually calls ASL.

**Residual risk (ponytail):** the release key sits in raven's `conf/env`
(host compromise = key compromise; ADR-008/ADR-025 custody is the upgrade);
descriptor-in-tree means a repo writer without the release key cannot produce
a verifiable release (intended), while a compromised Windows checkout plus a
stolen key forges releases (the unchanged H10/H12 accepted trade); Node is a
verification prerequisite on the host; the builder remains a self-edit lane
whose control is human review of `builder/` branches plus the sandbox; Pi
support is untested (WSL VM is the proven host).

**Future migration path:** `git verify-commit`-style simplification or an
ASL-hosted channel once a network remote exists; ADR-028 credentials when
raven first calls ASL; M17-pattern anchoring of builder evidence; Pi
verification parity; hardware-backed release keys (Stage 3).

---

## ADR-030: Cross-tenant isolation — one probe over every surface; a v2 evidence key opens only for its tenant (H8)

**Context:** H8 (ROADMAP Stage 2) is the federation gate (ADR-022): before any
non-personal tenant joins, cross-tenant isolation must close or its residual be
explicitly accepted per deployment. Much of the surface already exists — the
PDP tenant guard (`resource.tenantId === principal.tenantId`, evaluated before
policy), tenant-bound capabilities, tenant-scoped audit query/export and REST
routes (M14/M17), and, in Postgres mode only, `FORCE ROW LEVEL SECURITY` plus
per-tenant evidence keys (`evidence-key:v2:<tenant>:<level>`, M12). SQLite mode
stays app-level. The shared PROCESS remains in both modes (known-gap #7):
logical isolation only, one memory-safety bug crosses every boundary. Physical
isolation (microVM/process-per-tenant) is Stage 3. What did not exist was one
automated, table-driven cross-tenant probe over the whole current surface —
and the probe finds two real gaps:

1. **`AuthorizationService.revealEvidence` was not bound to the sealed key's
   tenant.** A v2 keyId names its tenant, but `revealEvidence` derived only the
   classification from the keyId and returned `open(sealed)`, dispatching the
   key derivation on whatever `sealed.keyId` said. It lazily registered an
   unknown keyId as a `'system'` resource under the CALLER's tenant. Capability
   resource ids are opaque strings, so a tenant-A root could mint a capability
   naming tenant B's keyId (`evidence-key:v2:B:<level>`); the tenant check then
   saw a resource bound to A, the capability matched, and the HKDF derivation
   from the keyId decrypted B's content. Probe-proven before the fix: an `acme`
   auditor capability naming `evidence-key:v2:globex:confidential` read a
   globex seal and bound the globex key to `acme` in the registry.
2. **`CapabilityRequestService.approve`/`deny` had no reviewer-tenant
   predicate.** The REST boundary checked it, so the HTTP surface was safe; the
   in-process decision surface (the M4 service itself — an embedder API and the
   guard's escalation lane) would let a tenant-B user approve a tenant-A
   request and record a B reviewer on an A approval. Probe-proven before the
   fix.

**Decision:**

1. **The milestone artifact is one reusable, table-driven cross-tenant probe**
   (`tests/h8-cross-tenant-probe.test.ts`): every REST route (authorize,
   sessions, capability requests, audit, tasks, anchors, healthz, static pages)
   and every in-process query surface (audit query/export, event-store reads,
   registry, sessions, capability requests, persistence). Each row asserts one
   of: (a) isolation in both directions, (b) a log-scan property (no foreign
   tenant marker or content in the caller's visible records or responses), or
   (c) a named `global-by-design` exposure. Postgres-gated rows skip cleanly
   without `DATABASE_URL`. A new tenant-facing surface MUST add a row; a
   surface without a row is unproven.
2. **Cryptographic isolation is key-binding at the evidence seam.** A v2 keyId
   may only be decrypted by the tenant it names. `revealEvidence` refuses a
   foreign keyId before any registration or authorization, records one clean
   deny event in the caller's own tenant (without naming the foreign key), and
   opens with `openFor(principal.tenantId, …)` as a second binding.
   `tenantFromKeyId` is the new seal helper (`src/seal.ts`). Legacy
   `evidence-key:<level>` seals keep their documented tenant-agnostic behavior
   — no silent re-encryption.
3. **Approval tenancy is enforced at the decision surface.** `approve`/`deny`
   refuse a reviewer whose tenant differs from the request's, not only at the
   HTTP boundary. The refusal is thrown before any event append, so a rejected
   cross-tenant review writes nothing into the request's tenant log.
4. **Named global-by-design surfaces** (never tenant-facing; no REST route
   exposes them): the single evidence chain (`all`, `bundle`, `verify`, and
   chain-slice verification — one signer, world-order seq, needed for
   resume/verify), and the embedder/operator views (`ResourceRegistry.list()`
   with no tenant, `SessionManager.all`, `CapabilityRequestService.all`).
   Deny/decision events may name the attempted foreign resource or action —
   that is the caller's own audit record, not the other tenant's data.
5. **SQLite mode stays app-level; Postgres mode keeps database-enforced RLS
   and per-tenant keys.** No new runtime dependency, no new service, no new
   REST surface.

**Alternatives:**
- **Per-tenant processes now (finish H8 physically).** Rejected: physical
  isolation is Stage 3 (microVM, no shared kernel) and depends on the
  container/microVM track; pulling it forward would delay the software-boundary
  probe and the two fixes. The shared-process residual is named, not hidden.
- **Rely on key possession alone (the keyId is public in the event metadata,
  so the master-key holder can always derive).** Rejected as the only control:
  the process holds the master key in both modes by design, so decryption must
  be bound by authorization; the keyId-to-tenant binding is the enforceable
  half, and it is now checked before authorization instead of after.
- **Optional tenant parameter on low-level helpers (`SessionManager.get`,
  `activeSessionsFor`, `registry.get`).** Rejected: an optional check is not a
  boundary. The enforced boundary is the route/service that may expose them;
  low-level views stay named and non-tenant-facing.
- **One probe per milestone suite instead of one table.** Rejected: coverage
  becomes unknowable; the H8 failure mode "a query missing a tenant predicate"
  is exactly what a surface table prevents.

**Reasoning:** H8's honest scope is not new isolation architecture; it is
proving the isolation contract of the surface that exists and closing what the
proof finds. The probe is the same pattern as the rest of the repo — one
enumerable table, each row bound to an assertion, no claim without a case. The
two fixes are both "a check that was assumed to exist at the wrong layer":
key-tenant binding was assumed to follow from the keyId shape (it did not),
and reviewer-tenant binding was assumed to be the route's job (it was, for the
route only). Both are now at the decision seam, with the probe as the
regression test. The process-boundary residual is not new and not closable in
this milestone; it stays visible in Claim 9, CURRENT_STATE known-gap #7, and
the THREAT_MODEL cross-tenant row.

**Security implications:** Closes one real cross-tenant evidence-decryption
path (probe-proven) and one cross-tenant approval path, and turns cross-tenant
coverage into an inspectable table. Does NOT close: the shared process (both
modes), SQLite's app-level-only checks, hardware side channels, or hypervisor
bugs. The per-tenant Postgres keys and RLS are unchanged.

**Tradeoffs:** Test-only code growth (the probe suite); Postgres rows skip
without a database; a cross-tenant `revealEvidence` now produces one clean
deny event in the caller's tenant instead of a possibly-allowing authorize
event. No production dependency, schema, or API change.

**Residual risk (ponytail):** accepted and named, per deployment:
- **Shared process memory, both modes (known-gap #7).** A memory-disclosure or
  serialization bug crosses the boundary; Stage 3 physical isolation is the
  structural fix.
- **SQLite mode is app-level only.** No database-enforced RLS; the PDP and
  service checks are the control (parity-tested).
- **Hardware-level side channels and hypervisor bugs** (the ROADMAP H8
  residual) are outside software control.
- **Principal ids are not enforced globally unique.** `capabilitiesFor(principalId)`
  may return a colliding tenant's capability; every authorization path
  re-checks capability tenant in `verifyCapability`, and the only non-PDP
  consumer (`deriveClassification`) is monotone-raise (conservative). Named,
  not tenant-facing.
- **`SessionManager.get`/`activeSessionsFor`/`revokeAllFor(principalId)`** are
  principal-id-keyed without a tenant predicate; the REST route owns the tenant
  check and no tenant-facing surface calls them. Revisit when an operator
  surface uses them.
- **One `CapabilityRequestService` per root.** Approving a request from a
  tenant other than the root's fails closed (`issuer may not mint capabilities
  in another tenant`); a multi-tenant deployment needs one service/root per
  tenant (or a per-tenant root resolver). Functional, fail-closed, not a leak.
- **The probe proves absence of the markers it plants**, not absence of
  unknown leak channels; continuous adversarial evaluation is H14.
- **BYOK/HYOK, cross-domain transfer, and physical controls** remain Stage 3+
  and are untouched.

**Future migration path:** each new tenant-facing surface adds a probe row (a
review condition, like a new security invariant); Stage 3 physical isolation
lands under the same probe, which becomes its software regression suite;
tenant-scoped low-level session/registry helpers when an operator surface
needs them; a per-tenant `CapabilityRequestService` root resolver for
multi-tenant capability-request deployments.

**Addendum (executed 2026-10-03):** the probe landed first and captured red at
`.scratch/h8/red.txt` (three failing assertions: the cross-tenant decrypt
returned the globex plaintext, the cross-tenant approval was accepted, and the
seal-test extension failed on the same decrypt), then the two fixes above.
`tests/h8-cross-tenant-probe.test.ts` (22: 8 REST, 12 in-process,
2 Postgres-gated skips) + the `tests/evidence.test.ts` extension (1). Gate:
`npm run typecheck` clean; `npm test` 676 / 655 pass / 0 fail / 21
Postgres-mode skips (baseline 653/634/19). The Postgres-gated rows follow the
M12 scratch-database convention and were not run live this session (no
`DATABASE_URL`). Branch `feat/h8-cross-tenant-isolation`, ADR commit
`5a86157`.

---

## ADR-031: Tamper-evident evidence — external anchors, operator-held checkpoints, recorded legal holds (H11)

**Context:** M3 closed the in-process half of evidence hardening: a SHA-256
hash chain over canonical event bodies, per-event Ed25519 signatures, an
append-only SQLite store (BEFORE UPDATE/DELETE triggers), a `<seq>:<eventHash>`
anchor file, and an offline `verifyBundle()`. Claim 8 names the residual
plainly: the anchor file lives **inside the runtime's trust domain**, so an
attacker with host access and the signing key can rewrite the store and the
anchor consistently — the M3 anchor is a witness only if it lives somewhere the
attacker does not control. ROADMAP H11 lists the failure modes that remain:
whole-log rewrite, anchor collusion, clock manipulation, selective deletion,
with the assumption "at least one append-only store the runtime cannot
rewrite" and the test methodology "anchor consistency checks; verifier against
adversarially rewritten logs; retention and legal-hold tests". M17 added the
reverse direction — federation clients anchor their head-hashes INTO this plane
(`POST /v1/anchors`) — but its `AnchorRegistry` keeps the accepted head
in memory (an explicit ponytail marker: a restart cannot distinguish "first
anchor" from "lost predecessor"). There is no source reconciliation anywhere:
one anchor file, one reader, no fork detection, no operator-held proof, no
recorded legal hold.

**Decision:**

1. **Anchor sinks are a port; the M3 file is one sink.** `AnchorSink`
   (`name`, `publish(point)`, optional `flush()`, `status()`) and
   `AnchorPublisher` (fan-out with per-sink isolation — a throwing sink must
   not break an evidence append). `FileAnchorSink` keeps the exact M3 format
   and stays synchronous. A new `HttpAnchorSink` POSTs
   `{ version, kind: 'asl-anchor-head', seq, headHash, eventCount, sentAt }`
   to an operator-configured URL with an optional bearer token (env; never
   logged). Publication is **non-blocking**: a bounded queue, kick on publish,
   explicit `flush()`, loud `published/failed/dropped/lastError` counters —
   no timers, no process kept alive by a dead witness. The witness is a
   detection surface, not a decision-path dependency, so it does not block
   appends (availability) and does not join H15's `HealthState`; its status is
   operator-inspectable (`evidence status`) and its failures are counted, not
   silent.
2. **The verifier reconciles sources.** `verifyAnchoredEvidence(bundle,
   { sources, checkpoint?, publicKey? })` parses every source, enforces
   monotone contiguous sequence numbers within a source, binds each line to
   the event at its seq, requires at least one source to anchor the bundle
   head, treats any source **ahead** of the bundle head as tail truncation,
   and reports two sources disagreeing at one seq as a **fork** — the
   anchor-collusion signal. A bundle without any source is reported
   `unanchored: true`, never silently "anchored".
3. **Operator-held checkpoints are the offline external witness.**
   `asl-anchor-checkpoint` is an Ed25519-signed (existing event key — no new
   key) JSON record `{ version, seq, headHash, eventCount, createdAt,
   previousCheckpointDigest, signature }`. `verifyCheckpoint` refuses a
   rewritten chain (the event at that seq hashes differently), a truncated
   chain (checkpoint seq beyond the chain), a broken checkpoint chain
   (previous digest mismatch, or the same seq with a different hash = fork),
   and a bad signature. A checkpoint file the operator takes off-host
   satisfies H11's assumption without requiring a live service.
4. **The federation anchor registry becomes durable.** `AnchorRegistry`
   replays `anchor.register` events in the constructor; the accepted head per
   tenant survives restart, so a client's claimed previous head is still
   checked against history. The event log is already the durable record — no
   new table.
5. **Clock manipulation is detected, not prevented.** Timestamps are part of
   the signed/hashed body, so any edit breaks hash + signature; verification
   additionally reports timestamp regressions as anomalies (non-fatal — an
   NTP step is not an attack) and witness records carry the witness's own
   `receivedAt`. H15's `ClockGuard` remains the runtime control; H11 adds no
   clock authority.
6. **Retention is structural; legal holds are signed evidence.**
   `evidence.hold` / `evidence.release` are ordinary signed events (new
   `KnownAction`s); `RetentionLedger` replays them (durable, restart-safe) and
   answers `isHeld(tenant, seq)` / `activeHolds(tenant)`. No prune path
   exists at any layer today (API surface, SQLite triggers, Postgres
   triggers), and that is the retention control: the ledger is the contract a
   future prune/archive-purge tool must consult, and the structural tests
   (no delete/update method; storage-layer DELETE aborts) are its
   enforcement.

**Alternatives:**
- **Block appends until the external witness acknowledges.** Rejected: it
  couples evidence to witness availability and turns a detection mechanism
  into a DoS chokepoint; H15's direction is loud degradation, not silent
  failure — and a witness that is behind still detects truncation at its last
  published head.
- **A hosted transparency-log service in-repo.** Rejected: no service exists
  and running one is deployment territory; the ADR fixes the protocol seam
  (`POST` head, `GET` heads) so any operator-hosted sink (WORM bucket
  front-end, transparency log) is a configuration, not a code change.
- **Treat a second local file as "external".** Rejected: same trust domain —
  an attacker with host access rewrites both. The honest external witnesses
  are the operator-held checkpoint and the network sink.
- **Persist the federation accepted heads to a table.** Rejected: the signed
  `anchor.register` events already are the durable record; replay keeps the
  single-writer chain as the one source of truth and avoids a second
  consistency story.
- **Enforce timestamp monotonicity as validity.** Rejected: a legitimate
  clock step would invalidate an untampered log; the verifier reports the
  anomaly and the chain/signature remain the controls.
- **Prune/compact old evidence under retention windows.** Rejected for H11:
  adding the first deletion path to an append-only plane to test the hold is
  backwards; the hold ledger and structural no-delete tests establish the
  contract, and a future archive tool is its consumer.

**Reasoning:** H11's remaining gap is a trust-domain problem, not a hashing
problem. The M3 primitives are correct; what is missing is a witness the
runtime cannot rewrite and the reconciliation logic that makes multiple
witnesses analytically useful. The design keeps every new piece on the
evidence-side seam (sinks, verifier, checkpoints, holds) and adds zero
authority: checkpoints sign with the existing event key, holds are operator
events in the existing log, and the witness is an operator-configured
destination. The milestone also closes the one M17 ponytail marker on the
inbound federation path (in-memory accepted heads). The structural retention
posture is stated as what it is: today nothing deletes, so the hold's
enforcement is the absence of a deletion path plus storage-level triggers;
the ledger makes the legal-hold claim a recorded fact instead of an
implication.

**Security implications:** closes Claim 8's residual **when at least one sink
or checkpoint lives outside the runtime's trust domain** — a rewritten or
truncated store is then caught by reconciliation even if the attacker holds
the signing key. Adds fork detection (anchor collusion between sources) and a
durable federation anchor history. Does NOT close: an attacker who controls
both the store and *every* sink (for example, the witness operator colludes);
compromised signing-key custody (ADR-008, unchanged); hardware WORM/HSM
attestation (HARD stage); a malicious operator who never takes a checkpoint.
The witness POST is new operator-configured egress from the evidence path;
the token is env-only and redacted from all output.

**Tradeoffs:** the witness sink is best-effort, so detection granularity
degrades while it is down (counted, not silent); a bounded queue drops the
oldest pending points under prolonged outage (the newest head still proves
truncation for everything before it); checkpoints are manual operator steps;
hold events are append-only facts whose release is itself an event (no
history is rewritten). No new runtime dependency, no schema change, no
decision-path change.

**Residual risk (ponytail):** accepted and named:
- **Host attacker + all witnesses compromised.** If the attacker can rewrite
  the store, the anchor file, the witness records, and the operator's
  checkpoint, there is no detection left — that is H11's named residual
  ("an attacker who controls both the log and the anchor").
- **Witness operator collusion / split-view.** Two colluding witnesses can
  present consistent lies; reconciliation detects disagreement, not a
  coordinated false view. Multi-party public transparency logs are the HARD
  upgrade.
- **Signing-key custody** stays environment/ADR-008; key rotation requires
  re-signing history (unchanged from ADR-013/Claim 8).
- **Clock claims** are claims: regression reporting is heuristic; the
  authoritative time is whichever witness/checkpoint the operator holds.
- **No prune exists**, so the legal-hold ledger is currently enforced by
  construction plus its tests, not by a live prune gate.

**Future migration path:** point `EVENT_ANCHOR_WITNESS_URL` at an
operator-hosted transparency log or WORM front-end; batch witness publishes
if volume grows; a hosted witness service is a separate deployment artifact;
prune/archive tooling (if ever built) must consume `RetentionLedger.isHeld`
and add its own structural tests; checkpoint chaining is the seed for
publication to third-party logs.

---

## ADR-032: LAS vehicle seams — device/service principals, a status/evidence feed, tailnet service auth (scope note)

**Context:** The `local-ai-system` (LAS) program assembles ASL, ctxd, kgp,
eyewright, orbit + supervisor, control-plane, creative-OS, engineering-OS,
project-raven, and home-agent into one system (LAS ADR-0006: LAS is the
assembly; ASL is **cross-cutting**, not a layer). ADR-022's federation model
defines how ASL serves state-plane clients over the M14 REST seam; it does not
name the seams the *assembled* vehicle exposes — one place, one identity, local
services reached over a tailnet, and a cockpit that reads state from every
piece. This ADR is a **scope note**: it records what ASL will grow when the car
needs it, so no LAS-motivated ASL feature is built speculatively, and so the
boundary is written down before the code exists.

**Decision:**

1. **Boundary rule from ASL's side (mirrors ADR-0006).** ASL owns **authority,
   keys, gates, evidence, and incident response** outright, and holds **final
   say — veto + notary** — wherever another piece's decision could violate
   those. ASL **never orchestrates**; it does not schedule, budget, route,
   store knowledge, decide truth, or delete data. One accountable boss per
   concern at the point of action; joint custody is normal. Deletion is the
   worked example: the data owner deletes (kgp corpus, ctxd ledger); ASL vetoes
   via a legal hold and notarizes the purge certificate.
2. **Vehicle seams (build each only when the car exposes it; each lands as its
   own milestone/ADR with tests — nothing here is a commitment to code now):**
   - **Device/service principals.** A local machine/service identity — the Pi 5
     node, supervisor-launched services (eyewright, `laya-serve`), and tailnet
     clients — derived the way ADR-028 derives workload identity (capped,
     claim-minimal, short-lived), extending ADR-029's device-principal seed.
     Every service caller authenticates; no ambient authority.
   - **Unified status/evidence feed.** One read-only projection for the cockpit:
     health across pieces (`/healthz` + eyewright's `/health/deep` + the
     supervisor + ctxd/kgp), the evidence head, active holds, and incidents. It
     is a **projection over existing** health/audit/anchor surfaces, not a new
     store and not a second evidence plane.
   - **Tailnet service auth.** LAS surfaces bind locally and are exposed over
     Tailscale (the control-plane/home-agent pattern). Services validate
     ASL-issued short-lived credentials; TLS terminates at the tailnet. ASL is
     the **verifier**, never the transport.
3. **Non-goals (explicit).** ASL does not become the orchestrator (ctxd/orbit
   do), the knowledge store (kgp), the truth gate (eyewright), or the service
   manager (the supervisor). Anchoring stays the integration primitive: ctxd
   ledger heads and eyewright verdicts are attested via the M17 anchor pattern
   / H11 checkpoints, not copied into a shared store. No new runtime dependency
   is implied by this ADR.

**Alternatives:**
- **Make ASL the hub/orchestrator.** Rejected: violates one-enforcement-plane
  (ADR-022), couples system availability to the security plane, and duplicates
  ctxd/orbit scheduling.
- **Absorb ctxd's ledger into ASL's EventLog.** Rejected: different volume,
  tiering, and lifecycle; the ledger is an operational trace and a training
  set, not the canonical attestation chain. Anchor heads instead (M17/M20
  pattern).
- **Per-piece bespoke identity.** Rejected: N trust stories; M2/ADR-016/ADR-028
  already centralize verification, and H8's probe already covers the surfaces.
- **A new LAS service manager beside the supervisor.** Rejected: orbit's
  `services.json`/`svcwatch` already exist and are generic; extend, don't fork.

**Reasoning:** The car needs a safety system that is everywhere and in charge
of nothing but safety. Writing the seams down now (a) keeps ASL's roadmap
honest — it grows device principals/auth/status only when a real caller needs
them, and (b) prevents the failure mode the federation model was built to
avoid: two pieces inventing two identity or evidence stories. Anchoring rather
than merging keeps the single-writer evidence chain intact while letting a
high-volume, tiered, eventually-forgetful operational ledger live where it
belongs.

**Security implications:** adds no authority path and no new store; it makes the
existing verification seam (ADR-016/ADR-028) reach local services and tailnet
clients, and makes ASL's evidence the cockpit's source of truth. It does **not**
close the shared-process residual (H8/Stage 3), key custody (ADR-008), or the
witness-collusion residual (ADR-031) — a LAS deployment inherits all three and
must accept them explicitly (per ADR-022's gate, H8 is closed with named
residuals).

**Tradeoffs:** tailnet exposure widens the reachable surface (mitigated by
short-lived credentials, loopback-by-default, TLS at the tailnet); a device
principal for a personal stack is single-user-shaped and will need review
before any multi-user use; the status feed must be a projection (cheap) or it
becomes a second source of truth (rejected).

**Residual risk (named):** shared process and SQLite app-level-only checks
(H8/ADR-030, Stage 3 physical isolation); key custody in env/ADR-008; a
compromised local device holding a valid device credential is a legitimate
principal until its `jti` is revoked (H2); the cockpit's status feed can be
stale without an alerting story (LAS owns alerting).

**Future migration path:** each seam becomes its own H/M item when LAS exposes
it (device principals → an ADR-029/028 extension with tests; status feed →
read-only routes over existing health/audit; tailnet auth → the ADR-028
verification contract applied to service callers). Cross-repo progress is
tracked as `LAS-I<n>` milestones in each related repo, indexed in
`local-ai-system/docs/architecture/assembly-map.md`; the first real drive
(Phase A) keeps ASL out of the loop, and the fully-wired drive is rehearsed as
a simulation before it is real.

---

## ADR-033: Continuous adversarial evaluation - a runner and a drift baseline; the schedule belongs to the operator (H14)

**Context:** the platform ships a 12-case attack corpus (`security-attacks/`), a
legitimate-task fixture set (`security-fixtures/`), a declarative loader that
routes each case through the session, network, or secret gate
(`src/attacks.ts`), policy-testing primitives (`simulate`, `diffDecisions`,
`loadFixtures`), an overlay differ (`npm run policy:diff`), and an M10 SLO gate
(`npm run benchmark`). ROADMAP H14 asks for something those pieces do not
provide: a *nightly* corpus run, mutation testing on policy, differential runs
across versions, and external red team at intervals - with the honesty rule
that an implementer-authored corpus is not high-assurance evidence.

Two facts make the literal ROADMAP wording unshippable as written. First, this
repository has no scheduler: no CI configuration, and its only remote is a local
bare repo. A "nightly run" is the operator's cron, not code this repo can
publish. Second, mutation testing is circular against the current oracle: the
corpus asserts `allow`/`deny`, not per-rule expectations, so a surviving mutant
is indistinguishable from a weak assertion. H3 owns the versioned golden
decision sets that make a mutant meaningful; ADR-033 therefore holds the
mutation lane behind H3 rather than reporting a number that means nothing.
External red team is an organizational commitment and cannot be an acceptance
criterion - a criterion that can never go green rots into a deletion.

**Decision:**

1. **H14 ships a runner and a report, not a scheduler.**
   `npm run adversarial` executes every enumerated lane against the current
   tree and writes `artifacts/adversarial-report.json` (version, lanes, digests,
   pass/fail, optional git head). Exit is non-zero on any failed lane. The
   repository additionally ships `scripts/schedule-adversarial.ps1`, which
   registers an operator-local nightly task against that command. The script is
   convenience infrastructure, explicitly **not** a security control: nothing in
   the evidence chain depends on it having run.

2. **Corpus drift is closed with a committed digest baseline.**
   `artifacts/adversarial-baseline.json` pins the SHA-256 of the attack corpus,
   the legitimate fixtures, and the policy decision vector - the H10 SBOM
   pattern applied to test inputs. Any change to any of the three fails the
   drift lane until `npm run adversarial --bless` rewrites the baseline in a
   reviewed change. Drift becomes a visible, deliberate act instead of a silent
   one, and the baseline itself is diffable in review.

3. **The differential lane reports, it does not adjudicate.**
   H14 compares the current decision vector against the baseline vector and
   fails on any change. It does not state which change was correct - that is
   H3's job, using versioned golden sets with rule ids and reasons. The overlap
   between the two milestones is a shared *input* (the policy engine), never a
   shared file.

4. **The mutation lane is deferred behind H3.**
   Recorded as debt with a named upgrade path, not silently omitted.

5. **Claims are worded to the mechanism.** SECURITY_CLAIMS says *scheduled
   adversarial evaluation with a drift baseline*, never "continuous"; and every
   claim from this milestone states that the corpus is implementer-authored and
   therefore evidence that known attacks are tested, not evidence of safety.

**Security implications:** H14 adds no runtime path, no authority, no store, and
no new dependency - the report is generated offline from the same inputs the
test suite already consumes. The report records digests and counts only; it must
never echo fixture content, and a structural test asserts that. Because the
harness cannot widen authority, it cannot regress H1/H8/H11 guarantees.

**Tradeoffs:** the baseline re-bless is a rubber-stamp risk - a reviewer who
approves `--bless` without reading the corpus diff has bought nothing. The
differential lane detects *that* decisions changed, not whether the change is
worse. Both are accepted because the alternative (no baseline) detects nothing
at all.

**Residual risk (named):** unknown-unknown attacks (the ROADMAP's own
assumption, "attacks can be enumerated faster than they are invented", is false
but useful); implementer-authored corpus bias; nothing runs unless the operator
schedules it; and no mutation coverage until H3 lands its oracle.

**Future migration path:** H3 lands versioned golden decision sets -> the
mutation lane turns on against that oracle and the `ponytail:` marker in
`src/adversarial.ts` is retired. When the repository gains hosted CI, the
nightly task moves from the operator script to the runner unchanged, and the
claim upgrades from "scheduled" to "continuous" in the same commit that proves
it ran.

---

## ADR-034: Policy evaluation under adversarial conditions - analysis on load, goldens as the oracle (H3)

**Context:** the engine (`src/policy.ts`) is pure and in-process: default deny,
deny-overrides, cross-tenant denial as a hard boundary independent of any rule,
`idPatterns` compiled once at construction with pathological-pattern refusal
(M5), and deterministic evaluation for a fixed rule list. Four of the ROADMAP's
five failure modes are therefore already absent by construction. What was
missing was any way to *prove* that on every change: no determinism fuzzing, no
conflict detection on load, no performance bound as a test, and no versioned
golden decision set. The last one matters beyond H3 - H14's mutation lane was
deferred explicitly pending an oracle, and the corpus's allow/deny assertions
are not one.

One failure mode is real today and was not written down anywhere: the engine's
*effect* is order-invariant (any matching deny wins; any matching allow wins;
otherwise default deny), but its *attribution* is not. `allowed ??= rule` keeps
the first matching allow in declaration order, so reordering the same rule set
leaves every decision unchanged while changing the `ruleId` and `reason` that
reach the evidence log. With overlapping allow rules, "which rule granted this"
is a property of list order.

**Decision:**

1. **Conflict detection runs where policy actually enters: `loadPolicyBundle`.**
   `src/policy-analysis.ts` computes findings over a bounded, rule-derived
   point set and `loadPolicyBundle` refuses a hash-verified bundle that carries
   an `error`-severity finding, before any engine exists. Plain
   `createPolicyEngine(rules, ...)` stays analysis-free because construction is
   on the test hot path (measured: analysis is quadratic in rule count) - the
   gate covers the baseline set instead.

2. **Findings are bounded and rule-derived, not a decision procedure.**
   `unreachable` (a rule matches no representative point) and `shadowed` (an
   allow rule's every match is also denied) are errors; `ambiguous-allow` (two
   allow rules match the same point) is a warning. Representative points are
   generated from each rule's own declarations - concrete instances of its
   patterns, its principal kinds/ids/roles, the classification at and above its
   ceiling, and a time that satisfies its own `before`/`after` conditions - so
   a rule cannot be reported unreachable merely because the sampler picked a
   bad instant. Caps: 256 points per rule, 4096 total.

3. **Attribution order-dependence is named, not silently changed.** Detection
   is `ambiguous-allow`; the semantics stay as they are. Changing `ruleId`
   attribution is an audit-visible change and belongs in its own ADR with the
   claims it touches, not as a side effect of a test milestone.

4. **Versioned golden decision sets are the oracle.** A committed
   `baseline-decisions.json` carries a version, the policy hash, the scenarios,
   and the full expected result (effect, `ruleId`, reason). Any semantic change
   fails until the file is re-blessed deliberately. This is what H14's mutation
   lane was waiting for.

5. **Performance bounds are tests, with generous ceilings.** The point is to
   catch an order-of-magnitude regression or an accidental per-decision
   allocation, not to police microseconds; a tight bound on shared CI is a
   flaky test that gets deleted.

**Security implications:** H3 changes no decision path except to refuse a
policy bundle that was previously accepted and is provably dead or shadowed.
`matchesRule` is extracted from `evaluate` so analysis uses the *same* matcher
as the runtime - a divergence between the analyzer and the engine would make
every finding a lie, so the extraction is behavior-preserving and the existing
suite is the proof.

**Tradeoffs:** the analyzer samples a domain it derives from the rules; it can
miss a conflict that only exists at a point the sampler never generates, and it
can never prove absence of conflict. That is stated in the claim. Refusing a
bundle on an `error` finding could block an operator whose policy is merely
unusual - the escape hatch is to fix or delete the rule, which is the intended
pressure.

**Residual risk (named):** sampled-domain incompleteness; attribution follows
declaration order when allows overlap; policy authored incorrectly remains a
human error the analyzer can only partially catch; semantics too clever is
unaffected by any of this.

**Future migration path:** if attribution stability is wanted, pick the
lexicographically smallest matching allow id (or reject overlapping allows
outright) in an ADR that updates Claim 1's evidence and the audit
reconstruction; then `ambiguous-allow` becomes an error. H14's mutation lane
consumes `baseline-decisions.json` unchanged.

---

## ADR-035: Mutation testing on policy, against the golden oracle (H14, completes ADR-033)

**Context:** ADR-033 deferred H14's mutation lane because the corpus asserted
allow/deny while a mutation score needs a per-rule oracle. ADR-034 landed that
oracle: `tests/fixtures/policy/goldens/baseline-decisions.json` pins the full
expected result (effect, `ruleId`, reason) against a `policyHash`, and its teeth
are already tested - flipping or deleting any baseline rule is caught. What was
still missing is the systematic part: mutating each rule in the ways real
review misses (a flipped effect, a widened ceiling, a dropped approval
requirement, a dropped condition) and reporting which of those the golden set
does *not* notice.

A surviving mutant means one of two things, and the lane must not conflate
them: either the golden set has a coverage hole worth closing, or the mutant is
semantically equivalent and no test could ever kill it.

**Decision:**

1. **Mutants are rule-level, deterministic, and derived from the policy.**
   `src/mutation.ts` emits one mutant per (rule, applicable mutation kind):
   `drop-rule`, `flip-effect`, `widen-actions` (to `*`), `drop-ceiling`,
   `widen-ceiling` (one classification up), `drop-approval`, `drop-condition`
   (each condition), and `widen-principals` (drop kind/id/role restrictions).
   A mutation that produces a rule identical to the original is not emitted -
   that is not a mutant, it is a no-op.

2. **A mutant is killed when the golden set disagrees with it.** The measure is
   `verifyGolden` on the mutated rule set: any mismatch (effect, `ruleId`, or
   reason) kills. Attribution counts, which is exactly why ADR-034 pinned
   `ruleId` and reason rather than effect alone.

3. **The bar is zero survivors, with a committed allowlist for proven
   equivalents.** An allowlist entry must name the mutant and the reason it is
   unreachable-by-construction; the default is to strengthen the golden set
   instead. When the lane first ran it produced survivors that were real
   coverage holes, not equivalents - they were closed by adding scenarios, not
   allowlisted (recorded in AGENT-SESSION.md).

4. **The lane reports, the gate decides.** `npm run adversarial` gains a fourth
   lane; survival fails the run. The mutant list is printed with the golden
   indices that killed each one, so a survivor is actionable rather than a
   number.

**Security implications:** none at runtime. The lane is a test-time property of
the policy oracle, and it cannot widen authority - it only makes a weak oracle
visible.

**Tradeoffs:** mutation testing costs time proportional to (rules × mutation
kinds × scenarios); on this policy that is milliseconds, and the lane is
bounded by construction because mutants are derived from a finite rule set. The
measure is only as good as the mutation kinds we thought to write - a mutant we
never generate cannot be caught, and that is the lane's real ceiling.

**Residual risk (named):** mutation-operator completeness (unimaginative
operators produce an over-confident score); equivalent mutants that are not
provably equivalent get allowlisted by someone in a hurry; the golden set tests
the baseline policy, not an operator's own policy - their policy gets the
analyzer, not the mutant lane, unless they commit a golden of their own.

**Future migration path:** per-tenant policies can reuse `mutateRules` against
their own golden file unchanged; adding a mutation kind is a one-line addition
plus the mutant it produces. If survivors become routine, raise the bar to a
score (percentage killed) rather than a binary - not before.

---

## ADR-036: Data-flow enforcement - taint as a first-class label that survives tool execution (H4)

**Context:** the enforcement boundary is already sound: the model emits
*requests*, the PDP decides, and no data can mint authority (invariants 1-4).
An injected instruction therefore cannot grant scope - it can only ask for scope
that policy and capabilities already allow, and the attack corpus proves that
end to end. What is missing is the *data* half of that story. Three of H4's
failure modes are live:

1. **Implicit trust of tool output.** `ToolResult` has `output` and `changed`,
   nothing else. A tool that fetches a document itself - an HTTP or database
   tool, the normal case in a real deployment - returns text with no label at
   all. If a session then writes it somewhere, nothing in the runtime knows it
   came from a higher-classification source.
2. **Classification lost across steps.** `deriveClassification` is called per
   step over the session's *current* capabilities. Capabilities are consumed
   (`authorization.consume`), so a phi read capability used in step 1 is gone by
   step 3: the write in step 3 derives from a public capability, the content map
   (which does not contain tool-fetched text), and the requested id. The
   classification that justified the read does not survive to the write.
3. **Taint lost through serialization.** Output reaches evidence as
   `outputDigest` plus a sealed blob. The evidence says what the bytes were, not
   where they came from or what they were allowed to touch.

**Decision:**

1. **A taint label, not a boolean.** `src/taint.ts` defines
   `TaintLabel { sources: string[]; classification: Classification; untrusted: boolean }`.
   `combine()` takes the maximum classification, the union of sources, and the
   logical OR of `untrusted` - labels only ever raise, never lower. `sources` is
   capped and sorted so the label is deterministic and safe to record.

2. **The session carries taint across steps.** `AgentSession` keeps a
   session-level label that accumulates every step's output. A step's input
   taint is `combine(target resource label, carried taint, the tool's declared
   taint)`. This is the fix for failure modes 1 and 2: the phi that step 1 read
   is still phi when step 3 writes.

3. **A tool may declare, and only raise.** `ToolResult.taint` lets a tool name
   the provenance of what it returns. It can raise the label, never lower it -
   `combine` has no lowering operation, and the runtime never substitutes a tool
   declaration for the inherited label. **An output with no declaration inherits
   the target resource's label**, which is correct for the common case (a tool
   returns the resource it was given) and is why a tool that fetches something
   else must declare it. Silence cannot lower the label, but it can under-state
   provenance for data the tool fetched itself; making a declaration mandatory
   belongs at H6's protocol boundary, once tools run out of process.

4. **Classification raising takes the maximum of both derivations.** The coarse
   session derivation stays as a floor (it is conservative by construction and
   documented as such) and the taint label is folded in. This can only raise a
   target, never lower one, so no existing guarantee is weakened.

5. **Evidence records the label, never the content.** Each step's metadata gains
   `taint: { classification, sources, untrusted }` alongside the existing
   `outputDigest` and sealed payload. Source ids are resource ids, already
   present in the event log; the label carries no plaintext.

**Security implications:** the new control is *provenance continuity*. It closes
the case where a tool fetches high-classification data itself and the session
writes it onward after the justifying capability has been consumed. It does not
and cannot inspect the model's reasoning: the model is a black box, and a
semantic deviation *inside* granted scope stays the ROADMAP's named residual.

**Tradeoffs:** `untrusted` on undeclared tool output means a careless tool
raises every subsequent write to the ceiling - noisy, and deliberately so: the
fix is for the tool to declare, which is one line and reviewable. The label
costs a map lookup plus a small sort per step.

**Residual risk (named):** the model's internal reasoning is unobservable, so
"this request was influenced by that document" is never provable - only "this
step's inputs were tainted"; a tool that lies about its taint is believed (it
can only be raised, but a *low* declaration on high data is silent
misattribution); and semantic deviation inside granted scope remains out of
reach.

**Future migration path:** H7 folds the label into egress DLP (a label above the
destination's ceiling refuses the egress rather than raising the target); H9
threads it through artifact provenance; H6 can require a declaration at the tool
protocol boundary once tools run out of process.

---

## ADR-037: Content-level egress DLP - canaries, encodings, and a refusal that never repeats itself (H7)

**Context:** the PDP gates *where* bytes may go (`network.egress`,
`model.invoke`), and the classification gate refuses egress above a ceiling.
Both are structural and both work. What neither can do is look at the bytes.
`src/model-http.ts` says so in a comment: text absent from the content map is
"free text, same class as `prompt` - that is H7's content-level DLP". That is
the gap: a prompt can carry an API key, a patient row, or a canary value to a
provider that is perfectly allowlisted, and every check passes.

Three of H7's failure modes follow from that:
- **encoding/compression bypass** - the value is base64, hex, or url-encoded;
- **exfiltration via model prompt** - the model call *is* an egress;
- **exfiltration via error messages** - a refusal that quotes what it caught
  turns the denial into the leak.

Volume anomaly is the fourth, and the honest version of it for a
request-scoped mediator is a byte cap, not a statistical detector.

**Decision:**

1. **One mediator, `inspectEgress`.** `src/dlp.ts` takes a payload, the session's
   `TaintLabel`, a destination ceiling, and a canary list, and returns a verdict.
   The classification check runs first and stays authoritative; a clean canary
   scan cannot argue with it. Every egress path calls this one function rather
   than growing its own scan.

2. **Canaries are planted values, and encodings are checked.** A canary is
   `{ token, classification }`. Matching covers the token raw, base64 (standard
   and url-safe), hex, and url-encoded, and the payload is decoded once (base64
   or hex) before matching - the cheap evasions are the common ones. Tokens
   shorter than four characters are ignored so a config mistake cannot turn
   every egress into a denial.

3. **A refusal never echoes the value it caught.** `reason` and every finding
   detail are fixed labels (`canary:phi`, `payload:restricted`,
   `volume:4096>1024`). Quoting the match would make the error message the
   exfiltration channel, which is the exact failure mode this milestone names.

4. **Volume is a per-egress byte cap.** `maxBytes` refuses an oversized payload
   outright. Counting bytes across a window (slow drip) needs session state the
   mediator deliberately does not hold - named as a residual, not faked.

5. **Wired where bytes actually leave.** `HttpModelAdapter` scans the outbound
   `prompt + context` payload for canaries before any fetch (the model call is
   an egress). `EgressProxy` buffers a request body up to the cap and inspects
   it before forwarding, so an allowlisted destination still cannot receive a
   canary.

**Security implications:** this is the first control that inspects payload
content rather than metadata. It closes the allowlisted-but-leaking channel and
makes a planted canary a tripwire across every egress. It cannot see a
paraphrase, an arithmetic encoding, or a steganographic channel.

**Tradeoffs:** the proxy buffers bodies up to the cap instead of streaming them
(the cap bounds the memory, the latency change is one copy); canary scanning is
O(canaries x encodings x payload) and is meant for a small planted list, not for
a corpus of every secret in the tenant.

**Residual risk (named):** human-approved exfiltration (an operator who clicks
"send" is the authorisation); steganography and semantic paraphrase; slow drip
across many requests; compression carried end-to-end (a `.zip` body is opaque -
the canary check runs on bytes, not on decoded archives); and a canary list that
is not maintained stops being evidence of anything.

**Future migration path:** H9 threads the same mediator through artifact
storage (an artifact is egress to disk); H6 can require the tool protocol to
declare a payload so inspection happens before serialization; a session-level
byte budget turns the cap into an actual slow-drip detector once there is a
session object to hang it on.

---

## ADR-038: Malicious tool handling - scope cannot ride in params, and quotas are evidence (H5)

**Context:** the sandbox is honest about what it is: `LocalSandbox` is
"in-process/no-isolation" and ADR-003 defers containment to a container or
microVM. So H5's first failure mode - sandbox escape - cannot be *closed* here;
it is Stage 3, stated rather than pretended. The other three are addressable
today and were not:

1. **A tool requesting more scope at runtime.** `ActionRequest.params` flowed
   into `ExecutionContext.params` untouched. The PDP authorises the action on
   `request.resourceId`; a tool that then reads `ctx.params.resourceId` acts on
   a different resource under a decision that never named it. The decision was
   right and the tool ignored it.
2. **Resource exhaustion.** There was no limit on params size, output size, or
   duration. A tool could return a gigabyte, and the session would seal it,
   digest it, and hand it to the guard.
3. **Output that lies about what it did.** Partly covered by the verification
   plane (`runVerifications`), which is where a post-execution check belongs -
   this ADR does not duplicate it.

**Decision:**

1. **Authority keys in params are refused, not ignored.** `resourceId`,
   `tenantId`, `capabilityId`, `principal`, `approvals` are refused before the
   tool is invoked. Ignoring them would leave a tool free to read them; refusing
   is one line and makes the intent explicit. Ordinary params are untouched.
2. **A `ToolQuota` bounds params, output, and duration.** Params and output are
   byte-capped (65 KiB / 1 MiB defaults); duration has a budget (30 s). Params
   are checked **before** invocation, so an oversized request never reaches
   tool code. Output and duration are checked **after**, because in-process code
   cannot be preempted - so they are *detected*, not prevented, and the
   detection rides the verification plane as a `tool-quota` failure rather than
   hiding in a log line.
3. **Preemption is the container's job.** `container-sandbox.ts` already exists
   for that; wiring timeouts and memory limits into it belongs to the runtime
   hardening track, not to a synchronous call in the session.
4. **A tool still cannot mint authority.** Invariant 4 is unchanged and
   re-asserted: `ExecutionContext` holds no issuance handle, no
   `AuthorizationService`, and no principal object beyond what the action names.

**Security implications:** closes parameter smuggling (scope taken from the
request instead of the decision) and bounds the blast radius of a runaway tool
within the session, without claiming containment. A tool that escapes the
process is ADR-003's residual and stays named.

**Tradeoffs:** the authority-key refusal is blunt - a legitimate tool that wants
a caller-supplied resource id must take it from `ctx.resourceId` instead. Byte
caps are per invocation; cumulative session budgets would need session state and
are not built. Duration detection is honest but late: the damage a slow tool
does in-process is already done by the time it is measured.

**Residual risk (named):** sandbox escape and kernel vulnerabilities (ADR-003,
Stage 3 microVM); a tool that lies about what it did is only caught by whatever
verification checks the operator configured; duration and memory are detected,
not enforced, in-process; a tool that ignores `ctx` and reaches the filesystem
directly is out of scope until containment is real.

**Future migration path:** `container-sandbox.ts` enforces wall-clock,
memory, and output limits at the kernel/cgroup boundary, at which point the
`tool-quota` verification becomes a backstop rather than the only signal. H6
makes the declaration boundary explicit once tools run out of process.

---

## ADR-039: Agent-to-tool protocol - the schema is data, and provenance is mandatory (H6)

**Context:** tools were `{ name, invoke }`. Three things crossed the boundary
unvalidated. The **description** is prompt text the model reads, so it is an
injection surface with no legitimate reason to contain instructions. **Params**
arrived from a possibly-compromised model (H5 refuses authority keys, but any
other undeclared key was ignored, leaving a tool free to read it). **Output**
carried no provenance, and H4 explicitly deferred that: a `ponytail:` marker
said an undeclared tool result is trusted to be the target's data until this
boundary existed.

**Decision:**

1. **A declaration is validated at registration.** `src/tool-protocol.ts`
   defines `ToolDeclaration { name, description, actions, params?, maxOutputBytes? }`.
   `ToolRegistry.register` refuses a declaration with an empty field, an action
   outside the vocabulary, a duplicate param, or **injection signals in the
   description** (the same detector that flags hostile documents - a schema
   description has no legitimate reason to trip it).
2. **Params are closed.** When a declaration lists params, exactly those keys
   are accepted, types are checked, and required ones must be present. Undeclared
   keys are refused before invocation, not ignored.
3. **Provenance is mandatory - the H4 debt is retired.** An output with no
   declared `taint` is `UNKNOWN_TAINT` (untrusted, ranked at the ceiling). Silence
   can no longer under-state where data came from. Every tool in the scenario
   world now declares, which is the pattern operators copy.
4. **No ambient authority.** The `ExecutionContext` key set is asserted by test
   to be exactly the action-scoped fields - no `authorization`, no `principal`,
   no credential, no capability handle. This is invariant 4 made structural.

**Security implications:** the schema attacks are now refused rather than
trusted, and tool output can no longer be the one unlabelled value in the data
flow. Costs are one validation per registration and one param check per call.

**Tradeoffs:** a legacy tool with no declaration still works but its output is
labelled at the ceiling, which will look noisy - deliberately so: declaring is
one line and it is the reviewable act. Descriptions with marketing language that
resembles injection guidance are refused too; rewrite the description.

**Residual risk (named):** a tool implementation that ignores the protocol
entirely (it holds the process; ADR-003's containment residual); a declaration
that lies about what the tool does - the protocol constrains the call, not the
code; and description scanning inherits `detectInjectionSignals`' false
positives and false negatives.

**Future migration path:** once tools run out of process (H6's transport half,
behind the container work), the same declaration becomes a wire schema and the
`taint` field becomes a required message field; the quota moves to the sandbox.

---

## ADR-040: Tool declarations live in data (amends ADR-039)

**Context:** ADR-039 put `ToolDeclaration` inline in each `Tool` object. That
made the description, the action list, and the param schema reviewable only by
reading source next to the implementation — while every other authoritative
surface in this repo is data (policy bundles, goldens, the attack corpus, the
tool manifest's own siblings).

**Decision:** declarations live in `tools/manifests/*.json`, loaded and
validated by `src/tool-manifest.ts` (same `validateDeclaration`). The binding is
**strict**: `manifestFor(manifest, name)` throws rather than returning
undefined, so a tool with no entry cannot register. That is the trap this
design creates — two sources of truth for the same fact — and strict binding is
the guard: a forgotten manifest is an error, not a silent downgrade to
"provenance unknown". Manifest-level checks (duplicate names, injection-carrying
descriptions) run in `parseManifest`, so a bad manifest fails before any world
is built.

**Tradeoffs:** a manifest and an implementation can still disagree about what
the tool *does* (ADR-039's residual, unchanged); the file adds one hop between
reading a declaration and reading its code.

**Residual risk:** the manifest is trusted as written; nothing cross-checks it
against behaviour.

---

## ADR-041: Artifact admission - sniff, compare, quarantine, keep (H9)

**Context:** nothing handled artifacts. An agent could produce bytes, an upload
could arrive, and there was no admission point that asked what the bytes are.
H9's failure modes are all admission-time: executing untrusted artifacts,
storing malware, serving attacker-controlled content, and artifacts as an
exfiltration channel.

**Decision:**

1. **Content is sniffed, never trusted from the name.** `sniff` reads magic
   bytes (PNG, PDF, zip, ELF, PE) and falls back to JSON-vs-text by parsing.
   `kindFromName` reads the extension. Both are recorded on the artifact.
2. **Four refusals at admission, all producing a quarantine, never an
   exception:** executable bytes whatever the extension, a declared/sniffed
   mismatch, a payload above the store ceiling, and a canary hit. The last two
   reuse H7's `inspectEgress` — an artifact is egress to disk.
3. **Quarantine keeps the bytes.** They are evidence; deleting them destroys the
   only record of what arrived. `released()` is what may be handed out.
4. **Tenant binding is structural** (H8 pattern): the key is
   `tenantId\0id`, and `get` returns undefined for a foreign tenant, so an id
   collision across tenants cannot leak.

**Security implications:** closes the "artifact as exfiltration channel" path by
reusing the egress mediator rather than inventing a second scanner, and makes
executable content non-releasable regardless of naming.

**Tradeoffs:** magic-byte sniffing is shallow — a polyglot file passes as its
first magic; the mismatch check is only as good as the extension vocabulary.

**Residual risk (named):** zero-day malware (no AV, by design — we do not ship a
scanner); polyglot files; a released artifact of the right kind carrying hostile
*meaning* (a PDF with an exploit is still a PDF); and quarantined artifacts still
occupy storage.

---

## ADR-042: Machine-checked PDP invariants (Stage 3 row: formalized security invariants)

**Context:** the thirteen invariants in `security-tests/invariants.test.ts` are
examples - each names a scenario and asserts an outcome. They catch what someone
thought to write, and they say nothing about the states nobody wrote. The
Stage-3 row asks for a "machine-checked model of the PDP" with "stable
semantics" as its prerequisite; semantics have been stable since H3 (mutation
lane, goldens), so the row is buildable.

**Decision:**

1. **State the properties as predicates over a state**, not as scenarios.
   `src/invariants.ts` defines `InvariantState` (principal, resource, action,
   capabilities held, clock, decision) and seven invariants:
   no-authority-without-capability, cross-tenant-never-allowed,
   expired-capability-never-authorizes, classification-ceiling-respected,
   foreign-capability-never-authorizes, empty-capability-set-denies,
   deny-carries-no-authority.
2. **Enumerate a bounded state space and check all of it.** The test drives the
   real `AuthorizationService` across 5 capability specs x 3 principals x 5
   resources x 5 actions (375 states) and asserts zero violations. Nothing is
   mocked: the model runs the same code the product runs.
3. **Prove the model has teeth.** A forged `allow` with no capabilities must
   fire at least two invariants; a vacuous checker would report a clean run and
   mean nothing.
4. **Say what it is not.** This is bounded model checking, not a proof: it is
   exhaustive over 375 hand-chosen coordinates and blind to any state outside
   them. "Machine-checked" here means "a machine checks every enumerated state",
   not "the property is proven for all inputs".

**Security implications:** an engine change that breaks a property now fails on
a class of states rather than on the one example someone remembered to update.
The enumeration is deliberately small enough to read.

**Tradeoffs:** the state space is chosen by hand, so its coverage is an opinion.
Expired capabilities cannot be enumerated because issuance refuses a past
expiry - that property is exercised by a constructed state instead, which is
weaker (it proves the predicate works, not that the service upholds it).

**Residual risk (named):** enumeration bias; no counterexample minimisation; the
invariants are necessary conditions, not a specification (they cannot say the
policy granted the *intended* thing).

**Future migration path:** a real model checker (TLA+/Alloy) over the same seven
properties would remove the enumeration bias; that needs a specification of the
PDP in a formal language, which is a research project rather than a milestone.

---

## ADR-043: Content-level lineage for derived artifacts (Stage 3 row: advanced provenance)

**Context:** the taint label (H4) flattens provenance into a set of source ids
with a maximum classification. That is the right shape for a decision ("may this
leave") and the wrong shape for an investigation ("where did this artifact come
from, six derivations back"). H9 recorded a provenance *label* per artifact;
nothing recorded the graph.

**Decision:**

1. **An explicit DAG.** `src/provenance.ts` `ProvenanceGraph` records nodes
   `{ id, tenantId, kind, parents, classification }` and answers `lineage(id)`
   (transitive ancestors, nearest first, deterministic order) and `depth(id)`.
2. **Four refusals, because a partial lineage graph is worse than none:** an
   unknown parent (no forward references), a parent in another tenant (existence
   would leak, the H8 failure mode), a cycle, and a re-record with different
   parents (one node, one history). Depth is capped at 32.
3. **Artifacts record lineage at admission, quarantined or not.** `ArtifactStore`
   takes an optional `ProvenanceGraph`; `derivedFrom` names the sources. A
   quarantined artifact still gets a node - evidence of what arrived needs its
   lineage as much as a released one does.

**Security implications:** an investigator can answer "what fed this" without
re-reading every event, and a derivation that skips its source is refused rather
than silently recorded. The graph is tenant-bound, so lineage cannot be used as a
cross-tenant existence oracle.

**Tradeoffs:** parents must be recorded before children (strict ordering is a
constraint on callers), and the graph is in-memory - persistence is the audit
log's job, and rebuilding lineage from events is not implemented.

**Residual risk (named):** in-memory only, so a restart loses lineage unless the
caller replays; `depth()` is recursive without memoisation (fine for the capped
graph, wrong for a large one); and lineage says what a node was *derived from*,
never what was done with it.

**Future migration path:** replay lineage from `document.ingest` /
`session.guard` / artifact events at startup; then the graph becomes a derived
view of evidence rather than a separate store.

## ADR-044: Buildless development, compiled publish

**Context:** the source tree runs directly under Node's type stripping, pinned
to `engines.node >= 22.18`. `bin/aisl.mjs` imported `../src/cli.ts`, and the
`files` allowlist shipped `src`, so the tarball was complete and the extracted
CLI ran. It still could not start after `npm i aisl`: Node refuses type
stripping anywhere under `node_modules`
(`ERR_UNSUPPORTED_NODE_MODULES_TYPE_STRIPPING`). The package was installable and
inert at the same time (ticket 01).

**Decision:**

1. **Two build modes, one source tree.** `tsconfig.json` stays the review
   artifact: `noEmit`, every relative import written with a `.ts` specifier, and
   `node src/cli.ts demo` stays the development loop. `tsconfig.build.json`
   extends it with `outDir: dist`, `rootDir: src`, `noEmit: false`,
   `declaration: false`, `sourceMap: false`, and includes only `src/**/*.ts`.
2. **`tsc` rewrites the specifiers.** `allowImportingTsExtensions` plus
   `rewriteRelativeImportExtensions` turn `./events.ts` into `./events.js` on
   emit, so the published JavaScript has no `.ts` specifier and needs no type
   stripping. No bundler: `typescript` is already a devDependency, and adding one
   would be a second compiler to trust.
3. **`bin/aisl.mjs` launches `../dist/cli.js`.** It keeps `pathToFileURL`
   because a Windows drive letter is not a valid ESM specifier. The launcher is
   the only file that knows where the entry lives.
4. **`dist` is in `files` and in `.gitignore`.** The npm package ships compiled
   output plus the source tree; the repository tracks only the source. `build`
   deletes `dist` before compiling, so a removed or renamed module cannot
   survive in a stale artifact and ship.
5. **`prepublishOnly` is `typecheck && test && build`.** No `prepare`: a
   consumer install must not need devDependencies, and a dependency that builds
   on install is a dependency that can fail on install.

**Security implications:** what npm publishes is now a deterministic function of
committed source, and the supply-chain gate keeps binding `files` content
through the SBOM baseline. Nothing about the runtime dependency set changes:
still `jose` and `postgres` (ADR-015).

**Tradeoffs:** two configs to keep in step; a publish step that can forget to
run `build` (`prepublishOnly` is the guard, and it is skipped by
`--ignore-scripts`); and the reviewer must read `src`, not `dist`, because
`dist` is generated.

**Residual risk (named):** `dist` is regenerated, never reviewed, so a
publishing machine with a dirty compiler or a stale `node_modules` can emit
different bytes than a clean clone would. The tree digest in the build manifest
covers committed source, not emitted output. And `aisl demo` sections 20-21
shell out to `git ls-files` at the package root (ADR-024), so a bare
`npm i aisl` with no `.git` starts the CLI but ends the demo with exit 1; the
packaging test stages a repository to reach exit 0.

**Future migration path:** emit a reproducibility record (compiler version,
`dist` digest) into the build manifest, then a consumer can check the published
bytes against the committed source instead of trusting the publisher.
