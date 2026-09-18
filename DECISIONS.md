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

**Context:** The project's ambition is expressed as "as close to 99.9996% secure
as possible". That number (≈3.4 failures per million, the Six Sigma figure) is a
legitimate aspiration and an unusable metric: it has no denominator, no defined
failure event, and no test that could falsify it. Publishing it would break the
rule this project was founded on — every claim must bind to a property, a threat
model, a mechanism, a test, and evidence.

**Decision:** Adopt 99.9996% as an internal **north star**, never as a published
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
