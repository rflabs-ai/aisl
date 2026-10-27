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
restated in each; **all landed M prompts live in `PROMPTS/M-Track--DONE/`**):
`M10-assurance-targets-and-slos.md` (the row above —
**done**; it set the SLO baseline every later milestone must not regress),
`M11-authz-depth.md` (Granular RBAC, Classification
propagation, Configuration management — **done**; A/B subagents ran in
parallel on disjoint surfaces, C consumed A's role surface),
`M13-runtime-realism.md` (model provider adapters, verification
pipeline, structured telemetry — **done**; ran concurrently with M11 on
disjoint module surfaces, zero new runtime dependencies),
`M12-platform-shift.md`
(Postgres ADR-018 + schema/migrations + tenant isolation + backup/restore —
**[DONE]**; Phase 0: ADR-018 (driver `postgres.js` pinned as `postgres@3.4.9`,
schema, two-role RLS model, per-tenant key derivation, fail-closed
`store-unavailable`); Phase 1: `EventStore` port + `PostgresEventLog` +
migrations framework; Phase 2: B (RLS policies + per-tenant keys) ∥ C
(backup/restore + persistence) ran in parallel on disjoint surfaces. All
verified against a live Postgres container; SQLite default unchanged).
M10 ran first — it set the SLO baseline every later milestone must not regress.

Scoping for Stage 0's finish line: `M14-rest-api.md`
(ADR-019 — the HTTP transport as a new trust boundary, `node:http` zero-dep,
authn/tenant/whitelist contracts, authorize + sessions + capability
requests + audit + tasks + healthz) then `M15-stage0-cleanup.md`
(ADR-020 — document ingestion ∥ Git read-only, the M12 capability-request
API seam, setup script, minimal UI served by the M14 server). Both landed —
**Stage 0 is fully [DONE]**. `M16-sandbox-lifecycle.md` (ADR-021 —
sandbox lifecycle: create, limit, destroy, attest) closed the last Stage 1
row. `M17-federation-control-plane.md` (ADR-022 — control-plane as the
first federation client) landed — evidence anchoring + capability-gated
dispatch across repos; its full-format spec moved to
`PROMPTS/M-Track--DONE/`. M18–M20 prompts are written just-in-time per the
M4–M16 convention.

The Stage 2 (HARD) queue lives in `PROMPTS/H-Track/` — one stub per open H
item (H2–H15; H1 is a tombstone for ADR-023), each pointing at its ROADMAP
section as the spec of record and expanded to full prompt format just-in-time
at kickoff.

---

## Stage 2 — HARD (substantial security engineering)

Each item lists attack surface, failure modes, assumptions, test methodology, and
residual risk, as required. Status markers apply: **[DONE]** / **[NEXT]** / **[ ]**.

- **Working order** (pick list, AGENT-SESSION SESSION 19): ~~H1 [NEXT]~~
  **H1 [DONE]** (ADR-023) — it was the root of trust for everything above it.
  ~~Next: H10, H12, H13, H15~~ **H10 [DONE]** (ADR-024) — signed builds and
  the supply-chain gate. **M17 federation [DONE]** — control-plane is the
  first federation client (anchoring + capability-gated dispatch); its two
  ASL-side REST gaps (anchor registration, capability-request status) closed.
  ~~Next: H12, H13, H15~~ **H12 [DONE]** (ADR-025) — signed update channel:
  descriptor chain, high-water mark, signed single-use rollback, sticky
  canary halt. **H13 [DONE]** (ADR-026) — incident response: tenant/global
  kill switch (freeze + revoke-all, `incident-frozen`), multi-writer
  revocation channel with bounded cross-node propagation, and paged evidence
  preservation (`asl-incident-bundle`) + reconstruction. **H15 [DONE]**
  (ADR-027) — fail-closed availability: per-dependency fault injection with
  distinct reasons, observed health + loud transitions, clock guard, the
  degraded-mode matrix, and the decision-latency budget. **H2 [DONE]**
  (ADR-028) — short-lived credentials: an admission contract at the single
  verification seam (required `sub`/`exp`/`iat`/`jti`, lifetime ceiling,
  bounded and actually-wired clock tolerance — the jose option name was a
  silent no-op), derived workload identity (`workloadAuth`/`sessionAgent`
  capped and claim-minimal), and `jti` revocation propagated on the H13
  channel. **H8 [DONE]** (ADR-030) — cross-tenant isolation: one table-driven
  probe over every REST route and in-process query surface, which proved and
  closed two gaps — a v2 evidence key now opens only for the tenant it names,
  and capability-request review enforces reviewer tenancy at the decision
  surface; the H13 global view is probe-pinned to the caller's own tenant
  authority and tenant-less events. **H11 [DONE]** (ADR-031) —
  tamper-evident evidence: external anchor sinks (file + HTTP witness, never
  blocking an append), multi-source reconciliation (binding, truncation, fork
  detection), operator-held signed checkpoints, durable federation anchor
  history, and recorded legal holds. H14 closed on 2026-10-27 (ADR-035) and H4
  the same day (ADR-036), which unblocks the rest of the runtime track: next is
  **H7** (data-flow continued into egress DLP) or **H5**, with **H6/H9**
  serialized behind them on `src/runtime.ts`. H5-H7 and H9 remain the open
  Stage 2 items.

  **Working order (agreed 2026-10-12).** **H14** (continuous adversarial
  evaluation) and **H3** (policy adversarial) run first and in parallel —
  H14's corpus feeds every later track, H3 is file-disjoint (policy + fixtures).
  As executed, H14's runner + drift + differential lanes landed first
  (ADR-033, 2026-10-27), H3 followed the same day (ADR-034), and H14's mutation
  lane closed against H3's goldens (ADR-035) - both milestones are now [DONE].
  H4 (data-flow taint) followed on the same day (ADR-036), unblocking the
  runtime track.
  **M18 Phase 1** proceeds in the raven repo (ASL consume-only). A
  **control-plane gap pass** ("to a good place") runs alongside. Then the
  runtime track: **H4 → H7** (H4 is the shared dependency of kgp's clean-room,
  home-agent's M19, and H9), with **H5/H6/H9 serialized behind H4** on
  `src/runtime.ts`. LAS (personal stack) is tracked separately — see the
  LAS-portfolio paragraph below, **ADR-032**, and
  `local-ai-system/docs/architecture/assembly-map.md`; its first real drive
  (Phase A: ctxd M0–M2 + kgp P0) deliberately keeps ASL out of the loop.

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

### H2 — Short-lived credentials and workload identity — *structurally necessary at federation (ADR-022)* **[DONE]** (ADR-028)

- **Attack surface:** credential issuance, transport, storage in memory, reuse.
- **Failure modes:** leaked long-lived token; clock skew extending life; credential
  left in a crash dump or an event payload.
- **Assumptions:** NTP with authentication; secrets never enter the event log.
- **Test methodology:** expiry fuzzing; credential-in-log scanning (a test that
  fails if any event contains a known secret value); revocation propagation tests.
- **Residual risk:** window of validity; in-memory exposure.
- **Class:** E.
- **Closed:** ADR-028 — the verification seam (`IdentityProvider.verifyToken`)
  refuses any token without `sub`/`exp`/`iat`/`jti`, a positive lifetime within
  `maxTokenLifetimeSec` (default 1 h, configured cap 24 h), and `iat`/`exp`
  inside a clock tolerance that is bounded (default 30 s, cap 60 s) and now
  actually wired into jose (the old `clockToleranceSec` key was silently
  ignored). Workload identity is derived and capped
  (`IdentityProvider.workloadAuth`; `sessionAgent` routes through it), never
  the launching human's raw claims. `jti` revocation propagates on the H13
  channel (new `revoke-token` record; `attachRevocationFeed`;
  `IncidentService.revokeToken` local-first, CLI `incident revoke-token`).
  Scan tests assert no raw token or payload canary reaches any event or error.
  Residual: in-memory revoked set per process (Postgres channel is the durable
  coordination path), poll-bounded propagation, SPIFFE/SPIRE still deferred.

### H3 — Policy evaluation under adversarial conditions

- **Attack surface:** rule set, condition evaluation, input size/shape.
- **Failure modes:** catastrophic backtracking; rule-order dependence; unbounded
  evaluation time; nondeterminism across versions; rule conflict ambiguity.
- **Assumptions:** rules are finite and statically analyzable.
- **Test methodology:** determinism fuzzing; conflict detection on load;
  performance bounds as tests; versioned golden decision sets.
- **Residual risk:** policy authored incorrectly; semantics too clever.
- **Class:** MVP.

**Closed (ADR-034, 2026-10-27):** `src/policy-analysis.ts` +
`npm run policy:analyze`, wired into `loadPolicyBundle` so a hash-verified
bundle carrying a dead or shadowed rule is refused **before an engine exists**.
Four findings: `unreachable` (rule matches no representative point),
`shadowed` (every point an allow matches is also denied — an entombed grant),
`ambiguous-allow` (two allows match the same point), `unknown-action` (action
outside the vocabulary). Points are derived from each rule's own declarations —
concrete instances of its patterns, its principal kinds/ids/roles, the
classification at and above its ceiling, and a time satisfying its own
`before`/`after` window — capped at 256 per rule / 4096 total. `matchesRule` was
extracted from `evaluate` and is now the **only** matcher, so the analyzer
cannot report on a policy nobody runs; making its pattern cache required closed
a real footgun found while testing (a bare call silently degraded every
idPattern to a literal). Determinism: 500 seeded random contexts across two
engines, plus repeat-evaluation and no-state-leak checks. Order: the *effect* is
permutation-invariant (200 contexts); the *attribution* is not when allows
overlap, and that is detected and stated rather than changed. Performance:
2000 rules × 2000 decisions inside a generous bound, compile cache proven not
to grow on the decision path, 500-segment id evaluated in bounded time.
**Goldens:** `tests/fixtures/policy/goldens/baseline-decisions.json` — version,
`policyHash`, scenarios, and full expected results (effect + ruleId + reason),
verified by `npm run policy:golden`, re-blessable only deliberately. Its teeth
are tested: flipping or deleting **any** baseline rule is caught. That is the
oracle H14's mutation lane was waiting for. 21 tests
(`tests/h3-policy-adversarial.test.ts`). Residual per ADR-034: the analyzer
samples a rule-derived domain — it can miss a conflict at a point it never
generates and can never prove absence; attribution order-dependence remains.

### H4 — Prompt-injection-resistant architecture (data-flow enforcement) **[DONE]** (ADR-036)

- **Attack surface:** every place untrusted text crosses into a decision.
- **Failure modes:** implicit trust of tool output; taint lost through
  serialization; classification lost on derived content.
- **Assumptions:** taint tracking is complete; new code paths are reviewed for it.
- **Test methodology:** taint-propagation tests; "malicious corpus end-to-end"
  runs where the expected outcome is denial or in-scope action only.
- **Residual risk:** semantic deviation inside granted scope (unavoidable).
- **Class:** MVP/HA.

**Closed (ADR-036, 2026-10-27):** `src/taint.ts` is a one-directional label
(`combine` takes the max classification, the union of sources, OR of
`untrusted`; there is no lowering operation). `AgentSession` carries a label
across steps and folds it into the existing coarse derivation, which stays as a
floor — so the write path can only be raised, never lowered. `ToolResult.taint`
lets a tool declare provenance (raise-only); `ExecutionContext` gains
`resourceClassification` so a declaration can be accurate. Every execution event
records `taint: { classification, sources, untrusted }` — ids and labels, never
content — and a canary test asserts the plaintext cannot reach it. The closed
hole: **revocation does not un-see data.** A session reads phi through a tool,
the capability is revoked, and a later write under only a public capability now
still raises the target to phi, because the label rode the session rather than
the grant. The end-to-end half is proven on all four corpus documents: every
step is denied, executed false, and marked `untrusted` with the source named.
9 tests (`tests/h4-dataflow.test.ts`). Residual per ADR-036: the model's
reasoning is unobservable — only the step's inputs are labelled, never "this
request was caused by that document"; an undeclared tool output is trusted to be
the target's data (`ponytail:` marker in `src/runtime.ts`, mandatory at H6);
semantic deviation inside granted scope is out of reach.

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

### H7 — Data-flow enforcement and egress DLP **[DONE]** (ADR-037)

- **Attack surface:** outbound bytes: network, files, artifacts, logs, model calls.
- **Failure modes:** encoding/compression bypass; slow drip below thresholds;
  exfiltration via model prompt; exfiltration via error messages.
- **Assumptions:** all egress is mediated; the model call is itself an egress.
- **Test methodology:** canary-value exfiltration suite (unique tokens per
  classification, assert none appear at any egress); encoding variants; volume
  anomaly detection.
- **Residual risk:** human-approved exfiltration; steganography.
- **Class:** E/HA.

**Closed (ADR-037, 2026-10-27):** `src/dlp.ts` is the one content-level
mediator: `inspectEgress({ payload, label, ceiling, canaries, maxBytes })`
returns a verdict whose classification check runs first and stays
authoritative. Canary matching covers the token raw, base64 (standard and
url-safe), hex, and url-encoded, and decodes the payload once (base64 or hex)
before matching — the cheap evasions. **A refusal never repeats what it
caught**: reasons and details are fixed labels (`canary:phi`,
`payload:restricted`, `volume:4096>1024`), because an error that quotes the
value is the exfiltration channel. Wired where bytes actually leave:
`HttpModelAdapter` inspects the outbound prompt+context before any fetch (the
model call *is* an egress — the gap its own comment named), and `EgressProxy`
buffers a body up to the cap and refuses it, so an allowlisted destination
still cannot receive a canary. `dlp-refused` is a distinct `DenyReason`. 14
tests (`tests/h7-egress-dlp.test.ts`), including the structural property that
no verdict contains the token in any encoding. Residual per ADR-037:
human-approved exfiltration; steganography and semantic paraphrase; slow drip
across requests (the cap is per-request — `ponytail:` marker in
`src/egress-proxy.ts`); compressed bodies are opaque to a byte scan; an
unmaintained canary list proves nothing.

### H8 — Cross-tenant isolation (cryptographic and physical) — *structurally necessary at federation (ADR-022)* **[DONE]** (ADR-030)

- **Attack surface:** shared process, shared database, shared caches, logs.
- **Failure modes:** a query missing a tenant predicate; a cache key collision;
  one tenant's data in another tenant's logs.
- **Assumptions:** some sharing is unavoidable in SaaS.
- **Test methodology:** automated cross-tenant probe in CI (every endpoint, every
  query); per-tenant key separation tests; log-scrubbing tests.
- **Residual risk:** hardware-level side channels; hypervisor bugs.
- **Class:** E/HA.

**Closed (ADR-030):** one table-driven cross-tenant probe
(`tests/h8-cross-tenant-probe.test.ts`) enumerates every REST route
(authorize, sessions, capability requests, audit, tasks, anchors, healthz,
static pages) and every in-process query surface (audit query/export,
event-store reads, registry, sessions, capability requests, persistence), each
row asserting isolation in both directions, a log-scan property (no foreign
marker/content in the caller's visible records or responses), or a named
`global-by-design` exposure; Postgres-gated rows skip cleanly. The probe proved
and this milestone closed two real gaps: `revealEvidence` did not bind a v2
keyId to its tenant — a tenant-A capability naming tenant B's key could decrypt
B's seal and bind the foreign key to A in the registry — now refused before
any registration/authorization, with one clean deny event in the caller's own
tenant and `openFor(tenantId)` as a second binding; and
`CapabilityRequestService.approve`/`deny` had no reviewer-tenant predicate (the
REST boundary had one — the in-process decision surface now enforces it). The
H13 global view (`tenantId: '*'`) is probe-pinned: authorized only by the
caller's own tenant audit capability and exposing only tenant-less events.
Residuals per ADR-030: the shared process (known-gap #7; physical isolation is
Stage 3), SQLite app-level-only checks, hardware side channels, principal-id
collisions on non-tenant-facing helpers, one `CapabilityRequestService` per
root, and the probe's marker-scope limitation. 22 probe cases (20 live, 2
Postgres-gated) + 1 evidence-seal extension; gate 676 tests / 655 pass / 0
fail / 21 skip.

### H9 — Secure artifact handling

- **Attack surface:** files produced by agents, uploads, model artifacts.
- **Failure modes:** executing untrusted artifacts; storing malware; serving
  attacker-controlled content to other tenants; artifact as exfiltration channel.
- **Assumptions:** artifacts are untrusted until verified.
- **Test methodology:** type confusion tests; content/extension mismatch;
  scanning and quarantine workflow; artifact provenance assertions.
- **Residual risk:** zero-day malware; polyglot files.
- **Class:** P/E.

### H10 — Signed builds and supply-chain security **[DONE]** (ADR-024)

- **Attack surface:** dependencies, build pipeline, registry, developer laptops.
- **Failure modes:** malicious dependency; compromised CI; unsigned artifact
  deployed; lockfile drift.
- **Assumptions:** at least two maintainers; CI is isolated from dev credentials.
- **Test methodology:** SBOM generation and diff on every build; pinning with
  hash verification; provenance attestation (SLSA-style) verified at deploy;
  dependency update review gate.
- **Residual risk:** a trusted maintainer going rogue; compiler-level attacks.
- **Class:** E/HA.

**Closed (ADR-024):** the source tree IS the artifact — `src/supply-chain.ts`
+ `npm run supply-chain` (the gate: deterministic `ASL-SBOM v1` from the
lockfile, diffed against the committed `artifacts/sbom.json` baseline; exact
version pins; sha512 integrity + registry URL on every lockfile entry; the
`ADMITTED_RUNTIME_DEPS` allowlist — a new runtime dep fails the gate until an
admission ADR lands in the same PR); `build sign` runs the full release gate
(typecheck + tests + supply-chain) and Ed25519-signs a build manifest binding
`treeDigest` (git blob SHAs — platform-independent), `sbomDigest`, `gitHead`,
and the gate result; `build verify` is the deploy-time check, fail-closed with
distinct reasons. Tests-first suite: `tests/h10-supply-chain.test.ts` (20).
The gate is wired to the local pre-commit hook; CI wiring, transparency-log
publication, and hardware key custody are the documented upgrade paths.

### H11 — Tamper-evident evidence (signatures, anchoring, retention) **[DONE]** (ADR-031)

- **Attack surface:** the event store, the verifier, the anchor.
- **Failure modes:** whole-log rewrite; anchor collusion; clock manipulation;
  selective deletion.
- **Assumptions:** at least one append-only store the runtime cannot rewrite.
- **Test methodology:** anchor consistency checks; verifier against
  adversarially rewritten logs; retention and legal-hold tests.
- **Residual risk:** an attacker who controls both the log and the anchor.
- **Class:** HA.

**Closed (ADR-031):** `src/anchors.ts` — the M3 local anchor file stays
byte-compatible; `AnchorSink` adds an external publication port
(`FileAnchorSink` for a second/WORM path, `HttpAnchorSink` for an
operator-configured witness with an optional env-only bearer token). Publication
is non-blocking: a bounded queue with kick-on-publish + `flushAnchors()`, loud
`published/failed/dropped/lastError` counters, a throwing sink can never break
an append, and a failing request keeps its point for the next attempt.
`verifyAnchoredEvidence` reconciles a bundle against any number of sources:
parse + monotone/contiguous seq checks, line-to-event binding, head coverage
(an uncovered tail fails closed), a source ahead of the bundle head = tail
truncation, and two sources disagreeing at one seq = **fork** (anchor collusion).
A bundle with no source is reported `unanchored`, never silently anchored.
`createCheckpoint` signs an `asl-anchor-checkpoint` with the existing
event-signing key (no new key, no new authority); `verifyCheckpoint` refuses
truncation, rewrite (even by a host attacker who re-signs the whole chain),
broken checkpoint chaining, same-seq forks, and bad signatures — the operator
takes the file off-host, satisfying the "store the runtime cannot rewrite"
assumption with no live service. The M17 `AnchorRegistry` rehydrates accepted
heads from `anchor.register` events (the in-memory marker is closed). Timestamp
regressions are reported as non-fatal anomalies and witness records carry the
witness clock; the hash chain and signatures remain the controls. Retention is
structural — no update/delete path at any layer — and legal holds are signed
`evidence.hold`/`evidence.release` events in `src/retention.ts`
(`RetentionLedger`, rehydrated from the log, tenant-bound: a principal may only
hold its own tenant). CLI: `node src/cli.ts evidence
status|checkpoint|verify|witness|hold|release` (+ `npm run evidence:status`).
Tests-first suite: `tests/h11-tamper-evident-evidence.test.ts` (39: 35 at the
milestone + 4 audit-follow-up cases) + the H8
probe's new `retention-ledger-tenancy` row (23 cases now). Zero new runtime
dependencies. Residuals per ADR-031: a host attacker controlling every witness
and checkpoint, witness-operator collusion/split-view, signing-key custody
(ADR-008), no prune path exists yet (the hold ledger is its future gate).

### H12 — Secure updates **[DONE]** (ADR-025)

- **Attack surface:** update channel, signing keys, rollback behaviour.
- **Failure modes:** rollback to a vulnerable version; unsigned update; update
  as remote code execution with high privilege.
- **Assumptions:** versioned, signed, staged rollout; emergency rollback exists.
- **Test methodology:** signature verification tests; rollback prevention tests;
  staged rollout with automated canary and auto-halt.
- **Residual risk:** a signed but malicious release.
- **Class:** E/HA.

**Closed (ADR-025):** the update channel is a signed descriptor chained onto
the H10 build manifest — `src/updates.ts` + `node src/cli.ts update
sign|verify|apply|promote|status|grant|rollback`. The chain: descriptor
structure → Ed25519 descriptor signature → embedded build manifest verified
against the **live tree** (H10 `verifyManifest` recomputes tree/SBOM digests)
→ persisted high-water mark → canary state. `apply` requires
`releaseVersion > highWaterMark` and raises it; the mark never lowers, so a
perfectly signed, perfectly stale descriptor is refused
(`rollback-blocked`) — signature validity and freshness are separate checks.
Emergency rollback is a **signed, single-use grant** naming the exact
from-version and the state's `rollbackGeneration` — one use per generation,
so a used grant never revives even if its from-version becomes current again
(replay → `grant-mismatch`), backward-only, and it never lowers
the mark — the version rolled back *from* stays burned. Staged rollout:
`stages` ascend to 100 (a rollout ending short is `bad-stages`), `apply`
lands canary, `promote` advances one stage per explicit health pass, a
failing signal halts and the halt is **sticky** (only a new descriptor or a
rollback grant resolves it). State is code-written only, atomic
(temp+rename), gitignored per instance. Tests-first suite:
`tests/h12-secure-updates.test.ts` (20), including the trust-boundary
invariant (no key material in state/descriptor/grant/refusal text). Residuals
per ADR-025: caller-supplied health signal, one release key (ADR-008
custody), no transport (this repo verifies updates, it does not host them),
signed-but-maintainer-rogue release unchanged.

### H13 — Incident response mechanisms — *structurally necessary at federation (ADR-022)* **[DONE]** (ADR-026)

- **Attack surface:** everything, under the assumption of an active incident.
- **Failure modes:** cannot revoke a session or a capability quickly; cannot
  freeze issuance; cannot reconstruct what happened; cannot preserve evidence.
- **Assumptions:** an on-call human exists and can act.
- **Test methodology:** game days measuring kill-switch latency, **capability
  revocation propagation (target <= 5 s)**, and evidence export completeness.
- **Residual risk:** incident response is slower than the attack.
- **Class:** MVP/E.

**Closed (ADR-026):** `src/incident.ts` + `src/incident-store-pg.ts` (migration
4) + two chokepoint edits in `src/pdp.ts`. `IncidentService.engage` is one
operator action — freeze issuance + revoke every registered capability in
scope + revoke sessions in scope — enforced at the two chokepoints
(`AuthorizationService.issue` refuses `incident-frozen`; `authorize` denies
with the distinct reason, evidence-read actions excepted so an incident can be
reconstructed while frozen). `lift` clears the freeze only; revoked authority
stays revoked. Revocation coordination is a separate multi-writer,
append-only `revocation_channel` (the event chain stays single-writer); the
`RevocationChannel` port has an in-memory backend (default; shared instance =
multi-node test seam) and a Postgres backend (mirror + async refresh, the
`PostgresEventLog` pattern) so an operator CLI can reach a running node.
Propagation is pull-on-decision — throttled on `authorize` (default 1 s ≤ the
5 s target), forced on `issue`; a fresh node replays from cursor 0 and
reconstructs freeze + revocation state; a channel outage still engages locally
and reports `broadcastOk: false`. `preserve` pages past M6's silent
1000-event cap into an independently verifiable `asl-incident-bundle`
(digest + offline chain/signature verification + anchor check) and records
only digest + head + counts; `reconstruct` summarizes the same authorized
slice. Tests-first: `tests/h13-incident-response.test.ts` (22) + the
PG-channel suite (3 live, skip cleanly). Residuals per ADR-026: poll-based
propagation, a channel writer can freeze (DoS is the H15 accepted trade),
single-node freeze state is in-memory (durability is the Postgres channel's),
and the ROADMAP residual — incident response slower than the attack — is
unchanged.

### H14 - Adversarial evaluation harness (continuous) **[DONE]** (ADR-033, ADR-035)

- **Attack surface:** the platform as a whole, tested continuously.
- **Failure modes:** corpus drift; tests that assert the wrong thing; coverage
  gaps mistaken for safety.
- **Assumptions:** attacks can be enumerated faster than they are invented (false,
  but useful).
- **Test methodology:** nightly corpus run; mutation testing on policy;
  differential runs across versions; external red team at defined intervals.
- **Residual risk:** unknown-unknown attacks.
- **Class:** MVP/HA.

**Closed in part (ADR-033, 2026-10-27):** `src/adversarial.ts` +
`npm run adversarial` compose the existing pieces into one run over three lanes
and pin their inputs with digests: **corpus** (attack cases + legitimate
fixtures, every case must behave as specified), **drift** (SHA-256 of the
corpus and fixtures against the committed `artifacts/adversarial-baseline.json`
— the H10 SBOM pattern applied to test inputs, so adding, removing, renaming or
editing a case fails the lane until `--bless` is run deliberately in a reviewed
change), and **differential** (the digest of the decision vector across every
policy fixture scenario, which catches semantic drift without adjudicating it —
that stays H3's job). The report is written to
`artifacts/adversarial-report.json` and carries digests and counts only, with a
canary test asserting no fixture content can reach it. Proven end-to-end: a
clone of a corpus case makes every case pass while the drift lane fails — the
"coverage change mistaken for safety" failure mode, closed. `scripts/
schedule-adversarial.ps1` registers an operator-local nightly run (verified
register/status/unregister, then unregistered) and is documented as
convenience, never a security control.

**Closed (ADR-035, 2026-10-27):** the **mutation** lane, the part ADR-033
deferred pending an oracle. `src/mutation.ts` derives mutants from the policy -
`drop-rule`, `flip-effect`, `widen-actions`, `drop-ceiling`, `widen-ceiling`,
`drop-approval`, `drop-condition`, `widen-principals` - and a mutation that
changes nothing is never emitted. A mutant is killed when the golden decision
set disagrees with it anywhere (effect, `ruleId`, or reason), which is exactly
why ADR-034 pinned all three. The lane passes only if **every** mutant is
killed, and fails closed if no mutants are generated at all. First run:
17 mutants, **5 survivors - and all five were real coverage holes**, not
equivalents: an approval widening the *action* (an approved agent could
delete), an approval widening the *principal* (a human reading through an agent
rule), a wildcard allow on a user rule, and a widened deny. They were closed by
adding five scenarios to the golden set (15 total), not by allowlisting; the
allowlist mechanism exists for future provable equivalents and is currently
empty. This also guards the oracle itself: weakening an expectation to match a
bad engine lets a mutant survive, so the lane fails. Four lanes now:
corpus, drift, differential, mutation. 16 + 14 tests
(`tests/h14-adversarial.test.ts`, `tests/h14-mutation.test.ts`).

**Not closed (operator obligations, not code):** external red team at defined
intervals - recorded as an operator obligation and never an acceptance
criterion; "continuous" is not claimed - this repo has no scheduler and its only
remote is a local bare repo, so the claim is *scheduled* adversarial evaluation,
and a missed night is invisible except via
`scripts/schedule-adversarial.ps1 -Status`. Residual: unknown-unknown attacks,
and the mutation lane is only as good as the mutation operators written.

### H15 — Fail-closed availability engineering **[DONE]** (ADR-027)

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

**Closed (ADR-027):** `src/health.ts` (`HealthState` + `ClockGuard`) plus
chokepoint edits in `src/pdp.ts`, `src/incident.ts`, and `src/rest-api.ts`.
The degraded-mode matrix is explicit and deny-only: IdP unreachable
(`idp-unavailable`, unchanged), store unavailable (`store-unavailable` for the
typed backend error / `evidence-write-failure` for any other failed write),
engine broken (`evaluation-error`), clock fault (`clock-unavailable`, new — a
stalled/backward/unreadable clock must not silently extend authority).
`HealthState` observes what the decision path experiences (append, engine
call, clock read) and emits **one loud signal per transition** — down and
recovery — via `process.emitWarning` instead of one warning per denied
decision. `ClockGuard` is lenient by default (throw/non-finite only) and
enables stall/backward detection only with an injected monotonic reference, so
deterministic test clocks keep working (M10 false-denial budget). Two
ordering defects closed: `issue()` records the issuance event **before**
registering the capability (a store outage refuses the mint; no unaudited
authority), and `unfreeze` records evidence before clearing the freeze while
revoke/freeze apply first and report missed evidence — safety changes that
widen record evidence first; narrowing changes apply first. `revokeAll`
completes the kill switch past per-capability evidence failures;
`IncidentService.engage` completes local enforcement during a store outage and
reports `evidenceRecorded: false`. `GET /healthz` gains `{ idp, store, engine,
clock }` when a `HealthState` is wired (M14 shape unchanged otherwise). The
benchmark measures `authorize()` p99 with and without persistence (advisory
SLO rows; ~1.6 ms vs ~0.2 ms in-process). Rate limiting stays deployment
territory (reverse proxy, DEPLOYMENT.md) — the M14 named non-goal resolved.
Tests-first: `tests/h15-fail-closed-availability.test.ts` (24; 19 initial + 5
audit-follow-up regression cases) — the 2026-10-02 session audit closed 1
must-fix (the broadcast-sync hook bypassed the clock guard, crashing
`authorize`/`issue` on a clock fault in production wiring), 3 should-fix, and
4 nits; see the prompt's audit-follow-up record. Residuals per
ADR-027: in-memory health resets to `ok` on restart (re-marked on the next
observed fault); clock trend detection needs the embedder's monotonic wiring;
the engine-fault reason stays shared with other evaluation errors. The
ROADMAP residual — an induced fault is a DoS — is unchanged and accepted,
now loud, bounded, and recoverable.

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
| M17 | control-plane | its "external verification decides" thesis rests on a writable JSONL log with zero sandboxing — anchoring + capability-gated dispatch close H11/H13 exposure without changing its semantics | none unshipped (M4 flow + M14 API + M16 sandbox all landed) | **[DONE]** |
| M18 | project-raven | self-building always-on agent: unsigned self-update is RCE by design (H12 — H10 signed builds [DONE], the manifest is the update-verification primitive); static device key (H2); unattended fail-closed (H13/H15) | H12 [DONE] (ADR-025) — the gate is cleared; H13/H15/H2 [DONE] (ADR-026/027/028) — unattended fail-closed + credential contract landed; Phase 0 = ADR-029 (local verification, descriptor-in-tree); raven's updater consumes `verifyUpdate`/`applyUpdate`; kickoff 2026-10-01 — prompt at `PROMPTS/M18-federation-project-raven.md` (discovery: raven's upgrade is copy-sync with no verification, builder is headless OpenCode via a systemd path unit) | **[ ]** |
| M19 | home-agent | web→model→shell injection path (H4); unclassifiable personal-data egress (H7); LSM memory tamper-evidence (H11) | M13 machinery exists | **[ ]** |
| M20 | engineering-OS | retire its regex-gated evidence log into ASL's signed EventLog — two evidence planes is the failure mode to avoid | M17 anchor pattern | **[ ]** |

creative-os integrates nothing: it holds the human Decision records that gate
dispatch (SUGGESTION != CANON) and reads audit through the ordinary client
path. Its capture-and-refinement surface is the reason the stack exists, not
a component that needs enforcement.

The federation itself pulls H8 (cross-tenant), H2, and H13 forward — all three
closed (ADR-030, ADR-028, ADR-026). Gate: before any non-personal tenant joins,
H8 must close or its residual be explicitly accepted per deployment — H8 is
closed with ADR-030's named residuals (the shared process / Stage-3 physical
isolation is the one a deployment must accept explicitly).

**LAS portfolio (personal stack).** A second, personal portfolio —
`local-ai-system` assembling ctxd, kgp, eyewright, orbit + supervisor,
creative-OS, engineering-OS, project-raven, and home-agent — treats ASL as a
**cross-cutting** safety/evidence layer rather than one more client row (LAS
ADR-0006; assembly index in
`local-ai-system/docs/architecture/assembly-map.md`). ASL's side of that
boundary — what it will grow (device/service principals, a read-only
status/evidence feed, tailnet service auth) and what it will not do
(orchestrate, store knowledge, decide truth, delete data) — is recorded in
**ADR-032**. The vehicle seams land as their own milestones only when a LAS
caller needs them; nothing here is built speculatively. **ASL's `LAS-I` rows**
(index: `local-ai-system/docs/architecture/assembly-map.md` §5): **I5**
ctxd/kgp ledger-head and digest anchoring into ASL (M17 pattern — consume-only),
**I6** purge certificates as ASL evidence beside H11 holds, **I8** the vehicle
seams themselves (ADR-032).

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
- Capability revocation propagation: ≤ 5 s — immediate in-process (M4 tests);
  cross-node via the revocation channel (H13: throttled pull, default 1 s;
  forced on issuance). Verified live 2026-10-01 against a disposable
  `postgres:16` container (two-instance broadcast, append-only privilege,
  hostile-row skip, cursor replay; audit tickets 10–19).
- Session revocation propagation: ≤ 5 s — immediate in-memory (SessionManager
  tests); bulk tenant/global revocation is on the kill switch and the same
  channel (H13).

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
`PROMPTS/M-Track--DONE/`, and the completion evidence (counts, commits, benchmark
results) lives in `CURRENT_STATE.md` and `AGENT-SESSION.md`.

Stage 0 (EASY) and Stage 1 (MEDIUM) are fully closed as of M15/M16. M17
federation (ADR-022) landed with control-plane as the first client — its
full-format spec is in `PROMPTS/M-Track--DONE/`. The open frontier is Stage 2
(HARD) — the queue is `PROMPTS/H-Track/` (H1 [DONE], H10 [DONE], H12 [DONE],
H13 [DONE], H15 [DONE], H2 [DONE], H8 [DONE], H11 [DONE], H3 [DONE] — ADR-034;
H14 [DONE] - ADR-033 + ADR-035; H4 [DONE] - ADR-036; the remaining items are
H5-H7 and H9).

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

### M17 — Federation: control-plane as first client (ADR-022) **[DONE]**

- **Purpose:** make control-plane the first federation client — anchored
  evidence + capability-gated dispatch across repos, no code merge.
- **Why it matters:** control-plane's "external verification decides" thesis
  rests on a writable JSONL log and unsandboxed workers; the federation
  closes both without changing its semantics.
- **Dependencies:** M14 REST API, M4 capability-request flow, M16 sandbox
  lifecycle — all shipped. The dispatch phase uses the human-gated M4 flow,
  so signed delegation (H1, now done) was never a prerequisite.
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
  export showing federation events. Full prompt: `PROMPTS/M-Track--DONE/M17-federation-control-plane.md`.
