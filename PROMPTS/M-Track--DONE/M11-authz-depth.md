# M11 — Authz depth: Granular RBAC + Classification propagation + Configuration management

Baseline: M10 complete — the SLO gate exists and its hard targets must not
regress (run `npm run benchmark` at the end). Read first: `src/policy.ts`
(`PolicyRule`, `PrincipalMatch` with `roles`, `BASELINE_POLICY`,
`createPolicyEngine`), `src/capability.ts` (`issueCapability`, attenuation),
`src/pdp.ts` (`evaluate`), `src/registry.ts` (`defineResource`,
`ingestDocument`), `src/policy-testing.ts` + `tests/fixtures/policy/`,
`CURRENT_STATE.md` known-gap #6 ("Policy is code"), `DECISIONS.md` ADR-002
(attenuation).

Three Stage-1 rows, one milestone, zero new runtime dependencies.

- **Granular RBAC** — "roles compose with capabilities" (identity, M, MVP).
  Today: `Principal.roles` is a free string list and policy rules can match
  roles (`matchesPrincipal`), but roles have no definition and capability
  issuance ignores them.
- **Classification propagation** — "labels flow to derived artifacts"
  (registry/ingestion, L, P). Today: classification is fixed at
  `defineResource`; ingested docs and tool-created artifacts inherit nothing.
- **Configuration management** — "versioned, reviewable, attributable" (M, P).
  Today: policy is code in `src/policy.ts` (known-gap #6): no version,
  signature, review gate, or attribution.

## 1. Subagents + parallelization (explicit)

- **Subagent A — Granular RBAC.** Owns `src/policy.ts` (role validation),
  `src/capability.ts` (role-templated issuance), `src/domain.ts` (role types
  if needed), tests.
- **Subagent B — Classification propagation.** Owns `src/registry.ts`,
  `src/runtime.ts` (seal / derived-artifact paths), tests.
- **Phase 1: A ∥ B run in PARALLEL** — disjoint module surfaces.
- **Phase 2: Subagent C — Configuration management.** Owns new
  `src/policy-config.ts` + the engine-construction seam + tests. Runs AFTER A
  because both touch `src/policy.ts`; C consumes A's role surface but must not
  edit it.
- **Shared-file rule:** only the main session edits `src/cli.ts` (demo and
  benchmark merges); nobody edits the M10 `slo` block except additively through
  the main session.

## 2. A — Granular RBAC

Deliverables:

1. **Role = first-class data:** `{ id, tenantId, description?, actions:
   readonly Action[], maxClassification: Classification }`. A versioned
   constant/table (C's bundle mechanism consumes it later).
2. **Role-templated issuance:** `AuthorizationService.issueForRole(issuer,
   roleId, subject, resourceIds, opts)` — mints through `issueCapability` with
   `IssueRequest.maxClassification` capped at the role's ceiling. The issuer
   authority checks (invariant 6, ADR-002) are untouched and explicitly
   exercised.
3. **Policy cross-validation:** a rule referencing a role in
   `principals.roles` that grants actions beyond that role's set, or a
   `maxClassification` above the role's ceiling, is rejected at engine
   construction — fail closed (`PolicyCompilationError`-style).
4. Tests: role caps issuance; over-privileged `issueForRole` throws; unknown
   role fails closed; cross-validation rejects widening rules; `verifyCapability`
   still enforces everything (no bypass); M2/M4 suites unaffected.

Invariant: **roles narrow authority; they never mint it.** Issuance stays
issuer-checked.

## 3. B — Classification propagation

Deliverables:

1. Ingest path (`ingestDocument`): a derived artifact's classification is the
   max rank of its source resources' classifications. It can only **raise**,
   never lower. Unknown label → rank 100 (fail toward sensitivity).
2. Runtime write path: when a tool creates or writes a resource
   (`changed: true`), the derived artifact and the recorded evidence inherit
   the max of the input classifications feeding the step. Reuse
   `classificationRank`; no new ranking logic.
3. Event metadata: derived artifacts record the derived label (additive field);
   verify the sealed record uses the derived classification's key.
4. Tests: derived-from-confidential is confidential; public+phi → phi; unknown
   label wins; labels never lower; seal `keyId` matches the derived label.

Invariant: propagation raises labels; it never downgrades; a derived label
feeds ceilings, never grants.

## 4. C — Configuration management

Deliverables:

1. **Policy bundle:** `{ id, version, rules, provenance: { source, reviewedBy?,
   approvedAt? }, hash }` — `hash = canonicalJson({ version, rules })`;
   `loadPolicyBundle(bundle)` verifies the hash and refuses mismatch (fail
   closed).
2. Engine construction from a bundle appends one `policy.load` event (version,
   hash, rule count, provenance). Plain-rule engines (tests) skip the event —
   the seam stays optional.
3. `npm run policy:diff` verifies bundle hashes before diffing; overlay files
   gain `{ version, provenance }`.
4. A's role table loads through the same versioned-bundle mechanism.
5. Tests: tampered rules → hash mismatch → refuse; load event appended once;
   diff works against a versioned bundle; the legacy unversioned path still
   works for tests.

This strikes the "policy is code" gap at the root: the boundary becomes a
verified artifact. Say honestly in the docs: authoring is still in-repo (the
review gate is git), not a service.

## 5. Demo (main session)

One section: role-scoped issuance (a capability minted narrower than the role
would allow is refused / mints at the role ceiling), a derived-artifact label,
and a versioned policy bundle load + tamper refusal.

## 6. Docs sweep (main session)

- ROADMAP rows Granular RBAC / Classification propagation / Configuration
  management → `[DONE]` with milestone refs.
- CURRENT_STATE: counts; known-gap #6 moved to "What M11 closed" (stated
  honestly — authoring is versioned + attributed + hash-verified; the review
  gate is git).
- SECURITY_CLAIMS: new claims per house structure (role-templated issuance
  cannot exceed the role; propagation only raises; bundles fail closed on
  tamper) — mechanism/test/limitations each.
- AGENT-SESSION entry. DECISIONS.md only if a real decision was made (the role
  model) — reference ADR-002.

## 7. Constraints

- Zero new runtime dependencies. Invariants 1–13 hold; R3 untouched; M7
  fixtures still pass; M10's hard SLO targets do not regress.
- Roles and propagation never widen authority — test both negatively.

## 8. Acceptance + skip list

Acceptance: gate green; SLO hard targets green; new claims have passing tests;
demo runs; docs updated.

skipped: role inheritance hierarchies, dynamic role CRUD API, ABAC beyond the
existing conditions, per-role approval routing.
add when: an operator actually defines more than a handful of roles or asks for
nested roles.
