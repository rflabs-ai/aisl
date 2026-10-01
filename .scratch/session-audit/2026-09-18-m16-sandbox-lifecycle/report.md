## Verdict: ship-with-notes — correct, well-tested, ADR-aligned; one incomplete ponytail marker ticketed, no must-fix issues
Target: session scope — M16 sandbox lifecycle, commit 95d5075 (feature branch) merged to trunk c130c48; housekeeping commit 88c987c
Checks: typecheck pass · tests 475 total / 460 pass / 0 fail / 15 PG-mode skip · demo exit 0 (section 19 present) · attack exit 0 · benchmark exit 0 (SLO 0 hard failures)

## Ticketed
- 01: .scratch/session-audit/2026-09-18-m16-sandbox-lifecycle/issues/01-ponytail-missing-upgrade-path.md — new ponytail at src/sandbox-registry.ts:244 names its ceiling but not its upgrade path, violating the AGENTS.md debt-marker rule; a swallowed exit-sweep failure is invisible to operators

## Findings

### Must fix (ticketed)
- (none)

### Should fix (ticketed)
- [should] src/sandbox-registry.ts:244 — the `ponytail:` marker on the `sweepExit()` catch block names the ceiling ("swallow per-sandbox sweep failures") but omits the required upgrade path. AGENTS.md mandates both. A failed sandbox teardown during exit sweep is then silently invisible — no event log entry, no operator signal. Fix: append an upgrade path to the comment (e.g. a `sandbox.sweep` summary event or process warning on partial failure). Comment-only; no behavior change. → 01

### Notes / nits (not ticketed)
- [note] src/sandbox-registry.ts:113 — event append (`this.append`) runs AFTER `registry.add` (line 96). If the event store throws (store-unavailable) the resource is registered but the handle is not tracked in `active`/`created` and no create event lands. Acceptable: store-unavailable is a global fail-closed condition; the orphaned resource is harmless and unreachable via `get`/`destroy`. Documented tradeoff, not a defect.
- [note] src/sandbox-registry.ts:63 — the `created` map is never pruned: destroyed sandbox handles accumulate for the process lifetime. Tradeoff for idempotency + unknown-id refusal (the destroy test asserts a re-created id is rejected). Memory cost is small per entry; acceptable until sandbox ids are recycled at scale.
- [note] src/sandbox-registry.ts:144-168 — `execute()` authorizes but does NOT consume the capability. A single-use `sandbox.execute` capability is reusable. Defensible (sandbox-as-scope, not execution-as-scope) and not spec-required; flag if an operator expects one-shot semantics. No behavior change requested.
- [note] PROMPTS/M16-sandbox-lifecycle.md:46 vs implementation — the prompt's literal Phase-1 signature lists `create({ tenantId, sandboxId, limits, attestationPolicy })`. The implementation dropped the undefined `attestationPolicy` param and always-attests (sealed events). ADR-021 is the authority ("Nothing else ships until ADR-021 lands") and specifies always-attested events, so the code correctly follows the ADR over the prompt's aspirational sketch. Worth a one-line ADR note for traceability.
- [note] PROMPTS/M16-sandbox-lifecycle.md:29 vs src/sandbox-registry.ts:189-196 — the spec's Destroy hard requirement says "must remove the Docker container (`docker rm -f`) and any tmpdir mounts." The implementation does NOT shell out to `docker rm -f`; it relies on the existing ephemeral-container model (`docker run --rm`, tmpdirs removed in `finally`), so there is nothing to clean up. Correct for the real ContainerSandbox; the spec text assumes a long-lived-container model that doesn't exist. ADR-021 acknowledges this. Forward-looking note: if long-lived containers are introduced, destroy must gain explicit cleanup.
- [note] src/sandbox-registry.ts:251-257 — `assertTenant` in `get`/`destroy` is defensive: the `active`/`created` maps are keyed by tenant-namespaced id, so cross-tenant lookups miss by construction. The check is only load-bearing when an operator manually rebinds a registry resource to another tenant (covered by the registry-rebind test). Not redundant — it's the trust-boundary guard.

## Clean axes
- Correctness: clean — spawn-before-register ordering prevents orphans; tenant binding re-checked on every lifecycle call; PDP gates every execute(); event payloads are sealed, plaintext metadata carries only digest + kind; no `as any`/`as never`; no secrets in logs/events/errors. Existing ContainerSandbox callers (scenario.ts, enforcement.test.ts) unaffected — constructor signature and `effectiveLimits` defaults are byte-identical to the prior inline defaults.
- Spec adherence: clean — all Phase-1 lifecycle methods present (create/get/list/destroy/attest/execute), events use the exact `EventStore.append` shape the spec requires (action/resourceId/decision/metadata.sealed/metadata.digest), PDP-gated execute, opt-in exit sweep, tenant-scoped lookups. The two prompt-vs-code divergences (attestationPolicy param, docker rm -f) are justified by ADR-021 and the ephemeral-container model respectively. All 6 doc-sweep checkboxes done (ROADMAP, CURRENT_STATE, DEPLOYMENT, SECURITY_CLAIMS Claim 31, AGENT-SESSION, ADR-021).
- Over-engineering: clean — 296 lines for a full lifecycle surface with PDP gating, sealing, attestation, and exit sweep. `SandboxLimits` alias and `SandboxHandle` interface are justified by the spec ("typed config record", "returns the handle"). Two-map design (`active` + `created`) is required for idempotency + unknown-id refusal, not speculative. No unrequested abstractions, no single-implementation interfaces, no config-for-constants.
- Tests: clean — 10 new tests cover every acceptance criterion the spec lists (round trip, limits sealed, attest sealed, destroy refuses unknown id, cross-tenant get undefined, registry rebind flips tenant, PDP-gated execute allow + deny, exit sweep, per-event seal/digest scan). Honest coverage of the Docker/LocalSandbox fallback via `resetDockerCache`. Repo convention (node:test, one suite per module) followed.
- Docs: clean — ROADMAP row 61 → [DONE], CURRENT_STATE counts + what-works + what-M16-closed, DEPLOYMENT.md lifecycle operating notes, SECURITY_CLAIMS Claim 31 (with evidence + known limitations + residual risk), AGENT-SESSION Session 19 entry, ADR-021 in DECISIONS.md.
- Debt markers: one new ponytail (src/sandbox-registry.ts:244) — ticketed for missing upgrade path; one pre-existing ponytail in container-sandbox.ts:40 (module-level bool, ceiling + upgrade path intact, not introduced by this work).

## Highest-leverage action
None blocking. The merge is green on trunk. If anything: append the upgrade path to the exit-sweep ponytail (src/sandbox-registry.ts:244) so the swallowed-failure debt is ledgerable — a one-comment fix, no behavior change.
