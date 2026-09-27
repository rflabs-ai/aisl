# M5 — Hierarchical Resource Matching

Begin M5. Read PROJECT_CONTEXT.md, ARCHITECTURE.md, SECURITY_CLAIMS.md (Claim 6, Claim 7), DECISIONS.md (ADR-001), ROADMAP.md (Stage 1 — Hierarchical resource matching, CURRENT_STATE.md known-vulnerabilities item 14), AGENT-SESSION.md, and `src/policy.ts`.

Goal: today `PolicyRule.resources` matches by exact `type` and exact `id` only — see `ResourceMatch` (`src/policy.ts:28`). A rule cannot say "all documents under project X" or "every repo whose id starts with `acme/`". Operators author many near-identical rules or over-broad `ids: [...]` lists to approximate hierarchy, which is error-prone and silently too broad. Implement prefix and glob matching on `id`, and `type + id` namespace prefixes (e.g., `acme/*` matches any id that begins with `acme/`).

This closes CURRENT_STATE.md known-vulnerabilities item 14 ("Policy cannot express resource hierarchy") and reduces the cost of expressing per-tenant or per-project rules.

## 1. Match grammar

Extend `ResourceMatch` (`src/policy.ts:28`) without changing the existing shape:

```typescript
export interface ResourceMatch {
  readonly types?: readonly ResourceType[];
  readonly ids?: readonly string[];
  /** Hierarchical match patterns. A pattern matches a resource id when any
   *  of the listed patterns matches. Patterns are tried in order; first match wins.
   *
   *  Syntax:
   *    `tenant/...`     — recursive: any id strictly under `tenant/` (a path segment boundary)
   *    `prefix*`        — single-segment glob: any id that starts with `prefix`
   *    `prefix?`        — single-character wildcard
   *    literal          — exact match (no wildcard)
   *
   *  `tenant/...` is the documented canonical form for hierarchy. `prefix*` is a
   *  pragmatic fallback for ids that use a flat namespace (no slashes).
   */
  readonly idPatterns?: readonly string[];
  /** Resource classification is at or below this ceiling. */
  readonly maxClassification?: Classification;
}
```

Add the matching helper `matchesIdPattern(resourceId: string, pattern: string): boolean` in `src/policy.ts`. Wire it into `matchesResource` (currently around line 107) so that a rule with both `ids` and `idPatterns` matches if either side matches; a rule with only `idPatterns` matches only by pattern.

Do **not** change `ids` semantics. Do **not** add a third match kind beyond prefix/glob.

## 2. Boundary semantics

`tenant/...` must NOT match `tenant-other` (boundary at the slash). `tenant/*` (no `...`) is a single-segment glob, so it matches `tenant/foo` but not `tenant/foo/bar`. Both forms are needed; both are explicit.

Document this in a header comment in `src/policy.ts` next to `ResourceMatch`. Add a test that proves the boundary behavior:

- `matchesIdPattern('acme/foo', 'acme/...')` → `true`
- `matchesIdPattern('acme/foo/bar', 'acme/...')` → `true`
- `matchesIdPattern('acme-other', 'acme/...')` → `false` (boundary)
- `matchesIdPattern('acme/foo', 'acme/*')` → `true`
- `matchesIdPattern('acme/foo/bar', 'acme/*')` → `false` (single segment)

## 3. Pattern safety

Patterns are evaluated in the PDP hot path. Constraints:

- No regex compilation per call. Compile each pattern once when the rule is loaded and cache the matcher. Add an internal cache `Map<string, IdPatternMatcher>` keyed by the pattern string, populated by `createPolicyEngine` (or a `compileRule` helper) before evaluation. The matcher is `O(|resource id|)` per evaluation.
- Reject pathological patterns at compile time. If a pattern has more than 64 characters, contains nested wildcards in an unsupported position (e.g., `**/foo`), or fails the documented grammar, throw a `PolicyCompilationError` from `createPolicyEngine`. Tests must exercise each rejection path. The hot path must never throw on a pattern; if the cache misses (defensive), fall back to literal match and emit a single-line warning to stderr — do not fail closed on a hot-path cache miss.
- The matcher must be a pure function over `(resourceId, compiledPattern)` — no regex backreferences, no capture groups, no nested quantifiers.

Ponytail: reuse the existing `NO_MATCH` flow. Don't introduce a parallel match function if a one-line edit to `matchesResource` does it.

## 4. Tests

Add `tests/m5-hierarchical-matching.test.ts` (place next to `tests/policy.test.ts`). Minimum cases — each must fail without the change:

- **Pattern compile**: `createPolicyEngine` accepts a rule with `idPatterns: ['acme/...']` and produces a compiled matcher.
- **Recursive match**: rule with `idPatterns: ['acme/...']` allows `acme/foo` and `acme/foo/bar`.
- **Boundary rejection**: rule with `idPatterns: ['acme/...']` denies `acme-other` and `acmefoo`.
- **Single-segment glob**: rule with `idPatterns: ['acme/*']` allows `acme/foo` and denies `acme/foo/bar`.
- **Type + pattern**: rule with `types: ['repository']` and `idPatterns: ['acme/...']` allows `repository` ids under `acme/...` and denies other types.
- **Cross-pattern OR**: rule with both `ids: ['literal-id']` and `idPatterns: ['acme/...']` matches either form.
- **Compilation rejection**: a pattern longer than 64 chars throws; a pattern with `**` throws; a pattern that mixes unsupported syntax throws. The PDP never throws on a hot-path lookup.
- **Hot-path cache**: invoking `evaluate()` repeatedly with the same rule does not recompile the pattern. (Assert by spying on the compile function — `tests/invariants.test.ts` has the pattern for this.)
- **Existing suite green**: all 166 prior tests still pass.

## 5. Demo / benchmark

Add a small section to the demo (`src/cli.ts`) showing the new matching in action: a rule with `idPatterns: ['acme/...']` allows a deeply-nested read, denies a flat `acme-other` id. Do not expand the demo's section count beyond what's necessary.

The benchmark (`npm run benchmark`) and attack harness (`npm run attack`) need no change — they exercise existing matching. Update `benchmarks/results.json` after the demo/benchmark run; it should be unchanged modulo `generatedAt` and `head`.

## 6. Update docs

- **SECURITY_CLAIMS.md Claim 6 (attenuation)** — note that hierarchical matching adds a new way to express a scope ceiling without enumerating ids, but it does not weaken attenuation: the matcher still respects the per-rule resource ceiling and the per-capability `resourceIds` array. If a capability lists specific resource ids, the matcher only succeeds against those ids; patterns in the rule do not expand the set of ids the capability may reach.
- **ROADMAP.md Stage 1 — Hierarchical resource matching** — flip to **[DONE]**.
- **CURRENT_STATE.md known-vulnerabilities item 14** — strike through, move to a new "What M5 closed" section with one paragraph describing the matcher and the boundary semantics.
- **AGENT-SESSION.md** — add a SESSION 4 entry summarizing what was built, what was deferred (if anything), and the next session's first action.

## 7. Constraints

- Zero new runtime dependencies.
- Do not change the policy semantics: default deny, deny-overrides, approval-gating, classification ceilings. The new matcher fits inside the existing `matchesResource` call.
- Do not change `Capability.resourceIds` semantics — capabilities still list explicit ids. Hierarchical matching only widens *which rules apply*; it does not widen *which resources a capability may reach*.
- Performance budget: the existing benchmark is the floor. `evaluate()` for a single rule with one pattern must be ≤ 2x the cost of the same rule with a literal `ids: [...]` list. If a micro-benchmark shows a regression beyond that, profile and fix before merging.

## 8. Acceptance

`npm run typecheck && npm test` green; 166 prior tests still pass; the new M5 tests pass; `npm run demo` and `npm run benchmark` still produce sane output; `benchmarks/results.json` regenerates; CURRENT_STATE, ROADMAP, SECURITY_CLAIMS, AGENT-SESSION updated. Report what you skipped and why.
