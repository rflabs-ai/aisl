## Verdict: needs-work — delegation can drop the parent's constraints and single-use flag (attenuation bypass in the exact seam H1 closed)
Target: session scope 2026-09-27 — commits 2bb3498 (roadmap drift cleanup), a9cb84b (ADR-022 federation + M17 prompt), f62230d (H1 signed delegation); merges 5c4365c, 06a03c0; uncommitted `benchmarks/results.json` (gate regeneration artifact)
Checks: `npm run typecheck` — pass (exit 0) | `npm test` — pass (499 tests, 484 pass, 15 PG-mode skips, 0 fail) | lint: no lint script exists in package.json

## Ticketed
- 01: .scratch/session-audit/2026-09-27-h1-signed-delegation/issues/01-attenuation-ignores-constraints-and-single-use.md — findOverreach checks 4 of 6 authority dimensions; children can drop constraints and single-use
- 02: .scratch/session-audit/2026-09-27-h1-signed-delegation/issues/02-root-parent-provenance-unvalidated.md — root issuer records delegatedFrom from an unvalidated parent
- 03: .scratch/session-audit/2026-09-27-h1-signed-delegation/issues/03-structural-scan-covers-two-files.md — structural test enforces "nowhere in src/" but scans 2 files
- 04: .scratch/session-audit/2026-09-27-h1-signed-delegation/issues/04-custody-refusals-unaudited.md — revoked/unregistered-parent refusals throw without an audit event

## Findings

### Must fix (ticketed)
- [must] src/capability.ts:296-310 — `findOverreach` covers resourceIds/actions/classification/expiry but not `constraints` and `singleUse`: a child may drop the parent's `network-host`/`param-equals` constraints and escape its single-use flag — strictly wider authority within the same scope, reachable in the delegation flow H1 built. The fuzz matrix (tests/h1-signed-delegation.test.ts:258) claims "every field extreme refuses" but has no case for either; ROADMAP H1 methodology says "attempt every attenuation bypass". Fix: constraint-subset + single-use inheritance checks plus two matrix cases. → 01

### Should fix (ticketed)
- [should] src/capability.ts:187-189 — provenance/`delegatedFrom` is built outside the `authorityRequired` block (164-183), so root + any parent records an unvalidated chain link (fabricated parent id/signature inside a valid child signature). Latent (no root+parent caller today); violates the "validated, walkable chain link" invariant when one appears. Fix: validate whenever a parent is present, or set `delegatedFrom` only in the validated branch. → 02
- [should] tests/h1-signed-delegation.test.ts:288-293 — structural invariant scans only `capability.ts` + `pdp.ts`; the claim it enforces (CURRENT_STATE "What H1 closed") says "anywhere in `src/`". A third file could reintroduce the seam green. Fix: glob `src/*.ts` in the scan. → 03
- [should] src/pdp.ts:97-105 — new custody refusals (revoked/unregistered parent) throw with no audit event; "delegate from a revoked capability" is incident-response signal. Consistent with pre-existing silent issuance throws (not a regression), but these paths are new and next to the event log. Fix: append a deny event before throwing, or name issuance-refusal as a non-eventing class in Claim 7. → 04

### Notes / nits (not ticketed)
- tests/h1-signed-delegation.test.ts:288 — typo "IsherAuthority" in the test name.
- benchmarks/results.json left modified after gate runs; repo convention commits regenerations (cf. 88c987c) — commit with the next gate run or check out.
- PROMPTS/M17-federation-control-plane.md:6 — baseline "475 tests (460 pass…)" is stale post-H1 (499/484), and "Runs PARALLEL to Stage 2 H1" is now historical; refresh at M17 kickoff.
- ROADMAP H1's test methodology lists "key ceremony drills" with no evidence in the Closed note — honest (the note doesn't claim it), but it maps to known-gap #4 / ADR-008 ops work and should be named there when that lands.
- SECURITY_CLAIMS.md:159 pins `src/capability.ts:296` as a line number (will drift) — pre-existing convention across claims, unchanged.

## Clean axes
- Correctness: aside from findings 01–04 — clean. All callers of the changed signatures migrated (`issue`/`issueForRole`/`issueCapability` grepped across src/tests/security-tests); parent checks run signature-before-fields; fail-closed ordering preserved; no secrets in new error messages or provenance (parent signature is integrity data the capability already exposes).
- Spec adherence: docs commits match their asks exactly (drift items 1–4 incl. 99.99996% ≈ 0.4 defects/million SSOT; ADR-022 + M17 prompt + M17–M20 rows + creative-os framing as agreed). H1 commit message's three claims (held-capability attenuation, chain link, service custody) all landed — the over-claim is the fuzz test's "every field extreme" name (finding 01).
- Over-engineering: clean. No new dependencies; `HeldAuthority` is a parameter type, not a speculative abstraction; `DelegatedFrom` is two fields consumed by real logic; one well-formed `ponytail:` marker (ADR-023, ceiling + upgrade path named).
- Tests: convention followed — 24 new H1 tests (refusals, custody, two-hop chain, extremes matrix, structural), legacy invariant 6 and M11 tests migrated to real signed parents; red-first via typecheck. Gaps named in findings 01/03.
- Docs & breadcrumbs: clean — Claim 6 rewritten, ROADMAP H1 [DONE] + working order, CURRENT_STATE counts/what-works/gap #11 struck/what-H1-closed (stale pre-M16 counts fixed in the same sweep), AGENT-SESSION entries, ADR-023. Nits listed above.
- Debt markers: clean — one `ponytail:` (DECISIONS.md ADR-023: no chain-depth limit; every hop attenuates so cycles cannot escalate — upgrade path named). No TODO/FIXME/HACK in the diff.

Highest-leverage action: fix finding 01 — two checks in `findOverreach` (constraints subset, single-use inheritance) plus two matrix cases close the only authority-widening path in the delegation seam.

---

## Resolution (2026-09-27, same session)

All four tickets fixed on ix/h1-audit-findings, commit b1e8454 (gate: 507
tests, 492 pass, 15 PG-mode skips, 0 fail; typecheck clean):

- 01 (must): findOverreach now covers constraints (subset with legitimate
  narrowing via effectiveHostSet intersections) and single-use (leaf
  authorities cannot delegate); +6 tests incl. the narrow-hosts anti-false-
  denial case.
- 02: parentValidityError runs whenever a parent is presented, root included;
  +2 tests (root refuses forged parent; root records a real link).
- 03: structural scan globs all src/*.ts (>= 30 files asserted); test-name
  typo fixed.
- 04: custody refusals append a capability.issue deny event (result: denied,
  capabilityId = parent id, metadata.refusal) before the throw; both custody
  tests now assert the event.

ADR-023 addendum, Claim 6 (claim + mechanism), CURRENT_STATE, ROADMAP H1
Closed note, and the M17 prompt baseline were updated in the same commit.
