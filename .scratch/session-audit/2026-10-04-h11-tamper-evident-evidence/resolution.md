# Resolution — H11 audit follow-up (2026-10-04)

All audit findings and nits ticketed and resolved. `3f71244` = fixes;
this record = tracker + evidence; `benchmarks/results.json` committed here
(milestone boundary, ticket 10).

| Ticket | Status | Fix | Evidence |
|---|---|---|---|
| 01 chain-key precondition | resolved `3f71244` | `chainKeyRefusal` in `src/anchors.ts`; `requireVerifiableChain()` in `evidence checkpoint\|hold\|release`; DEPLOYMENT precondition bullet | `tests/h11-…` chain-key describe (2); CLI hold smoke exit 0 |
| 02 stale Claim 8/19 refs + surface enum | resolved `3f71244` | refs de-numbered to symbol names; `flushAnchors` added to CURRENT_STATE enumeration | `grep -F` verifications in ticket |
| 03 dead `KNOWN_ACTIONS` | resolved `3f71244` | set deleted (neighbors remain — all used) | `git grep KNOWN_ACTIONS HEAD -- src` → no hits |
| 04 `sentAt` → `eventAt` | resolved `3f71244` | wire field renamed (payload, docstring, test, DEPLOYMENT) | `git grep -F "sentAt" HEAD -- src tests DEPLOYMENT.md` → no hits |
| 05 ahead-error noise | resolved `3f71244` | per-line pushes removed; `aheadOfBundle` + one aggregate error | truncation test still green |
| 06 witness caveat | resolved `3f71244` | in-memory note added to the witness branch | CLI smoke |
| 07 rebuild-chain duplication | accepted (no change) | contracts differ (targeted mutation vs prefix demo); sharing imports adversarial code into `src/` | ticket rationale |
| 08 untested branches | resolved `3f71244` | 2 tests: signed eventCount mismatch; head cap | suite 39/39 green |
| 09 pdp evidence-read set | resolved `3f71244` | rationale + future freeze-interaction note in the docstring (no behavior change) | `git grep -F "evidence.hold" HEAD -- src/pdp.ts` |
| 10 results.json uncommitted | resolved here | committed at this boundary | `git status` clean for the milestone |
| 11 line-count drift | resolved `3f71244` | refreshed to ~14,000 / 48 modules / 716 tests | `Measure-Object` = 14000; gate below |

Follow-up gate (this run): `npm run typecheck` clean; `npm test` 716 tests /
695 pass / 0 fail / 21 Postgres-mode skips (`follow-up-test.txt`);
`npm run supply-chain` PASS (run in `3f71244`'s pre-commit hook);
demo exits 0 (section 24 unchanged).