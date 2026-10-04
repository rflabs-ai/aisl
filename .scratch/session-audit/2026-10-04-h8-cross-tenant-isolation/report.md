# Session audit — H8 cross-tenant isolation (branch `feat/h8-cross-tenant-isolation`, `main...HEAD`)

## Verdict: ship — the probe is real, both fixes are sound and regression-covered, every headline claim reproduced fresh; only polish-level nits remain

Target: `git log main...HEAD` — 2 commits (`5a86157` ADR-030 docs-only; `a477ec7` probe + 2 fixes + docs sweep), 13 files, +1469/−58. Working tree: `benchmarks/results.json` churn + 6 untracked `.scratch/h8/` artifacts (convention-compliant).

Checks:
- `npm run typecheck` — pass (exit 0)
- `npm test` — pass: 676 tests / 655 pass / 0 fail / 21 skip (fresh run)
- `npm run demo` — pass (exit 0)
- benchmark — pass via the suite's `slo.test.ts` execFileSync gate inside the fresh `npm test` run (subagent's `.scratch/h8/benchmark.txt` = reported, not re-run)

## Ticketed
- (none — nothing rose above nit)

## Findings

### Must fix (ticketed)
- (none)

### Should fix (ticketed)
- (none)

### Notes / nits (not ticketed)
- `src/capability-request.ts:212` — the `requireSameTenant` docstring says "embedders and the guard's escalation lane call it directly", but the lane only submits (`src/guard.ts:194: const request = ctx.capabilityRequestService.submit(`). One-line docstring fix; the check itself is correct and probe-covered (both `approve` and `deny`).
- `tests/h8-cross-tenant-probe.test.ts:401-415` — `rest-healthz-and-static-page` is labeled `exposure: 'enforced'` but asserts only a no-leak property; ADR-030's "log-scan property" class (decision 1(b)) has no code label. Cosmetic taxonomy drift.
- `tests/h8-cross-tenant-probe.test.ts:515-527` — `session-manager-tenant-scoped-bulk` asserts one direction (tenant-A bulk revoke spares B's session); no reverse row. Mitigated by `rest-sessions-cross-tenant` + `log-scan`.
- `revealEvidence`'s keyTenant refusal (`src/pdp.ts:694`) runs before the auth check, so even an unauthenticated in-process caller produces one deny event in its claimed tenant — fail-closed, no authority consequence, but ordering differs from `authorize()` (auth-first).
- `.scratch/h8/` is split: `red.txt` committed, while `commit.txt` (89 KB), `full-gate.txt` (88 KB), `benchmark.txt`, `demo.txt`, `green-check.txt`, `hypotheses.ts` remain untracked. Harmless; pick one convention.
- No REST route exposes `CapabilityRequestService.deny` (`addRoute` grep: 6 routes, none call deny) — which makes the new `requireSameTenant` on `deny` that path's *only* tenant guard. Worth a line in Claim 38 someday; not a defect.

## Clean axes
- Correctness: clean — typecheck 0; fresh suite 676/655/0/21; caller greps: `approve`'s only src caller is `rest-sessions.ts:192` behind the boundary check (`:164`), `deny` has no REST caller, `revealEvidence` has no src caller (embedder seam); the refusal writes nothing (probe asserts `capability.approve` event count unchanged); legacy-seal cross-tenant behavior is code-cited (`seal.ts:165: if (!v2) return open(sealed);` + `pdp.ts:694` guard skips `undefined` tenants) and explicitly acknowledged as a residual in DECISIONS.md:2202, SECURITY_CLAIMS.md:2038, and CURRENT_STATE "What H8 closed" item 1 — named, not hidden.
- Enum-exhaustive: clean — no union type changed (`DenyReason` untouched; the fix reuses `tenant-mismatch`); the probe's `exposure` union ('enforced' | 'global-by-design') is traced across all 20 rows (19 + 1); `tenantFromKeyId`'s `undefined` branch (legacy/unknown shapes) is traced to the documented fallback.
- Spec adherence: clean — ADR-030 decisions 1–5 all present (probe table, key binding before registration/authorization, decision-surface tenancy, named global-by-design surfaces, no new deps/routes); "22 cases" matches the file (20 + 2 PG); red-first evidenced by the committed `.scratch/h8/red.txt` (3 failures with the exact leak payloads); commit messages match content; the `--no-verify` on `5a86157` is documented and the commit is genuinely docs-only (DECISIONS.md +144, nothing else).
- Over-engineering: clean — one new export (`tenantFromKeyId`, seal.ts:95) with a real consumer; no new module, no new dependency (no `package.json` in the diff), no speculative config.
- Tests: convention honored — red captured before the fixes; both fixes have direct regression rows (`capability-request-service-tenancy`, `evidence-key-binding`) plus the `tests/evidence.test.ts` extension asserting the deny event and the no-foreign-key-id property.
- Docs & breadcrumbs: clean — ROADMAP (`H8 [DONE]` + working order math verified: 7 done, remaining eight named), CURRENT_STATE (header counts verified exact: 12,744 src lines measured / 46 modules / 676 tests), SECURITY_CLAIMS Claim 38 (evidence + limitations match the fresh gate), THREAT_MODEL cross-tenant row, AGENT-SESSION SESSION 36, prompt stub `[x] [DONE]` + resolution.
- Debt markers: clean — diff marker grep yields only a test-output line (`ℹ todo 0` inside committed red.txt); ADR-030's residual section names each ceiling with a migration path.

## Citation audit
| finding | command run | output line |
|---|---|---|
| fix-1 guard | `Select-String src\pdp.ts -Pattern 'keyTenant'` | `pdp.ts:694: if (keyTenant !== undefined && keyTenant !== principal.tenantId) {` |
| fix-1 second binding | same run | `pdp.ts:736: return openFor(principal.tenantId, sealed);` |
| legacy fallback (residual) | `Select-String src\seal.ts -Pattern 'if \(!v2\) return open'` | `seal.ts:165: if (!v2) return open(sealed);` |
| fix-2 | `Select-String src\capability-request.ts -Pattern 'requireSameTenant'` | `capability-request.ts:152:` and `:235:` `this.requireSameTenant(request, reviewer);` |
| nit-1 | `Select-String src\capability-request.ts -Pattern 'escalation lane'` + `Grep capabilityRequestService src/guard.ts` | `capability-request.ts:212: * must hold on its own (embedders and the guard's escalation lane call it` / `guard.ts:194: const request = ctx.capabilityRequestService.submit(` |
| REST boundary | `Select-String src\rest-sessions.ts -Pattern 'request.tenantId !== ctx.principal.tenantId'` | `:148` and `:164: if (request.tenantId !== ctx.principal.tenantId) throw new RestRejection(403, 'tenant-mismatch');` |
| legacy residual acknowledged | `Select-String DECISIONS.md -Pattern 'tenant-agnostic'` | `DECISIONS.md:2202: evidence-key:<level>` seals keep their documented tenant-agnostic behavior` |
| red evidence | `Read .scratch/h8/red.txt` | `actual: 'globex-only-content', expected: undefined` (evidence.test.ts:178) / `Missing expected exception` (probe:538) / `actual: 'globex-sealed-h8probe-b-be47b0c7-…'` (probe:566) |
| probe row count | `Select-String tests\h8-cross-tenant-probe.test.ts -Pattern "id: '"` + PG describe | 20 case ids + `describe('H8 probe: Postgres-gated storage surfaces'` with 2 `{ skip: PG_SKIP }` tests |
| docs counts | `Get-ChildItem src -Filter *.ts \| Get-Content \| Measure-Object -Line` | `src lines: 12744` / `modules: 46` — matches CURRENT_STATE header |
| checks | typecheck / npm test / demo | `TYPECHECK EXIT: 0` / `ℹ tests 676 … pass 655 … fail 0 … skipped 21` / `DEMO EXIT: 0` |

Self-falsification: all cited strings re-verified at their lines in this run (`Select-String -SimpleMatch` pass: pdp.ts:694/736, seal.ts:165, capability-request.ts:152/212/235, rest-sessions.ts:148/164, guard.ts:194, DECISIONS.md:2202 — all hit; no empty answers). Ledger: `.scratch/session-audit/2026-10-04-h8-cross-tenant-isolation/evidence.md`.

---

## Resolution (f61817e, 2026-10-04)

All five nits resolved on `feat/h8-cross-tenant-isolation` (commit
`f61817e`): the `capability-request` docstring audience, the probe's
`log-scan` exposure class, the reverse-direction session-row assertion, the
`revealEvidence` ordering rationale, and the Claim 38 `deny`-guard note.
Suite unchanged: 676 / 655 pass / 0 fail / 21 skip (focused probe: 22 tests,
20 pass, 2 PG skips). Scratch artifacts committed under `.scratch/h8/`;
fast-forward merged to `main` as instructed.
