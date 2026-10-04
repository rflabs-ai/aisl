# Audit report — H11 tamper-evident evidence (2026-10-04)

## Verdict: ship-with-notes — the evidence mechanism is tested, gated, and demo-proven; three small should-fixes (one behavioral precondition, two doc/dead-code hygiene)
Target: session scope — commits `6ab8386`, `1bc6bda`, `f70ef41` on `feat/h11-tamper-evident-evidence` (range `b3e345b..HEAD`, 26 files, +3251/−81); working tree clean except `benchmarks/results.json` (milestone convention).
Checks:
- `npm run typecheck` — **pass** (exit 0)
- `npm test` — **pass** (712 tests / 691 pass / 0 fail / 21 Postgres-mode skips; this run)
- `npm run supply-chain` — **pass** (exit 0)
- `npm run demo` — **pass** (exit 0; section 24 all five checks green: VERIFIED / DETECTED ×2 / RECORDED / DELIVERED 7/7)
- benchmark — **pass, re-run** inside `npm test` (`benchmark integration (M10 slo block)`, 72712.9 ms, SLO 0 hard failures)

## Ticketed
- 01: `.scratch/session-audit/2026-10-04-h11-tamper-evident-evidence/issues/01-evidence-hold-signing-key-precondition.md` — PG-mode `evidence hold/release` appends with the CLI process's (ephemeral) key, no H13-style fail-closed key precondition
- 02: `.scratch/session-audit/2026-10-04-h11-tamper-evident-evidence/issues/02-claim8-stale-line-refs-and-eventlog-surface.md` — Claim 8/19 cite five stale `events.ts` line numbers; CURRENT_STATE "exposes only …" omits `flushAnchors`
- 03: `.scratch/session-audit/2026-10-04-h11-tamper-evident-evidence/issues/03-policy-testing-dead-known-actions.md` — dead, drifted `KNOWN_ACTIONS` hand-copy in `policy-testing.ts:79` (pre-existing M17 drift, extended by the two new actions)

## Findings

### Must fix (ticketed)
- (none)

### Should fix (ticketed)
- [should-fix] `src/cli.ts:1916-1917,1929-1930` — `evidence hold`/`release` append to a shared Postgres chain with no signing-key precondition; without `EVENT_SIGNING_*_PEM` (`src/events.ts:343,355`) the CLI process signs with an ephemeral key, so the hold event's signature can never verify under the deployment key — H13's `preserve` refuses this exact case fail-closed (`src/incident.ts:765-768`) and DEPLOYMENT.md:490-492 documents the precondition for preserve only. Minimal fix: mirror H13's refusal + hint in the hold/release branches; add the precondition line to the H11 runbook. → ticket 01
- [should-fix] `SECURITY_CLAIMS.md:251,252,257,258,260` (Claim 8) and `:709-713` (Claim 19) — cite `src/events.ts:83/147/204/269/357` and `:122/147/154/141`; actual positions are 87/253/430/122/621 and 352. Plus `CURRENT_STATE.md:69-70` "exposes only `append`, `all`, … `close`" — `flushAnchors` (`src/events.ts:117,504`) makes "only" false. Minimal fix: renumber/de-number the claim refs; extend the enumeration. → ticket 02
- [should-fix] `src/policy-testing.ts:79-94` — `KNOWN_ACTIONS` is declared and never read (single `git grep` hit), a hand-copy of `KnownAction` already missing `anchor.register` (M17) and now `evidence.hold`/`evidence.release`. Minimal fix: delete it (the validator's `asAction` only shape-checks) or derive it from `KnownAction`. → ticket 03

### Notes / nits (not ticketed)
- `src/anchors.ts:191` — `sentAt: point.at` carries the event's timestamp, not the send time; field name overpromises.
- `src/anchors.ts:429` — one error line per anchor-line ahead of the bundle head; a large truncation prints many near-duplicates.
- `src/cli.ts:1890-1898` — `evidence witness` from an empty default world refuses via `src/anchors.ts:466` (`'the bundle has no events to anchor'`) without the in-memory caveat that `status`/`hold` print (`cli.ts:1752,1818,1920`).
- `src/cli.ts` `resignChain` duplicates the H11 test's `rebuildChain` — acceptable test/CLI separation, noted for awareness.
- Untested branches: `verifyCheckpoint`'s `eventCount !== seq+1` refusal and the `MAX_WITNESS_HEADS` cap have no direct case.
- `src/pdp.ts:97` `EVIDENCE_READ_ACTIONS` does not include the new actions — safe today: no REST route or minting surface routes `evidence.hold`/`evidence.release` through the PDP (RetentionLedger appends directly, tenant-bound at `src/retention.ts:82,120`). A future capability-gated hold path must decide freeze-interaction explicitly.
- `benchmarks/results.json` left modified, uncommitted — precedented (H2/H13/H15 sessions; committed at explicit milestone/audit boundaries).
- CURRENT_STATE says "~13,962" src lines; this run counts 13,965 across 48 modules — within the tilde.

## Clean axes
- Correctness (callers/signatures): clean — `npm run typecheck` exit 0; the `EventStore` port gained `flushAnchors` and both implementers plus the `ThrowingEventLog` test stub compile against it (typecheck is the proof); sink fan-out is try/catch-wrapped (`src/events.ts:486-498`, PG mirror identical — `git grep -F 'threw on publish (evidence append unaffected)'` hits both append paths).
- Enum-exhaustive (`evidence.hold`/`evidence.release` through every action gate): clean with two scoped notes — `KnownAction` has 16 members (`src/domain.ts:170-172`); traced filter sites: `src/pdp.ts:97` (freeze exception — new values absent, but no PDP-routed path exists; note above), `src/policy-testing.ts:79` (dead set — ticket 03), no REST route accepts them, no baseline role grants them.
- Security (secrets/trust boundaries): clean — witness token is env-only and redaction is tested (H11 suite: "the witness token is sent as a header and never appears in status or errors"); hold metadata carries seqs + operator-typed reason (H13's non-secret convention); no secrets in events/errors (full suite green).
- Spec adherence: clean — every prompt item shipped (6 CLI subcommands, `npm run evidence:status`, demo section 24 exit 0 this run, H8 probe row `tests/h8-cross-tenant-probe.test.ts:568`, ROADMAP record); the skip list is named in ADR-031 and the prompt.
- Over-engineering: clean — one port, two sinks, both consumed (CLI/tests/probe); checkpoints reuse the event key (no new key/authority, per ADR-031); two speculative helpers (`mutatingStoreMethods`, `RetentionSourceEvent`) were deleted before commit and never landed.
- Tests: clean — tests-first honored (red at `.scratch/h11/red.txt`), 35 H11 cases + the probe row in this run's suite; every new fail path (sink throw, witness 4xx/5xx, queue drop, fork, truncation, unanchored tail, checkpoint rewrite/truncation/fork, cross-tenant hold) has a case; two untested branches noted above.
- Debt markers: clean — exactly one new `ponytail:` (`src/anchors.ts:237`, names the paging ceiling + upgrade path); the closed M17 in-memory marker was removed rather than left; no TODO/FIXME/HACK in the diff.
- Docs & breadcrumbs: covered by ticket 02 (two precise spots); all other touched docs (ROADMAP, THREAT_MODEL, TM-004, DEPLOYMENT, COMPLIANCE, PROJECT_CONTEXT, AGENT-SESSION, prompt) verified current against HEAD this run.
- Dedupe: clean — no open ticket overlapped H11 files (only resolved `2026-10-02-h15` and `2026-10-04-h8` audit dirs exist).

## Citation audit
| finding | command run | output line |
|---|---|---|
| cli.ts hold (F01) | `git grep -F "const hold = ledger.hold(world.user, { tenantId, fromSeq, toSeq, reason });" HEAD -- src` | `HEAD:src/cli.ts:      const hold = ledger.hold(world.user, { tenantId, fromSeq, toSeq, reason });` |
| incident keyHint (F01) | `git grep -F "chain.detail === 'signature mismatch' && !process.env.EVENT_SIGNING_PUBLIC_KEY_PEM" HEAD -- src` | `HEAD:src/incident.ts:        chain.detail === 'signature mismatch' && !process.env.EVENT_SIGNING_PUBLIC_KEY_PEM` |
| ephemeral key (F01) | `git grep -F "using ephemeral Ed25519 event signing key" HEAD -- src` | `HEAD:src/events.ts:    'EVENT_SIGNING_*_PEM unset: using ephemeral Ed25519 event signing key (not durable across restarts)',` |
| DEPLOYMENT precondition (F01) | `git grep -F "the operator process must share the event-signing key" HEAD` | `HEAD:DEPLOYMENT.md:   **Precondition:** the operator process must share the event-signing key` |
| Claim 8 stale ref (F02) | `git grep -F "src/events.ts:83" HEAD -- SECURITY_CLAIMS.md` | `HEAD:SECURITY_CLAIMS.md:the previous event's hash (`src/events.ts:83`); Ed25519 signature per event` |
| exposes-only (F02) | `git grep -F "The EventLog class exposes only" HEAD -- CURRENT_STATE.md` | `HEAD:CURRENT_STATE.md:  database access. The EventLog class exposes only `append`, `all`,` |
| flushAnchors (F02) | `git grep -F "flushAnchors(): Promise<void>;" HEAD -- src` | `HEAD:src/events.ts:  flushAnchors(): Promise<void>;` |
| dead KNOWN_ACTIONS (F03) | `git grep -F "const KNOWN_ACTIONS: ReadonlySet<string> = new Set<string>([" HEAD -- src` | `HEAD:src/policy-testing.ts:const KNOWN_ACTIONS: ReadonlySet<string> = new Set<string>([` |
| new action (enum) | `git grep -F "| 'evidence.hold'" HEAD -- src` | `HEAD:src/domain.ts:  | 'evidence.hold'` |
| freeze exception (enum) | `git grep -F "new Set(['query.audit', 'audit.export', 'evidence.decrypt'])" HEAD -- src` | `HEAD:src/pdp.ts:const EVIDENCE_READ_ACTIONS: ReadonlySet<string> = new Set(['query.audit', 'audit.export', 'evidence.decrypt']);` |
| sink wrap (correctness) | `git grep -F "threw on publish (evidence append unaffected)" HEAD -- src` | `HEAD:src/event-store-pg.ts:          process.emitWarning?.(\`anchor sink '${sink.name}' threw on publish (evidence append unaffected)\`);` |
| truncation error (correctness) | `git grep -F "an anchor source is ahead of the bundle head: tail truncation suspected" HEAD -- src` | `HEAD:src/anchors.ts:      errors.push('an anchor source is ahead of the bundle head: tail truncation suspected');` |
| tenant-bound hold (correctness) | `git grep -F "a principal may only hold evidence in its own tenant" HEAD -- src` | `HEAD:src/retention.ts:      throw new RetentionError('a principal may only hold evidence in its own tenant');` |
| memory-world fix (regression) | `git grep -F "const sinks = options.anchors ?? (options.memory ? [] : anchorSinksFromEnv());" HEAD -- src` | `HEAD:src/scenario.ts:175: const sinks = options.anchors ?? (options.memory ? [] : anchorSinksFromEnv());` |
| new ponytail (debt) | `git grep -F "ponytail: no paging" HEAD -- src` | `HEAD:src/anchors.ts: * ponytail: no paging — one witness response must carry every head, capped to` |
| probe row (spec) | `git grep -F "id: 'retention-ledger-tenancy'," HEAD -- tests` | `HEAD:tests/h8-cross-tenant-probe.test.ts:    id: 'retention-ledger-tenancy',` |
| sentAt nit | `git grep -F "sentAt: point.at," HEAD -- src` | `HEAD:src/anchors.ts:            sentAt: point.at,` |
| witness-empty nit | `git grep -F "errors.push('the bundle has no events to anchor');" HEAD -- src` | `HEAD:src/anchors.ts:      errors.push('the bundle has no events to anchor');` |

Highest-leverage next action: resolve ticket 01 (mirror H13's signing-key precondition in the `evidence hold`/`release` CLI branches + one DEPLOYMENT line) — it is the only behavioral finding and closes a silent attribution gap on the shared chain.
