## Verdict: ship-with-notes — two handler-ordering bugs in the persistence mirror (one data-loss on approve, one split-brain on submit); both only fire when a Postgres store is wired

Target: session scope — commit c9f5176 (M15 Stage-0 closure, ADR-020), merged as 9d88d0d on main
Checks: typecheck pass, tests 448 pass / 14 skip / 0 fail, demo exit 0, benchmark exit 0 (SLO pass)

## Ticketed
- 01: .scratch/session-audit/2026-09-18-m15-stage0-cleanup/issues/01-persist-before-inmemory-mutation.md — approve/submit handlers mutate in-memory state before persisting; persist failure = data loss on approve, split-brain on submit
- 02: .scratch/session-audit/2026-09-18-m15-stage0-cleanup/issues/02-persistence-status-validation.md — `updateCapabilityRequestStatus` accepts any string; no validation against allowed statuses

## Findings

### Must fix (ticketed)
- [must] src/rest-sessions.ts:161-170 — approve handler calls `service.approve()` before `persist()`. If persist throws, single-use capability is consumed in memory but approval is lost on restart — permanent data loss. Fix: move `persist()` before `service.approve()`. → 01
- [must] src/rest-sessions.ts:107-131 — submit handler calls `service.submit()` before `persist()`. If persist throws, client sees 500 but request exists in memory (visible on GET). On restart, request lost. Fix: persist before submit (requires refactoring `submit()` to accept external id). → 01

### Should fix (ticketed)
- [should] src/persistence.ts:433 — `updateCapabilityRequestStatus` accepts any `string` for `status`; no validation against `pending | approved | denied | expired`. A direct SQL insert could put garbage in the column. → 02

### Notes / nits (not ticketed)
- [nit] src/ingestion.ts:22-25 — `ChunkOptions` interface is exported but never imported or used anywhere. Dead code; the `ingest()` method takes `chunkSize` as an optional number parameter instead. Delete the interface.
- [note] tests/m15-persistence-capability-requests.test.ts — PG persistence test skipped (Docker daemon not running). SQL patterns follow the proven migration-3 idempotency patterns, but live verification is pending. Documented in AGENT-SESSION.md Left section.
- [note] src/rest-sessions.ts — deny mirror not wired (deny has no REST route). Matches ADR-019's endpoint contract; add a route + mirror when reviewers work through the API.

## Clean axes
- Correctness: two handler-ordering bugs found (ticketed); no injection, no secrets in code/logs, no trust-boundary validation gaps
- Spec adherence: all ROADMAP items [DONE], ADR-020 decisions match implementation, claims 29/30 added with evidence
- Over-engineering: clean — no unrequested abstractions, no speculative interfaces with one impl, one dead interface found (nit)
- Tests: 23 new tests covering all new modules; deterministic chunker, sealed events, config-time refusals, traversal refusal, accessibility, secret scan; PG persistence test skipped (documented)
- Docs: clean — ROADMAP, CURRENT_STATE, DEPLOYMENT, AGENT-SESSION, SECURITY_CLAIMS all updated
- Debt markers: one ponytail in git-reader.ts (A..B over-refusal, ceiling + upgrade path named); ponytail markers in setup scripts (fixed port/throwaway password, upgrade path: DEPLOYMENT.md)

## Highest-leverage action
Move `persist()` before `service.approve()` in the approve handler (src/rest-sessions.ts:161-170). One-line reorder; prevents permanent capability consumption on persist failure. The submit handler needs a refactor (accept external id) — larger but lower urgency since it's split-brain, not data loss.
