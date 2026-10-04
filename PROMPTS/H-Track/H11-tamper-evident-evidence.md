# H11 — Tamper-evident evidence: signatures, anchoring, retention (ROADMAP Stage 2)

Status: [x] **[DONE]** (ADR-031) — executed 2026-10-04 on
`feat/h11-tamper-evident-evidence`; resolution record at the bottom.

Spec of record: ROADMAP.md "H11" (attack surface: the event store, the
verifier, the anchor; failure modes: whole-log rewrite, anchor collusion,
clock manipulation, selective deletion; assumptions: at least one
append-only store the runtime cannot rewrite; test methodology: anchor
consistency checks, verifier against adversarially rewritten logs, retention
and legal-hold tests; residual risk: an attacker who controls both the log
and the anchor).

Baseline: M3 closed the in-process part — per-event Ed25519 signatures,
append-only SQLite triggers, the `<seq>:<eventHash>` head-hash anchor FILE,
and offline `verifyBundle()`. M17 lets federation clients anchor INTO this
plane (`POST /v1/anchors`, `AnchorRegistry`). What does not exist: the anchor
lives inside the runtime's trust domain — an attacker with host access
rewrites the store and the anchor consistently (Claim 8 residual); anchors
are never reconciled across sources (no fork/collusion detection); the
federation registry is in-memory (M17 ponytail marker: a restart cannot
distinguish "first anchor" from "lost predecessor"); there is no
operator-held proof, no timestamp-regression report, and no recorded legal
hold — retention is structural but unwitnessed.

Zero new runtime dependencies. Everything H11 needs is `node:crypto`
(reuse the M3 event-signing key; no new key, no new authority), `node:fs`,
and the built-in `fetch` (the `HttpModelAdapter` posture: injectable, no
shell, no new package).

## Phase 0 — ADR-031 (docs only)

ADR-031 must decide:

- **Anchor sinks are a port; the M3 file is one sink.** `AnchorSink`
  (`name`, `publish(point)`, optional `flush()`, `status()`) +
  `AnchorPublisher` fan-out. The local file sink keeps the exact M3 line
  format (`<seq>:<eventHash>\n`) — byte-compatible, no migration. A new
  **HTTP witness sink** POSTs `{ version, kind, seq, headHash, eventCount,
  sentAt }` to an operator-configured URL (optional bearer token from env,
  never logged). Publication is **non-blocking**: a queued, bounded sink
  with kick-on-publish + explicit `flush()`, loud counters
  (`published/failed/dropped/lastError`), never a throw into `append`.
  A dead witness degrades detection granularity, never availability — and
  never silently (status is inspectable; not a decision-path dependency).
- **The verifier reconciles sources.** `parseAnchorLines` +
  `verifyAnchoredEvidence(bundle, { sources, checkpoint?, publicKey? })`:
  per-source parse and monotone/contiguous seq checks; line-to-event
  binding; head coverage (at least one source anchors the bundle head);
  a source **ahead** of the bundle head is tail truncation; two sources
  disagreeing at one seq is a **fork** (anchor-collusion detection). A
  bundle with no source is reported `unanchored: true`, never silently
  "anchored".
- **Operator-held checkpoints are the offline external witness.**
  `asl-anchor-checkpoint`: Ed25519-signed (same event key)
  `{ version, seq, headHash, eventCount, createdAt,
  previousCheckpointDigest, signature }`. `verifyCheckpoint` refuses a
  rewritten chain (head hash does not match the event at that seq), a
  truncated chain (checkpoint seq beyond the chain), a broken checkpoint
  chain (previous digest mismatch, same-seq fork), and a bad signature.
  This closes the "at least one append-only store the runtime cannot
  rewrite" assumption with a file the operator takes off-host.
- **The federation anchor registry becomes durable.** `AnchorRegistry`
  replays `anchor.register` events on construction — the accepted head per
  tenant survives restart (closes the M17 ponytail marker). The durable
  record is the event; no new table.
- **Clock manipulation is detected, not prevented.** Timestamps live inside
  the signed/hashed body, so any edit breaks hash + signature; the verifier
  additionally reports timestamp regressions as anomalies (non-fatal: an
  NTP step is not an attack) and witness receipts carry the witness's own
  clock. No new clock control (H15's `ClockGuard` remains the runtime's).
- **Retention is structural; legal holds are signed evidence.** There is no
  update/delete path at any layer (API, SQLite triggers, Postgres
  triggers); `evidence.hold` / `evidence.release` events plus a
  `RetentionLedger` replayed from the log record which ranges must be kept.
  No prune path exists today — the ledger is the contract any future
  prune/archive-purge tool must consult, and the structural tests are the
  enforcement.

Phase 0 is the ADR. Nothing else ships until ADR-031 lands.

## Phase 1 — `src/anchors.ts` + store wiring

One module, no framework:

- `AnchorPoint { seq, headHash, eventCount, at }`, `AnchorSink`,
  `AnchorSinkStatus`, `AnchorPublisher` (per-sink try/catch — a throwing
  sink must not break the evidence append).
- `FileAnchorSink` (M3 format, sync) and `HttpAnchorSink` (bounded queue,
  kick + `flush()`, injectable `fetch`, optional bearer token, redacted
  errors).
- `parseAnchorLines(content)` + `verifyAnchoredEvidence(...)` (parse,
  binding, coverage, ahead, fork, timestamp anomalies) +
  `fetchWitnessHeads(url)` (shape-validated; malformed response refuses).
- `createCheckpoint(events, { previous?, now? })` /
  `verifyCheckpoint(checkpoint, events, { publicKey?, previous? })` +
  `checkpointDigest`.
- `EventStore` port + both backends gain `flushAnchors(): Promise<void>`
  and accept `{ anchors }` in their constructors; `EVENT_ANCHOR_WITNESS_URL`
  / `EVENT_ANCHOR_WITNESS_TOKEN` are read by `scenario.ts` (the test/demo
  seam), default off.

## Phase 2 — retention ledger

- `src/retention.ts`: `RetentionLedger` over `EventStore` — `hold()` /
  `release()` append signed `evidence.hold` / `evidence.release` events
  (new `KnownAction`s), `activeHolds(tenantId)`, `isHeld(tenantId, seq)`,
  `status()`; rehydrated from the event log in the constructor (durable by
  construction, restart-safe).
- Structural retention: no prune method exists; SQLite/PG delete attempts
  abort; a hold is signed evidence and survives a rebuild.

## Phase 3 — CLI + tests

- `node src/cli.ts evidence status|checkpoint|verify|hold|release|witness`
  (+ `npm run evidence:status`).
- `tests/h11-tamper-evident-evidence.test.ts` (written FIRST,
  red-confirmed before the module exists).
- Demo section 24: witness publication round trip, a signed checkpoint, a
  truncated + re-signed chain caught by checkpoint/anchor, a source fork
  flagged, and a legal hold that survives a ledger rebuild. Demo exits 0.

## Hard requirements (never simplify away)

- **Fail-closed verification:** a source that fails to parse, a line whose
  hash disagrees with the event at its seq, a source ahead of the bundle
  head, a cross-source divergence, a checkpoint that does not bind or does
  not extend — each is a distinct reported failure; no path prints
  "verified" without matching the recomputed state.
- **Anchoring never blocks the evidence append.** Sink failures are loud
  counters + `lastError`, never a throw; the local file sink stays
  synchronous and byte-compatible.
- **No new runtime dependencies, no new key, no new authority.** The
  checkpoint signs with the existing event-signing key; holds are operator
  events, not capabilities.
- **No secrets in output:** the witness token and URL query never reach
  stdout, event metadata, status objects, or error messages (tested).
- **Structural retention:** the EventStore surface gains no delete/prune
  method; storage-layer DELETE keeps aborting.
- **Timestamp anomalies are reported, not weaponized:** a regression does
  not flip `valid` (a legitimate clock step exists); the chain and
  signature remain the controls.

## Tests / acceptance

- `tests/h11-tamper-evident-evidence.test.ts` green (~25 cases).
- The full gate stays green: `npm run typecheck && npm test` (676 existing
  + new; 21 PG-mode skips unchanged).
- `npm run demo` exits 0 with the new section; `npm run benchmark` shows no
  new hard-target failures.
- ROADMAP H11 → [DONE]; M18 note updated if the gate row references it.

## Docs sweep

- ROADMAP: H11 heading [DONE] (ADR-031) + mechanism; working order.
- CURRENT_STATE: counts, what-works entry, "What H11 closed", gap #3.
- DECISIONS.md: ADR-031.
- SECURITY_CLAIMS.md: Claim 39 + Claim 8 refresh.
- THREAT_MODEL.md evidence row; TM-004 attack-path row + controls.
- DEPLOYMENT.md: witness + checkpoint + legal-hold runbook.
- COMPLIANCE.md: evidence/retention rows if the existing columns claim less.
- AGENT-SESSION.md: session entry.
- This prompt: resolution record at the bottom.

## Constraints

- No `as any` / `as never`; witness responses parsed narrowly (a malformed
  response is a refusal, not a cast).
- No runtime dependency additions; no dev dependency additions.
- No secrets in logs/events/errors; no key material outside env/files.
- No comments-only debt: every deliberate ceiling carries a `ponytail:`
  marker naming the ceiling and the upgrade path.

## Acceptance + skip list

Acceptance: tests red-then-green; gate green; demo exits 0 with the section;
ROADMAP row [DONE]; docs updated; committed on the branch with the gate run
on it.

skipped: a hosted transparency log / witness service (the protocol seam is
defined and testable with an injected fetch; operating one is deployment
territory). skipped: automatic witness retries on a timer (kick-on-publish +
explicit flush only — a dead witness must not keep the process alive).
skipped: signing-key custody/rotation (ADR-008 family, unchanged).
skipped: hardware WORM storage / HSM attestation (HARD stage). skipped:
actual pruning (no prune path exists; the hold ledger is its future gate).
add when: an operator runs a witness outside this host, or a prune/archive
tool is built.

---

## Resolution (executed 2026-10-04)

- **ADR first:** ADR-031 (`DECISIONS.md`) landed as the Phase 0 commit
  `6ab8386` (docs only, with this prompt expanded to the full M4–M16 format
  in the same commit).
- **Tests first (red captured):** `tests/h11-tamper-evident-evidence.test.ts`
  (35) written before `src/anchors.ts` / `src/retention.ts` existed; the red
  run is `.scratch/h11/red.txt` (`ERR_MODULE_NOT_FOUND` from the missing
  module). One test-writer bug was caught by the red/green loop: mutating a
  signed timestamp breaks the hash, so the anomaly test now appends a valid
  chain with regressing timestamps at append time. A self-review fix was
  pinned red-first (test 35): `memory: true` worlds must not inherit
  `EVENT_ANCHOR_WITNESS_URL` (a demo publishing fixture heads to a live
  witness); explicit injected anchors still apply.
- **Implementation:** `src/anchors.ts` (AnchorSink port, FileAnchorSink,
  non-blocking HttpAnchorSink with bounded queue + `flush()` and loud
  counters, `parseAnchorLines`, `verifyAnchoredEvidence` — binding, coverage,
  truncation, fork, `unanchored` — `fetchWitnessHeads`, `createCheckpoint`,
  `verifyCheckpoint`, `checkpointDigest`); `src/retention.ts`
  (`RetentionLedger` + signed `evidence.hold`/`evidence.release`, replayed
  from the log, tenant-bound); `src/events.ts`
  (`VerificationResult.timestampAnomalies` + `collectTimestampAnomalies`,
  `EventStore.flushAnchors`, sink fan-out on the append path — a throwing
  sink is wrapped); `src/event-store-pg.ts` (same sink/flush surface);
  `src/rest-anchors.ts` (accepted federation heads rehydrated from
  `anchor.register` events); `src/domain.ts` (two new KnownActions);
  `src/scenario.ts` (`WorldOptions.anchors` +
  `EVENT_ANCHOR_WITNESS_URL`/`_TOKEN`, default off); `src/cli.ts` (the
  `evidence status|checkpoint|verify|witness|hold|release` command + demo
  section 24); `package.json` (`evidence:status`).
- **H8 probe:** a new `retention-ledger-tenancy` row (ADR-030's review
  condition for a new tenant-facing surface); the probe is now 23 cases
  (8 REST, 13 in-process, 2 Postgres-gated skips).
- **Gate:** `npm run typecheck` clean; `npm test` 712 / 691 pass / 0 fail /
  21 Postgres-mode skips (baseline 676/655/0/21; +36: 35 H11 + 1 probe row).
  `npm run demo` exits 0 with section 24 (sources + checkpoint VERIFIED,
  re-signed truncation DETECTED, fork DETECTED, hold survives rebuild,
  witness delivery 7/7). `npm run benchmark` exits 0, 0 hard failures.
- **Docs:** ROADMAP H11 [DONE] + mechanism + working order; CURRENT_STATE
  (header, counts ~13,962 lines / 48 modules / 711 tests, what-works,
  "What H11 closed", gap #3, assumptions); SECURITY_CLAIMS Claim 39 + Claims
  8/9 refresh; THREAT_MODEL evidence row; TM-004 attack path + controls +
  assumptions + failure modes + test methodology + residual; DEPLOYMENT
  (witness/checkpoint/legal-hold runbook + evidence-preservation note);
  COMPLIANCE (PR-PS-06, AU-2/3/12, AU-9); PROJECT_CONTEXT module map;
  AGENT-SESSION SESSION 37; this record.
- **Skips (named in ADR-031):** hosted witness/transparency-log service
  (protocol seam only; operating one is deployment), timer-driven witness
  retries (kick + explicit flush only), key custody/rotation (ADR-008),
  hardware WORM/HSM (HARD stage), actual pruning (no prune path exists — the
  hold ledger is its future gate). The witness fetch is injected in tests by
  design; no live HTTP witness or live PG sink run this session.
- **Residuals:** a host attacker who controls the store AND every
  witness/checkpoint; witness-operator collusion / split-view; no off-host
  sink/checkpoint means host-level durability only; the same ADR-008
  key-custody family as every other signing surface.
- **Branch:** `feat/h11-tamper-evident-evidence` — Phase 0 `6ab8386`;
  implementation + docs commit on the same branch. Merge to `main` not
  performed this session (no operator instruction).