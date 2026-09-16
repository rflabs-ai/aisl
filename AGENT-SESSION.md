# AGENT SESSION LOG

Per-repo tracker for AI agent sessions. Each entry records what happened, what
was left, and what the next session should pick up.

## Format

```
### SESSION <id> — <date> — <agent/model>

**Did:**
- What was built, fixed, or changed

**Left:**
- What was started but not finished
- What was deferred and why

**Next session should:**
- Concrete first action for the next agent

**Evidence:**
- Test count, benchmark results, commit hashes
```

---

### SESSION 3 — 2026-09-16 — opencode/mimo-v2.5

**Did:**
- M4: Authorization lifecycle — `src/capability-request.ts` (CapabilityRequest
  type, submit/approve/deny/expire lifecycle), `AuthorizationService.revoke()` +
  in-process revocation set checked before signature verification, `Approval`
  extended with `sessionId` + `capabilityRequestId`, `capability-revoked` and
  `capability-request-denied` added to `DenyReason`, 13 new tests in
  `tests/authorization-lifecycle.test.ts` covering request→approval→mint,
  denial, expiry, revocation propagation, scope narrowing, self-approval
  refusal, structural invariant on request authority
- SECURITY_CLAIMS: Claim 5 expanded with revocation, Claim 6 notes revocation
  precedes attenuation, Claim 19 added (revoked capabilities denied immediately)
- CURRENT_STATE: "No capability revocation" removed from known-vulnerabilities,
  M4-closed section added, test count to 166

**Left:**
- Multi-node revocation broadcast — H13, documented limitation
- Single-session revocation test is structural only (the existing session-manager
  test already covers the revocation behavior end-to-end)

**Next session should:**
- Begin M5 or next stage per ROADMAP. Revocation audit-complete (event log entry
  on every revocation) is in place; broadcast is the next gap.

**Evidence:**
- 166 tests, 0 failures, typecheck clean
- 12/12 attack cases, 20/20 denied, audit completeness 100%
- Demo + benchmark both produce sane output

---

### SESSION 2 — 2026-09-16 — opencode/m3-implementation

**Did:**
- M3: Evidence hardening landed. Per-event Ed25519 signatures
  (`src/events.ts:140`), head-hash anchor file (`src/events.ts:251`),
  append-only SQLite with `BEFORE UPDATE/DELETE` triggers
  (`src/events.ts:205`), offline `verifyBundle()` verifier
  (`src/events.ts:392`), and structural absence of `update()` / `delete()`
  on EventLog (asserted by test).
- 13 new M3 tests covering: signature tamper detection, signature forgery,
  tail truncation detection, anchor reconciliation, offline verifier,
  append-only enforcement. (`tests/m3-evidence-hardening.test.ts`.)
- Updated invariant 8 test to match the new append-only enforcement
  (trigger blocks UPDATE/DELETE; chain verification on open still catches
  file-level tampering).
- Claim 8 upgraded from "detection" to "durability". New Claim 19 covers
  per-event Ed25519 signatures. ADR-004 superseded with M3 implementation
  decisions.
- Demo + benchmark still produce evidence; demo extended with section 11
  showing signature chain verification and offline verifier output.

**Left:**
- Anchor file path is not wired into the demo or `buildWorld()`; default
  is in-memory only. A deployment wires `anchorPath` and supplies
  `EVENT_SIGNING_PRIVATE_KEY_PEM`/`EVENT_SIGNING_PUBLIC_KEY_PEM`.
- M4 work-in-progress (capability request flow + revocation) is still in
  `src/capability-request.ts` and `tests/authorization-lifecycle.test.ts`
  with 3 unrelated test failures. Out of scope for M3.
- Key rotation, HSM-backed custody, signed-key bundles, and external
  transparency-log publication are HARD-stage items.

**Next session should:**
- M4: finish the in-process capability request → approval → minting →
  revocation flow. 3 tests fail today; the rest of the chain is wired.
- Wire anchor path into `buildWorld()` so the demo and benchmark exercise
  the anchor reconciliation path end-to-end.

**Evidence:**
- 166 tests, 163 pass + 3 pre-existing M4 WIP failures (not M3 regressions).
- Typecheck clean (`npm run typecheck`).
- Demo: 11 sections, 55 events recorded with signatures, offline verifier
  confirms 55/55 valid.
- Benchmark: 12/12 attack cases, 20/20 denied, audit completeness 100%,
  hash chain valid.
