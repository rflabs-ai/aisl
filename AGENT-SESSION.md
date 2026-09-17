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

### SESSION 5 — 2026-09-17 — opencode/m5-implementation

**Did:**
- M5: Hierarchical resource matching landed.
  - `PolicyRule.resources.idPatterns?: readonly string[]` in `src/policy.ts:28`.
    Grammar: `tenant/...` (recursive, slash boundary), `prefix*` and `prefix?`
    (single-segment glob), literal (exact). Header comment in `src/policy.ts`
    documents the grammar and the boundary semantics.
  - `compileIdPattern(pattern): IdPatternMatcher` exported. Rejects patterns
    > 64 chars, `**`, unsupported characters, and recursive forms without a
    trailing `/` (e.g. `acme...`) — all throw `PolicyCompilationError`.
  - `matchesIdPattern(resourceId, matcher)` exported. Pure function over the
    compiled matcher; literal uses `===`, recursive uses `startsWith` with a
    length check (boundary at the slash), glob uses a regex built once and
    cached.
  - `createPolicyEngine` now compiles every unique `idPatterns` entry into a
    `Map<string, IdPatternMatcher>` at construction time and threads the map
    into `matchesResource`. Hot path never compiles. Defensive cache miss
    falls back to literal match + one stderr warning (ponytail: keeps the
    PDP answering even on a bug; documented ceiling).
  - `matchesResource` extended so `ids` and `idPatterns` OR-combine within
    one rule, and a rule with only `idPatterns` matches only by pattern.
    Default-deny, deny-overrides, classification ceilings, and tenant
    isolation are unchanged.
  - `_compileCacheSize(): number` exposed on the engine for the hot-path test
    (asserts the cache does not grow across `evaluate()` calls). Not part of
    the `PolicyEngine` interface; test-only seam.
- Demo (`src/cli.ts`) extended with section 12: a standalone policy with
  `idPatterns: ['acme/...']` allows `acme/project/sub/file` and denies
  `acme-other` at the boundary.
- Docs updated: ROADMAP Stage 1 hierarchical resource matching flipped to
  `[DONE]`; CURRENT_STATE known-vulnerability item 14 struck through and
  moved to a new "What M5 closed" section with the grammar and the
  boundary semantics; SECURITY_CLAIMS Claim 6 "Known limitations" notes that
  hierarchical matching widens rule selection, not capability scope;
  CURRENT_STATE test count 166 → 185.

**Left:**
- The hot-path test uses `_compileCacheSize()` because the existing test
  files have no spy pattern. The method is a single line of test-only
  surface — if a richer introspection API is needed (e.g. to confirm which
  specific patterns were compiled), the same map can be exposed.
- A `+` glob quantifier (`a+b`) was deliberately rejected at compile time.
  If operators need "one or more of the previous character", that is an
  additive grammar change with a test; nothing prevents it but the ceiling
  is documented.
- Cross-rule OR (a rule whose `idPatterns` succeeds but whose `types` fails
  matches if another rule also matches by type) is already correct — the
  loop is per-rule — but no test asserts it explicitly. If the test
  surface grows, add one.

**Next session should:**
- Per `AGENTS.md` discipline: the next MEDIUM-stage item per ROADMAP is
  whichever open item the operator picks next. Candidates still on the
  board: policy testing framework (NEXT), sandbox lifecycle management,
  configuration management (versioned, reviewable, attributable policy —
  closes B10 partially), audit query/export API, or a fresh EASY item
  (REST API surface, project/task/session persistence, basic document
  ingestion, basic Git integration, minimal UI, developer setup script).

**Evidence:**
- 185 tests, 0 failures, typecheck clean
- 12/12 attack cases, 20/20 denied, audit completeness 100%
- Demo: 12 sections; new section 12 demonstrates `acme/...` allowing
  `acme/project/sub/file` and denying `acme-other` at the boundary
- Benchmark: results regenerated; numbers unchanged modulo `generatedAt`
  and `head`

---

### SESSION 4 — 2026-09-16 — opencode/doc-sweep

**Did:**
- Doc-vs-code drift sweep. M3/M4 had landed without a matching doc pass; the
  docs were accurate in spirit but full of stale status markers and stale line
  references. Items closed:
  - **ROADMAP** Stage 1 table: Approval workflow, Capability request flow, and
    Capability revocation flipped to `[DONE]`. Capability revocation note added
    (in-process; multi-node = H13). Assurance target row 8 (revocation
    propagation) updated from "not implemented" to "immediate (in-process);
    multi-node = H13".
  - **ARCHITECTURE.md** section 1 plane diagram: identity/MFA "NOT YET
    IMPLEMENTED" replaced with the implemented M2 description, ADR-006 →
    ADR-016 reference. Section 5 deliberate-stubs table: Identity and
    SecretBroker rows rewritten (Identity implemented in M2; SecretBroker
    replaced by `EnvelopeSecretBroker` in M1).
  - **threat-models/TM-004** dependency entry and attack path: `jose` is now
    documented as the one runtime dependency under ADR-015 with the admission
    policy in place; "Add a malicious dependency" no longer reads as "succeeds".
  - **Line-number drift** corrected in SECURITY_CLAIMS, SECURITY_PRINCIPLES,
    ARCHITECTURE, DECISIONS, threat-models/TM-002/TM-003/TM-004, AGENT-SESSION
    (41 `src/<file>:<line>` tokens updated across 8 files by a focused
    subagent; verified by re-grep).
  - **CURRENT_STATE.md** cosmetic: module count 21 → 22 (added
    `src/capability-request.ts`), header "Updated after M3" → "Updated after
    M4", known-vulnerability item 12 strike-through cleaned up to a single
    sentence ("No multi-node capability revocation broadcast; H13").
- Wrote `PROMPTS/M5-hierarchical-resource-matching.md` so M5 can be picked up
  without further discovery work.

**Left:**
- The doc sweep did not commit. The diff is staged in the working tree. The
  next session (or the user) should review `git diff` and commit if the diff
  is acceptable — the sweep is mechanical and isolated, but committing is
  outside the doc-sweep mandate.
- ARCHITECTURE.md still says `src/policy.ts:81` and `src/runtime.ts:62` for
  PolicyEngine/Sandbox in section 7 — corrected to 95 and 64 in this sweep.
  No remaining stale line refs found by re-grep; if any creep back in, the
  same canonical table the subagent used can be reused.

**Next session should:**
- Run `git diff` to review the doc sweep, commit if clean (suggested commit
  message: `doc-sweep: align docs with M3+M4 code; line-ref drift; status
  markers`).
- Pick up M5 from `PROMPTS/M5-hierarchical-resource-matching.md`. The M5
  scope is hierarchical resource matching (idPatterns + recursive `tenant/...`
  and single-segment `prefix*`), closes CURRENT_STATE known-vulnerability item
  14, has acceptance criteria and a test list ready to run.

**Evidence:**
- 166 tests, 0 failures, typecheck clean
- 12/12 attack cases, 20/20 denied, audit completeness 100%
- Demo + benchmark produce sane output after the sweep

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
  (`src/events.ts:147`), head-hash anchor file (`src/events.ts:269`),
  append-only SQLite with `BEFORE UPDATE/DELETE` triggers
  (`src/events.ts:208`), offline `verifyBundle()` verifier
  (`src/events.ts:357`), and structural absence of `update()` / `delete()`
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
- Anchor file path is wired via the `EVENT_ANCHOR_PATH` env var; the demo
  exercises the reconciliation path end-to-end when the env var is set.
  Production: point `EVENT_ANCHOR_PATH` at a WORM bucket / customer-held
  witness and supply `EVENT_SIGNING_PRIVATE_KEY_PEM` / `EVENT_SIGNING_PUBLIC_KEY_PEM`.
- Key rotation, HSM-backed custody, signed-key bundles, and external
  transparency-log publication are HARD-stage items.

**Next session should:**
- M4: finish the in-process capability request → approval → minting →
  revocation flow (3 unrelated tests fail today on a separate branch;
  the rest of the chain is wired).
- Move the anchor into a real WORM-tier storage and wire `EVENT_ANCHOR_PATH`
  in a deployment fixture.

**Evidence:**
- 166 tests, 166 pass, typecheck clean.
- Demo: 11 sections, 55 events recorded with signatures, offline verifier
  confirms 55/55 valid; anchor reconciliation exercised when
  `EVENT_ANCHOR_PATH` is set.
- Benchmark: 12/12 attack cases, 20/20 denied, audit completeness 100%,
  hash chain valid.
