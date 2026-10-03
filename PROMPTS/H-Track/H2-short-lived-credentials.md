# H2 — Short-lived credentials and workload identity (ROADMAP Stage 2)

Status: [x] **[DONE]** (ADR-028) — executed 2026-10-03; resolution record at
the bottom. Federation flag: structurally necessary at federation (ADR-022) —
cross-repo REST clients are long-lived bearer tokens today.

Spec of record: ROADMAP.md "H2" (attack surface, failure modes, assumptions,
test methodology, residual risk). This stub is the queue placeholder, not the
spec.

Known context from the build so far: IdP tokens carry expiry (M2, `jose`);
REST deployment tokens in `data/secrets.json` posture are long-lived; no
workload identity for non-human principals.

At kickoff: Phase 0 ADR first (DECISIONS.md, newest last); expand this stub
to the full M4–M16 prompt format; tests first (red), gate before commit.
*(Executed lean per operator instruction: no full-format expansion.)*

---

## Resolution (executed 2026-10-03)

- **ADR first:** ADR-028 (`DECISIONS.md`) landed as the Phase 0 commit
  `a5ec515`. Mechanism: short-lived credentials are a **verification
  contract** at the single seam (`IdentityProvider.verifyToken`) — ASL stays a
  verifier, never a token issuer. Required claims `sub`/`exp`/`iat`/`jti`;
  declared lifetime `exp - iat` within `maxTokenLifetimeSec` (default 1 h,
  configured ceiling capped at 24 h); clock tolerance bounded (default 30 s,
  hard cap 60 s) and **actually wired** into jose — the M2 `clockToleranceSec`
  option name was silently ignored (`clockTolerance` is the real option).
  Workload identity is derived from a verified parent
  (`IdentityProvider.workloadAuth`; `sessionAgent` routes through it): capped
  at `min(parent expiry, +15 min default)`, `amr: []`, `claims: {}`,
  `derivedFrom` recorded. `jti` revocation propagates on the H13 channel:
  new `revoke-token` record, `attachRevocationFeed` consumption,
  `IncidentService.revokeToken` local-first + audit, CLI
  `incident revoke-token`.
- **Tests first (red captured):** `tests/h2-short-lived-credentials.test.ts`
  (31) written before the implementation; red = ESM link error on the new
  exports (`.scratch/h2/red.txt`). Coverage: admission contract + deterministic
  2 000-case expiry fuzz; end-to-end jose verification incl. the
  tolerance regression; workload derivation bounds; cross-node revocation
  propagation and REST 403 before principal mint; credential-in-log scanning
  (raw token + payload canary absent from events, responses, errors on success
  and failure paths).
- **Implementation:** `src/identity.ts`, `src/domain.ts` (`derivedFrom`),
  `src/incident.ts` (`revoke-token`, `TokenRevoker`, `revokeToken`,
  `applyRecord`), `src/cli.ts` (`incident revoke-token`), `src/testing.ts`
  (mock `omit` + config pass-through). Zero new runtime dependencies; no
  `as any`/`as never`; no secrets in logs/events/errors.
- **Gate:** `npm run typecheck` clean; `npm test` 653 / 634 pass / 0 fail /
  19 Postgres-mode skips (baseline 622/603/19; +31).
- **Docs:** ROADMAP H2 [DONE] + mechanism + working order (remaining nine);
  CURRENT_STATE (header, intro, counts, gap #2 closed, "What H2 closed");
  SECURITY_CLAIMS Claim 37 (+ Claim 17 updated); THREAT_MODEL replay row;
  TM-005 paths/controls/residual; DEPLOYMENT credential contract; COMPLIANCE
  rows; AGENT-SESSION SESSION 35.
- **Skips (named in ADR-028):** SPIFFE/SPIRE workload attestation (still
  HARD-stage), mTLS/`private_key_jwt` client auth, IdP introspection/CAEP
  push, IdP-side issuance changes (ASL stays a verifier). Cross-repo note:
  M17's control-plane bearer token must switch to IdP client-credentials
  issuance to satisfy the ceiling (documented in DEPLOYMENT; not a change in
  this repo).
- **Residuals:** window of validity (≤ 1 h default) and in-memory exposure;
  replay inside the window unless `jti` revoked; poll-bounded propagation;
  per-process in-memory revoked set; required-claim contract needs IdP
  configuration.
- **Branch:** `feat/h2-short-lived-credentials` (ADR commit `a5ec515` +
  implementation commit); merge to `main` pending.
