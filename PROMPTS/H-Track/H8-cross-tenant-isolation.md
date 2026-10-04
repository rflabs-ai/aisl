# H8 — Cross-tenant isolation, cryptographic and physical (ROADMAP Stage 2)

Status: [x] **[DONE]** (ADR-030) — executed 2026-10-03; resolution record at
the bottom. Federation gate (ADR-022): closed — the shared-process residual is
explicitly accepted per deployment (ADR-030) before any non-personal tenant
joins.

Spec of record: ROADMAP.md "H8" (attack surface, failure modes, assumptions,
test methodology, residual risk). This stub is the queue placeholder, not the
spec.

Known context from the build so far: Postgres mode enforces FORCE RLS +
per-tenant evidence keys (M12, live-tested); SQLite mode stays app-level; the
shared PROCESS remains in both modes (known-gap #7) — one memory-safety bug
crosses every boundary.

At kickoff: Phase 0 ADR first; tests first (red), gate before commit.
*(Executed lean per operator instruction: no full-format expansion.)*

---

## Resolution (executed 2026-10-03)

- **ADR first:** ADR-030 (`DECISIONS.md`) landed as the Phase 0 commit
  `5a86157`. Scope decided honestly: cryptographic isolation exists at the
  evidence seam (per-tenant v2 keys, Postgres FORCE RLS) but the shared
  process remains (known-gap #7) and physical isolation is Stage 3. One
  table-driven probe is the milestone artifact; a new tenant-facing surface
  must add a row.
- **Tests first (red captured):** `tests/h8-cross-tenant-probe.test.ts` + one
  `tests/evidence.test.ts` extension, written before the fixes; the red run
  (`.scratch/h8/red.txt`) proved both gaps: an acme clearance naming
  `evidence-key:v2:globex:confidential` decrypted globex content and bound the
  foreign key to acme; `CapabilityRequestService.approve` accepted a globex
  reviewer on an acme request.
- **Implementation (smallest fix each):** `src/seal.ts` (`tenantFromKeyId`),
  `src/pdp.ts` (`revealEvidence` refuses a foreign v2 keyId before any
  registration/authorization, audits one clean `tenant-mismatch` deny event
  without naming the foreign key, opens with `openFor(principal.tenantId, …)`),
  `src/capability-request.ts` (`requireSameTenant` in `approve`/`deny`). Zero
  new runtime dependencies; no `as any`/`as never`; no secrets in
  events/errors.
- **Probe coverage:** 22 cases — 8 REST routes (authorize, sessions, audit,
  capability requests, anchors, tasks, healthz, static pages), 12 in-process
  surfaces (audit query/export, event-store reads + global-by-design chain
  view, registry, tenant-wide session revocation, capability-request review,
  evidence-key binding, incident global view + preserve, log-scan), 2
  Postgres-gated storage cases skipping cleanly; plus the seal extension. The
  H13 global view (`tenantId: '*'`) is pinned to the caller's own tenant
  authority and tenant-less events.
- **Gate:** `npm run typecheck` clean; `npm test` 676 / 655 pass / 0 fail /
  21 Postgres-mode skips (baseline 653/634/19; +23).
- **Docs:** ROADMAP H8 [DONE] + mechanism; CURRENT_STATE (counts, what H8
  closed, known-gap #7); SECURITY_CLAIMS Claim 38 + Claim 9 refresh;
  THREAT_MODEL cross-tenant row; AGENT-SESSION SESSION 36.
- **Skips (named in ADR-030):** physical/process isolation (Stage 3 — the
  shared-process residual is explicitly accepted per deployment), per-tenant
  low-level session/registry helpers, a per-tenant `CapabilityRequestService`
  root resolver, the probe's marker-scope limitation (continuous adversarial
  evaluation is H14).
- **Residuals:** shared process (both modes); SQLite app-level only; hardware
  side channels / hypervisor bugs; principal-id collisions in non-tenant-facing
  helpers; one service root per tenant for capability requests.
- **Branch:** `feat/h8-cross-tenant-isolation` (ADR commit `5a86157`,
  implementation/docs commit `a477ec7`, audit follow-up `f61817e`); merge to
  `main` performed as instructed (fast-forward).

## Audit follow-up (2026-10-04)

Session audit verdict: ship - no must-fix or should-fix items; five nits
ticketed and resolved in `f61817e`:

- 01 `capability-request` docstring audience (the escalation lane submits;
  `deny` has no REST route).
- 02 probe exposure taxonomy: the `log-scan` class added; healthz/page and
  log-scan rows relabelled.
- 03 session-manager row: reverse-direction assertion added (same row count).
- 04 `revealEvidence` ordering rationale documented.
- 05 Claim 38: the `deny`-no-REST-route note.

Audit record: `.scratch/session-audit/2026-10-04-h8-cross-tenant-isolation/`;
implementation scratch evidence committed under `.scratch/h8/`.
