# H1 — Robust capability issuance (root of trust) — DONE

Resolved without a stub (executed straight from the ROADMAP H1 section).

- ADR-023: signed delegation — a non-root issuer attenuates against its own
  signed capability, never a declared object; constraints and single-use are
  attenuated dimensions (audit addendum); custody refusals audited.
- Tests: `tests/h1-signed-delegation.test.ts` (32) + rewritten invariant 6.
- Residual: symmetric process-wide HMAC key (known-gap #4); ADR-008
  asymmetric keys is the portability path.
