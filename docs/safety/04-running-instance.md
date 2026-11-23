# Safety ticket 04 — running instance safe

**Status:** closed 2026-11-12
**Evidence:** [`../SAFETY-2026-11-01.md`](../SAFETY-2026-11-01.md), gate 4
**Blocked by:** nothing

- [x] Both servers bind `127.0.0.1` only; no wildcard bind anywhere
- [x] Every credential is environment-supplied, documented in `DEPLOYMENT.md`
- [x] `/healthz` is the only unauthenticated route and is tested to carry no secret material
- [x] Egress deny-by-default: network gateway + proxy with DNS pinning, private-range blocking, H7 body DLP
- [x] No code execution from untrusted input: no issuance handle in `ExecutionContext`, authority keys refused in params
- [x] Auditable: hash-chained signed log with external anchors; `npm run adversarial`
- [x] One-command stop: `incident freeze`, `incident revoke-all`
- [x] **Provider spend cap** — `ModelBudget` on `HttpModelAdapter`: per-day call and token ceilings, refused **before** the fetch with `denyReason: budget-exhausted`, so an exhausted budget costs nothing. Provider-reported usage is charged; when the provider reports none, a conservative estimate is charged instead. In-memory counter (documented ceiling: a restart refills it).
- [x] **Fail closed on missing keys in production.** `src/key-policy.ts` refuses to start the REST server (the `RestApi.start()` path, which requires all five keys) or to open a persistent event store (the world's store factory: a SQLite path, or `EVENT_STORE=postgres` plus `DATABASE_URL`; the event-signing pair plus `EVIDENCE_SEALING_KEY`) when a required key is missing. The error names each missing variable, explains why it matters, and says how to produce one. `npm run demo`, the test suite, and in-memory worlds are unchanged. The explicit override `aiSL_ALLOW_EPHEMERAL_KEYS=1` is never the default and prints one warning that evidence will not survive a restart. Covered by `tests/key-policy.test.ts`.
- [x] **TLS at the edge** — `RestApi` accepts `host` and `tls: { key, cert }`. A non-loopback host without TLS is refused **before a socket exists**; loopback stays plaintext by default. `0.0.0.0` is deliberately not treated as loopback. 5 tests in `tests/tls-binding.test.ts`.

## Done when

A stranger can clone, set their own credentials, start the server, and neither
inherit a bill nor depend on an ephemeral key surviving a restart.
