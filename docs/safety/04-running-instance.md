# Safety ticket 04 — running instance safe

**Status:** open — two items left
**Evidence:** [`../SAFETY-2026-11-01.md`](../SAFETY-2026-11-01.md), gate 4
**Blocked by:** gates 1 and 2 (both satisfied for local use; gate 2 open for publishing)

- [x] Both servers bind `127.0.0.1` only; no wildcard bind anywhere
- [x] Every credential is environment-supplied, documented in `DEPLOYMENT.md`
- [x] `/healthz` is the only unauthenticated route and is tested to carry no secret material
- [x] Egress deny-by-default: network gateway + proxy with DNS pinning, private-range blocking, H7 body DLP
- [x] No code execution from untrusted input: no issuance handle in `ExecutionContext`, authority keys refused in params
- [x] Auditable: hash-chained signed log with external anchors; `npm run adversarial`
- [x] One-command stop: `incident freeze`, `incident revoke-all`
- [x] **Provider spend cap** — `ModelBudget` on `HttpModelAdapter`: per-day call and token ceilings, refused **before** the fetch with `denyReason: budget-exhausted`, so an exhausted budget costs nothing. Provider-reported usage is charged; when the provider reports none, a conservative estimate is charged instead. In-memory counter (documented ceiling: a restart refills it).
- [ ] **Fail closed on missing keys in production** — the process currently falls back to an ephemeral key. Correct for a demo; a deployment must refuse to start without durable keys rather than silently minting one that dies with the process.
- [ ] **TLS at the edge** — loopback plus a reverse proxy is the documented shape; nothing in the repo terminates TLS.

## Done when

A stranger can clone, set their own credentials, start the server, and neither
inherit a bill nor depend on an ephemeral key surviving a restart.
