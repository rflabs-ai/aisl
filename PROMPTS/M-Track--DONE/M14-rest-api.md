# M14 — REST API surface

Baseline: M12 complete and verified (Postgres control plane: EventStore port,
RLS, per-tenant keys, persistence, rehearsed backup/restore; second runtime
dependency admitted per policy). The API is a **new network trust boundary** —
AGENTS rule 4: one structural invariant test per new trust boundary. Zero new
runtime dependencies are planned (Node's built-in `node:http` covers it), but
the milestone still needs an ADR: the transport is the first network ingress
the platform has ever had, and the defect bar (SECURITY_PRINCIPLES.md) makes
input validation at that boundary a defect-class requirement, not a
tradeoff. Sequence accordingly.

Scope (ROADMAP row): REST API surface — real clients | PDP, session | M | P.

Environment note: nothing new. The server binds an ephemeral port in tests;
no database needed beyond what M12 already skips cleanly.

## 0. Phase 0 — ADR-019: HTTP transport trust boundary (docs only; UNBLOCKED)

- **ADR-019**: the REST API as the platform's enforcement point for real
  clients. Must decide:
  - **Transport: `node:http` builtin, no framework.** Express/Fastify are
    dependencies whose middleware ecosystem we do not control — rejected
    under ADR-012's supply-chain posture. Routing is a whitelist of
    literal method+path pairs.
  - **Identity contract:** `Authorization: Bearer <JWT>` only. The principal
    is derived from jose token verification (ADR-016) and **never from
    client-supplied `X-*` identity headers** (the egress-proxy tests already
    prove that pattern in src/egress-proxy.ts). No/garbage/expired token →
    `unauthenticated-principal` deny, fail closed.
  - **Tenant derivation:** the tenant comes from the verified principal
    only. A request field that names a tenant is validated against it
    (`tenant-mismatch` on disagreement), never trusted.
  - **Request parsing = whitelist parser** (`parseModelOutput` style,
    src/model.ts:42): a fresh object is constructed from a field whitelist;
    unknown fields from a hostile client are dropped, not
    ignored-with-a-warning. Body size cap (reject with a distinct status
    before parsing). Garbage body → structured rejection, never a crash.
  - **Response construction = whitelist too:** no stack traces, no
    database URLs, no token contents beyond what `identity.ts` already
    records; `denyReason` surfaces as a structured code on 403.
  - **Fail-closed mapping:** an internal error yields a 500 whose event
    says `evaluation-error` — never an allow-shaped response; an unhandled
    path closes the connection.
  - **Transport security:** TLS terminates at the deployment (reverse
    proxy/balancer); the server itself binds loopback by default. Known-gap
    #8 is updated honestly — a transport now exists; TLS-in-process is
    still not implemented and stays a documented gap (operator's job,
    DEPLOYMENT.md).
  - **H15 health signal:** `GET /healthz` — IdP health + store status,
    operator-visible, no secrets. This is the first operator-facing health
    endpoint H15 has asked for since M2.
  - **Rate limiting: NOT in scope** (H15/deployment territory) — named as
    not-implemented so the gap cannot hide.
- Endpoint contract written into the ADR (see the list in §2). Implementation
  must match the ADR or the ADR gets amended — no drift.

## 1. Subagents + parallelization (explicit)

- **Phase 1 (after ADR-019): Subagent A — server skeleton + auth middleware +
  `/v1/authorize` + `/healthz`.** Owns new `src/rest-api.ts` (router:
  literal method+path dispatch, whitelist body parsing, size cap, fail-closed
  error mapping) + the auth middleware (token → principal seam over
  `identity.ts`) + the authorize route (the same PDP decision path) +
  healthz. B and C **wait** — the router and the middleware contract are
  the schema everything else hangs on.
- **Phase 2 (after A): B — session + capability-request endpoints ∥ C —
  audit + task-run endpoints, in PARALLEL.** Each owns its own handler
  module (`src/rest-sessions.ts`, `src/rest-audit.ts`) and its own test
  file; the router registration of both is **main-session wiring** (one
  edit, no shared-file conflict). Neither edits the event backend or
  `src/rest-api.ts`.
- **Shared-file rule:** only the main session edits `src/cli.ts` (if the
  demo gains an API section), benchmark additions go through the main
  session — the M10 SLO gate must stay green.

## 2. Endpoints (the contract; implementation must match the ADR)

- `POST /v1/authorize` — body `{ action, resourceId, params? }` → verified
  principal → the ordinary `authorize()` path → `200 { decision, reason }`
  or `403 { denyReason }`. Nothing executes here; this is the decision
  surface for real clients.
- `POST /v1/sessions` — create a bound session (MFA-authenticated human,
  per session-manager). `DELETE /v1/sessions/:id` — revoke (session
  revocation propagation is immediate, existing tests).
- `POST /v1/capability-requests` — an agent submits a request (M4 flow).
  `GET /v1/capability-requests` — reviewer's pending list. `POST
  /v1/capability-requests/:id/approvals` — an authenticated human approves
  (narrowing allowed); the mint stays exactly what M4 mints.
- `GET /v1/audit?...` — through `AuditQueryService` unchanged: authorized,
  tenant-scoped, the ≤ 90-day / ≤ 1000 bounds already enforced at the
  service boundary. `POST /v1/tasks` — executes a task through the ONE
  existing `AgentSession.run()` path (model port wired) and returns the
  trace summary; it is the execution surface the minimal UI (row 39) will
  use. No new execution path may exist.
- `GET /healthz` — `{ idp, store }` (H15); no secrets, no internals.

## 3. Tests / acceptance

- Authn: no token → 401 `unauthenticated-principal`; garbage/expired token
  → 403; valid token → 200. Identity headers cannot mint a principal
  (structural, mirrors the egress-proxy test).
- Tenant: cross-tenant audit query → 403 `tenant-mismatch`; every endpoint
  derives the tenant from the principal (test: a request field naming
  another tenant is refused, not obeyed).
- Whitelist: unknown body fields dropped; oversized body → distinct
  rejection; garbage JSON → structured rejection, server keeps serving.
- Fail-closed: an engine that throws → 500 + a deny event recorded
  (invariant 7 parity: every PDP-exercising request produces exactly the
  events the in-process path produces).
- SLO gate green; demo/benchmark unchanged and exit 0; no new runtime
  dependencies (SBOM diff clean, H10).

## 4. Docs sweep (main session)

- ROADMAP row REST API surface → `[DONE]` with milestone refs.
- DECISIONS.md: ADR-019.
- CURRENT_STATE: counts; what-works entry; known-gap #8 (transport) gets its
  honest update.
- DEPLOYMENT.md: TLS termination model + reverse-proxy note under the
  Postgres-mode section's siblings.
- AGENT-SESSION entry.

## 5. Constraints

- No runtime dependencies — `node:http` (+ `node:crypto`/`jose` for
  verification) only. No framework, no middleware, no CORS handling (the
  API is same-origin loopback/deployment), no rate limiting (H15/
  deployment), no WebSockets, no streaming.
- No `as any`/`as never`; every request body and every response is built
  through a whitelist parser; nothing is cast at the trust boundary.
- No secrets in logs/events/errors (tokens redacted; database URL redacted
  to endpoint host — mirror `redactUrl` in src/event-store-pg.ts).

## 6. Acceptance + skip list

Acceptance: gate green; API test suite green; SLO gate green; demo/
benchmark unchanged; docs updated.

skipped: rate limiting, CORS, WebSocket/streaming endpoints, OpenAPI schema
generation.
add when: a real customer integration or the audit-trail product surface
demands them.
