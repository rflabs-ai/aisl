# M6 — Audit Query + Export API

Begin M6. Read PROJECT_CONTEXT.md, ARCHITECTURE.md (sections 4 and 5), SECURITY_CLAIMS.md (Claim 7, Claim 8, Claim 13), DECISIONS.md (ADR-001, ADR-004), ROADMAP.md (Stage 1 — Audit query + export API; CURRENT_STATE.md known-vulnerabilities around evidence), AGENT-SESSION.md, `src/events.ts`, `src/pdp.ts` (especially `revealEvidence` at line 233 and the deny-reason taxonomy), `src/policy.ts`, and `src/registry.ts`.

Goal: M3 hardened the evidence plane — hash chain, per-event Ed25519 signatures, head-hash anchor file, append-only SQLite, offline `verifyBundle()` — but the runtime has no way to answer the operator question "who accessed what between T1 and T2, on tenant X, and what was denied?" `world.eventLog.all()` returns everything across every tenant (insufficient for multi-tenant). `forTenant(tenantId)` filters by tenant but lacks time/actor/action/decision filters and does not go through authorization. Operators have no programmatic way to read their evidence.

This closes the loop on M3: evidence that an operator cannot query is evidence that nobody can use. M6 adds an in-process query + export API that:
1. Is authorized (capability AND policy, fail-closed).
2. Is tenant-scoped (no cross-tenant reads).
3. Returns events with their Ed25519 signatures intact, so the consumer can `verifyBundle()` independently.
4. Reuses the existing `evidence.decrypt` authorization pattern (`src/pdp.ts:233`).
5. Does **not** introduce an HTTP server, a new storage backend, or a new trust boundary.

This is a Stage 1 MEDIUM item, MVP class, M-size.

## 1. Resource model

Add a synthetic resource representing the per-tenant audit log:

| Type | Resource id pattern | Purpose |
| --- | --- | --- |
| `audit-log` | `audit-log:<tenantId>` | Synthetic resource that gates `query.audit` and `audit.export` for one tenant |

Add the type to `ResourceType` in `src/domain.ts`. The resource is **never ingested into the resource registry**; it exists only as an authorization target (matches the `evidence-key:<classification>` pattern at `src/seal.ts:43`). The capability carries the synthetic id; the policy rule matches by `types: ['audit-log']`.

## 2. Actions

Add two new actions to `KnownAction` in `src/domain.ts`:

- `query.audit` — read access to filtered events. Returns redacted events (sealed content if present stays sealed; the consumer calls `evidence.decrypt` separately if they need plaintext — that is a separate authorization).
- `audit.export` — structured export for offline verification. Returns a bundle-shaped object (events + their signatures + the chain head). Always authorized through the same capability as `query.audit`; the distinction is policy-side only.

Ponytail: do not invent a third "audit.bundle" action. `audit.export` covers it.

## 3. Authorization

Reuse the `revealEvidence` pattern at `src/pdp.ts:233`. Add a method to `AuthorizationService`:

```typescript
queryAudit(input: AuthorizeInput, filters: AuditFilters): AuthorizationDecision
```

with the same authorization pipeline: auth check → tenant check → capability match → policy `evaluate` → event log append. Default deny on every failure.

Add a new `AuditQueryService` class in `src/audit-query.ts` that:
- Takes a `ResourceRegistry`, `EventLog`, `PolicyEngine`, `now()` clock, `IdPHealth` getter.
- Exposes `query(principal: AuthenticatedPrincipal, filters: AuditFilters): QueryResult`.
- Validates filters at the boundary (time range bounded to ≤ 90 days, page size ≤ 1000, offset ≥ 0).
- Authorizes via `AuthorizationService.authorize({ principal, action: 'query.audit', resourceId: 'audit-log:<tenantId>' })`.
- Then calls `eventLog.query(filters)` (new method, see §4).

Ponytail: do not give `AuditQueryService` a reference to the policy engine directly. It must go through `AuthorizationService.authorize`. One path.

## 4. EventLog query method

Extend `src/events.ts` with a new method on `EventLog`:

```typescript
query(filters: AuditFilters): readonly SecurityEvent[]
```

`AuditFilters`:
```typescript
export interface AuditFilters {
  readonly tenantId: string;          // required; tenant-scoped
  readonly fromSeq?: number;          // inclusive
  readonly toSeq?: number;            // inclusive
  readonly fromTime?: number;         // ms epoch, inclusive
  readonly toTime?: number;           // ms epoch, exclusive
  readonly actor?: string;            // exact match
  readonly action?: Action | '*';     // exact or '*'
  readonly decision?: 'allow' | 'deny';
  readonly resourceId?: string;       // exact match
  readonly limit?: number;            // default 100, max 1000
  readonly offset?: number;           // default 0
}
```

`query()` MUST be tenant-scoped: any filter that does not include `tenantId` throws. The method executes one SQL query against the existing `security_events` table using prepared statements (parameterized — no string concatenation with filter values). Index on `(tenant_id, seq)` already supports the common case; add `(tenant_id, timestamp)` only if the benchmark shows it is needed (do not add speculatively).

Return events in seq-ascending order, with `eventHash` and `signature` preserved. `query()` does **not** re-sign or re-hash; the consumer verifies via `verifyBundle()`.

## 5. Export

Add a method on `EventLog`:

```typescript
exportFor(filters: AuditFilters): AuditExport
```

where:
```typescript
export interface AuditExport {
  readonly tenantId: string;
  readonly generatedAt: number;
  readonly fromSeq: number;
  readonly toSeq: number;
  readonly events: readonly SecurityEvent[];  // includes signature + eventHash
  readonly head: string;                        // eventHash of the last event in events
  readonly previousHead: string | null;         // eventHash of the event immediately before fromSeq, or null
}
```

`previousHead` lets the consumer verify the chain slice against the full chain — pass both to `verifyBundle` (which already accepts partial bundles and checks the head matches the anchor). `audit.export` authorization requires `query.audit` to already be authorized in the same call (single capability covers both actions — the policy rule scopes `types: ['audit-log']`, `actions: ['query.audit', 'audit.export']`).

Ponytail: `exportFor` is `query()` plus packaging. Do not duplicate the SQL. One prepared statement, two result shapes.

## 6. Sealing + redaction

`query.audit` returns the on-store event shape. Sealed content (from M1 sealing, Claim 13) stays sealed in the result — `event.output` may include `sealed: { ciphertext, iv, tag, keyId }` and never plaintext. The consumer can read the digest without authorization; plaintext requires `evidence.decrypt` for the level (separate call, separate authorization, separate event).

Ponytail: do **not** decrypt as part of `query.audit`. One authorization = one capability. Mixing the two widens scope.

## 7. Boundary semantics

- `query.audit` requires an authenticated principal (the auth check fires first, before any capability or policy check — mirrors `revealEvidence`).
- The synthetic resource id must include the principal's `tenantId`; `AuthorizationService.queryAudit` MUST derive `resourceId = 'audit-log:' + principal.tenantId` and reject any caller-supplied id. One input, one derived value, no caller-controlled route.
- Cross-tenant queries fail closed (`tenant-mismatch`).
- An unknown tenant in the synthetic id (e.g. `audit-log:unknown`) is denied (no capability, no policy rule match).
- Time ranges > 90 days throw `AuditFilterError` at the service boundary (defends against accidental full-history dumps; not a security boundary but a usability one).
- `limit > 1000` or `limit ≤ 0` throws.
- `offset < 0` throws.
- Empty result set is allowed (returns `[]`, not an error).

## 8. Tests

Add `tests/m6-audit-query.test.ts` next to `tests/authorization-lifecycle.test.ts`. Minimum cases:

- **Authorization**: an unauthenticated principal is denied (`unauthenticated-principal`).
- **Tenant scope**: tenant A's query against tenant B's synthetic id is denied (`tenant-mismatch`).
- **Capability required**: a principal with a `query.audit` capability for tenant A but no policy rule match is denied (`policy-deny`).
- **Default deny**: empty policy set denies (`no matching allow rule`).
- **Happy path**: principal with capability + matching allow rule gets results; the returned events match the filters exactly.
- **Filter: time range**: `fromTime`/`toTime` restrict the result.
- **Filter: actor**: only events with that `actor` field are returned.
- **Filter: action**: only events with that action are returned.
- **Filter: decision**: only `allow` or only `deny` is returned as requested.
- **Filter: resourceId**: only events for that resource are returned.
- **Filter: limit + offset**: pagination returns the right slice in seq order.
- **Empty result**: filters that match nothing return `[]` (no error).
- **Bad filter**: `limit: 5000` throws; `limit: 0` throws; `fromTime > toTime` throws; time range > 90 days throws.
- **Tenant isolation invariant**: a tenant A query MUST NEVER return a tenant B event — assert this even with adversarial filters that try to widen scope.
- **Export shape**: `exportFor` returns `{ tenantId, generatedAt, fromSeq, toSeq, events, head, previousHead }`; `verifyBundle(export.events, ...)` succeeds.
- **Chain slice**: a slice from seq 5 to seq 10 verifies when `previousHead = events[4].eventHash` and `head = events[9].eventHash` (assuming events 0..9 form a valid chain).
- **Decision audit completeness** (Claim 7): every `query.audit` call appends exactly one event with the right `decision` field.
- **Existing suite green**: 185 prior tests still pass.

## 9. Demo / benchmark

Add a small demo section to `src/cli.ts` after section 12:

```
13. M6: audit query + export API
```

The demo:
- Builds a world.
- Runs a few decisions.
- Issues a `query.audit` capability for tenant A to a user.
- Calls `world.audit.query(userPrincipal, { tenantId: TENANT_A, action: 'read', decision: 'deny' })` and prints the count.
- Calls `world.audit.exportFor(userPrincipal, { tenantId: TENANT_A, fromSeq: 0, toSeq: 10 })` and prints the chain slice head + previousHead.

The benchmark adds two new metrics:
- `auditQueryLatencyP99Ms` — measure 1000 queries with filters and report p99.
- `auditExportLatencyP99Ms` — measure 1000 exports and report p99.

Update `benchmarks/results.json` after the demo/benchmark run. `unauthorizedActionDenialRate` should remain 1.0 (the 20 adversarial requests are unchanged). `auditCompleteness` increases by the number of M6 query events.

Ponytail: do not add a "queries per second" throughput target. Latency p99 is what an operator feels; throughput is not the bottleneck.

## 10. Update docs

- **SECURITY_CLAIMS.md** — add **Claim 21 — Audit query + export is authorized and tenant-scoped**. Mechanism: `AuditQueryService` + `EventLog.query()` + synthetic `audit-log:<tenantId>` resource + `query.audit` / `audit.export` actions; authorization through `AuthorizationService.authorize` (capability AND policy); tenant id derived from the principal, never from caller-supplied filters. Test: `tests/m6-audit-query.test.ts`. Threat model: TM-004 (evidence store as a target). Known limitation: in-process query only; multi-node audit aggregation is H13.
- **ROADMAP.md Stage 1** — flip the "Audit query + export API" row to **[DONE]**. Add a short status note pointing to the M6 commit and the new Claim 21.
- **CURRENT_STATE.md** — strike "What becomes possible" gap (operators cannot read evidence); add a "What M6 closed" section describing the query+export API, the synthetic resource, the two new actions, the 90-day / 1000-row service-side limits, and the chain-slice verification path. Update test count.
- **AGENT-SESSION.md** — add a SESSION 6 entry summarizing what was built, what was deferred (if anything), and the next session's first action.
- **THREAT_MODEL.md** — no change; the new claim cites TM-004.

## 11. Constraints

- Zero new runtime dependencies. `node:sqlite` is already used.
- Do not change `EventLog.verify()`, `verifyBundle()`, `signEventBody`, or any existing authorization path. The new query/export sit beside them.
- Do not introduce an HTTP server. M6 is in-process; an HTTP layer is a later milestone (see ROADMAP "REST API surface").
- Do not change `Capability.resourceIds` semantics. The synthetic id is just another resource id; capabilities already handle it.
- Performance budget: `query()` for a tenant with 10⁵ events returns ≤ 100 ms at p99 (the existing benchmark is the floor; add a measured line, not a target).
- Sealed content stays sealed in the result. No plaintext leak through the audit path.

## 12. Acceptance

`npm run typecheck && npm test` green; 185 prior tests still pass; new M6 tests pass (target 18+ cases); `npm run demo` runs all 13 sections; `npm run benchmark` regenerates `benchmarks/results.json` with the two new latency fields; CURRENT_STATE, ROADMAP, SECURITY_CLAIMS, AGENT-SESSION updated. Report what was skipped and why.
