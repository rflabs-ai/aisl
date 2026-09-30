# Session audit — M17 federation ASL gap closure — 2026-09-29

## Verdict: ship  —  all gates green; the one ticketed finding is fixed in-session and its regression test is in the suite.
Target: uncommitted changes in both repos (no commit yet). The control-plane
client was already merged earlier; this session's work is the ASL-side REST
gap closure for tickets 04/05 plus the doc sweep on both sides, followed by
the session-audit fix for ticket 01 (registry mutation order).

Checks:
- ASL `npm run typecheck` — pass (exit 0, no output).
- ASL `npm test` — pass (540 tests / 525 pass / 15 Postgres-mode skip / 0 fail).
- control-plane `npm run typecheck` — pass (exit 0).
- control-plane `npm test` — pass (538 passed / 3 skipped / 0 fail).
- Audit probes (P1 first-anchor claim, P3 poisoning, P4 cross-tenant
  isolation) run and deleted after capture per audit discipline; the
  P3 case was converted into the permanent test for ticket 01.

## Ticketed
- 01: .scratch/session-audit/2026-09-29-m17-federation-closure/issues/01-anchor-registry-mutation-order.md
  — **resolved**: `AnchorRegistry.record` now advances `lastHeadByTenant` only
    after `eventLog.append` succeeds; red-first test added
    (`tests/m17-federation.test.ts`, "a throwing event append must not poison
    the registry").

## Findings
### Fixed in-session (was must/should, now closed)
- [fixed] `src/rest-anchors.ts:61` — registry mutation order. Fixed: the
  `lastHeadByTenant.set` now runs after `eventLog.append`; a throwing append
  propagates as a 500 and leaves the registry untouched. Red-first test at
  `tests/m17-federation.test.ts` ("registry head advances only on successful
  append"). Ticket 01.

### Notes / nits (not ticketed)
- [nit] `src/rest-anchors.ts:57` — first anchor with a claimed
  `previousHeadHash` is accepted as authoritative (Probe P1). The predicate
  short-circuits on `previous === undefined`. Expected for a true first anchor;
  worth a sentence in Claim 33 limitations so the affordance is documented.
- [nit] `src/rest-anchors.ts:61` — a *tampered* anchor still advances
  `lastHeadByTenant` (its append succeeds, so the head advances). This is
  correct, not a bug: the registry mirrors the client's *claimed* chain, and
  refusing to advance would permanently flag every subsequent honest anchor
  from that client. The tamper flag itself remains advisory (control-plane
  detects tamper from its own receipts, `control-plane/src/asl/anchor.ts`).
- [nit] `src/capability-request.ts:55` — `minted` Map is never pruned; same
  in-memory-lifetime ceiling as the existing `requests` map. Acceptable.
- [nit] `tests/` — `.scratch/session-audit/2026-09-18-m15-stage0-cleanup/`
  and `.scratch/session-audit/2026-09-18-m16-sandbox-lifecycle/` are untracked
  in the ASL repo. Pre-existed this session; not part of M17 audit scope, but
  flagging.
- [nit] `AGENT-SESSION.md:325,348` — Session 21 entry still references the
  pre-move path `PROMPTS/M17-federation-control-plane.md`. Historical record;
  not falsified.

## Clean axes
- **Correctness (other than registry mutation order):** clean — caller grep
  `grep capabilityFor src tests` → only `rest-sessions.ts:147` and the
  service's own methods; no broken callers. Tenant guard
  (`rest-anchors.ts:112`) verified; cross-tenant head isolation verified
  (Probe P4).
- **Spec adherence:** clean — ticket 04 (anchor registration) and ticket 05
  (request status) each get exactly one route + tests as ticketed. Both
  routes derive tenant from verified principal; no plaintext content in
  events (digest + counts only — `tests/m17-federation.test.ts:144` asserts
  no `"signature"` substring in the anchor response). Capability request
  scope equals approved scope (`tests/m17-federation.test.ts:311`).
- **Over-engineering:** clean — `AnchorRegistry` is one class, 40 lines, with
  a named ponytail ceiling at `rest-anchors.ts:11-14`. No new dependency
  (`package.json` unchanged). `rest-anchors.ts` does not duplicate the
  `intParam` / `str` / `optStr` whitelist helpers from `rest-api.ts` /
  `rest-audit.ts`; it uses them.
- **Tests:** clean — 13 cases in `tests/m17-federation.test.ts`, red-first
  (module-not-found before implementation at audit start; the ticket-01 test
  red with `actual: true, expected: false` before the fix, green after). Repo
  test convention followed: per-test boot/teardown via `node --test`, real HTTP
  via `node:http` (matches `tests/m14-rest-*.test.ts`).
- **Docs & breadcrumbs:** clean — ROADMAP M17 row + spec header + working
  order updated (`ROADMAP.md:144, 392, 644`); control-plane ROADMAP M17
  status flipped (`ROADMAP.md:258` in control-plane); tickets 04/05 marked
  resolved with resolution notes; M17 prompt moved to
  `PROMPTS/M-Track--DONE/` (similarity 100% rename). SECURITY_CLAIMS Claim 33
  added with mechanism/threat-model/evidence/limitations. AGENT-SESSION
  Session 27 added.
- **Debt markers:** clean — single `ponytail:` comment at
  `rest-anchors.ts:11-14`, naming both the ceiling (in-memory registry,
  advisory tamper signal, restart loses predecessor) and the upgrade path
  (persist accepted-head map). No `TODO`/`FIXME`/`HACK`.
- **Security / trust-boundary:** clean — `tenant` from body must match
  principal tenant (`rest-anchors.ts:112`); `headHash`/`previousHeadHash`
  sha256-hex regex (rest-anchors.ts:113-115, 92-96). No `as any` / `as never`
  in changed files (`grep 'as any|as never' src/rest-anchors.ts
  tests/m17-federation.test.ts src/rest-sessions.ts src/capability-request.ts
  src/rest-api.ts src/domain.ts` → no hits). Zero new runtime dependencies.
- **Enum-exhaustive `CapabilityRequestStatus`:** clean — the new
  `GET /v1/capability-requests/:id` route does not gate the response on
  status; it always returns `projectRequest` and conditionally includes
  `projectCapability(capabilityFor(id))`. Traced `'pending' | 'approved' |
  'denied' | 'expired'` through `CapabilityRequestService.approve()` /
  `deny()` / `expirePending()` → minted is set only in `approve`. So
  `pending`, `denied`, `expired` correctly omit capability; `approved`
  includes it. Tests cover pending/approved/denied (no expired test).

## Citation audit
| finding | command run | output line |
|---|---|---|
| F1 (Ticket 01, pre-fix) | Read src/rest-anchors.ts:59-63 | `const id = randomUUID();` `const acceptedAt = this.now();` `this.lastHeadByTenant.set(input.tenant, input.headHash);` `this.eventLog.append({` |
| F1 (Ticket 01, probe) | node --test tests/probe-m17-poisoned-registry.test.ts | `PROBE-P3 fourth anchor (honest chain against poisoned registry): { tamper: true }` |
| F1 (Ticket 01, red) | node --test tests/m17-federation.test.ts | `AssertionError [ERR_ASSERTION]: a failed append must leave the last accepted head unchanged` `actual: true, expected: false` |
| F1 (Ticket 01, fixed) | Read src/rest-anchors.ts | `// Advance only after the append landed (session-audit ticket 01): a throwing` `// event log must not leave the registry claiming a head the evidence plane` `// never accepted — otherwise the next honest anchor is flagged tamper.` `this.lastHeadByTenant.set(input.tenant, input.headHash);` |
| F1 (Ticket 01, green) | node --test tests/m17-federation.test.ts | `tests 13 / pass 13 / fail 0` |
| F1 (gate re-run) | npm run typecheck && npm test | typecheck exit 0; `tests 540`, `pass 525`, `skipped 15`, `fail 0` |
| N1 (first-anchor) | node --test tests/probe-m17-first-anchor.test.ts | `id: '4f37382b-2161-46ff-8120-37a18b295d1e', acceptedAt: 1790730911122` (tamper undefined) |
| N2 (tamper advances) | node --test tests/probe-m17-cross-tenant.test.ts | `tenants track last head independently and cross-tenant previousHeadHash claims are flagged tamper` (✔) |
| E1/E2 (rest-anchors shape) | Read src/rest-anchors.ts | `class AnchorRegistry { private readonly lastHeadByTenant = new Map<string, string>(); ... record(principal: Principal, input: AnchorInput): RecordedAnchor ... }` |
| E3 (tenant guard) | Read src/rest-anchors.ts:111-112 | `const tenant = str(ctx.body.tenant, 'tenant');` `if (tenant !== ctx.principal.tenantId) throw new RestRejection(403, 'tenant-mismatch');` |
| E9 (wiring) | git diff HEAD src/rest-api.ts | `+ registerAnchorRoutes(api, deps);` |
| E10 (KnownAction) | git diff HEAD src/domain.ts | `+ | 'anchor.register';` |
| E11 (GET status) | git diff HEAD src/rest-sessions.ts | `+ api.addRoute('GET', '/v1/capability-requests/:id', ...)` |
| E12 (capabilityFor) | git diff HEAD src/capability-request.ts | `+ private readonly minted = new Map<string, Capability>();` `+ capabilityFor(requestId: string): Capability | undefined { return this.minted.get(requestId); }` |
| E13 (test count) | Read tests/m17-federation.test.ts | 13 cases across 3 describe blocks (12 at audit start; +1 from ticket-01 fix) |
| E16 (rename) | git status --short | `R  PROMPTS/M17-federation-control-plane.md -> PROMPTS/M-Track--DONE/M17-federation-control-plane.md` |
| E20/E21 (ASL gate) | npm run typecheck && npm test | typecheck exit 0; `tests 540`, `pass 525`, `skipped 15`, `fail 0` (post-ticket-01; pre-fix run was 539/524) |
| E22/E23 (cp gate) | npm run typecheck && npm test (cp) | typecheck exit 0; `Tests 538 passed | 3 skipped` |
| E26 (ponytail) | Read src/rest-anchors.ts:11-14 | `ponytail: the registry is in-memory ... Upgrade: persist accepted heads to a table ...` |
| E27 (no `as any`) | grep on changed files | no hits |
| E28 (no new dep) | git diff HEAD package.json | empty |

## Highest-leverage action
Ticket 01 is closed (fix + red-first test in `tests/m17-federation.test.ts`).
Remaining optional next step, per the ponytail marker at `rest-anchors.ts:11-14`:
persist the accepted-head map alongside the evidence so a restart can
distinguish "first anchor" from "lost predecessor". Not required to ship.
