# Evidence ledger — session audit of M17 federation ASL gap closure (2026-09-29)

Target: uncommitted changes in both repos (no commit yet — the work is staged
for review). Committed work in `control-plane` is the prior session audit and
the federation client (30da058 + bb8807c + b587fed); the only changes in
this session are:

- ASL repo (working tree):
  - new `src/rest-anchors.ts` (AnchorRegistry + POST /v1/anchors)
  - new `tests/m17-federation.test.ts` (12 cases)
  - modified `src/domain.ts` (adds KnownAction 'anchor.register')
  - modified `src/rest-api.ts` (wires registerAnchorRoutes into createRestApi)
  - modified `src/rest-sessions.ts` (adds GET /v1/capability-requests/:id)
  - modified `src/capability-request.ts` (adds capabilityFor + minted Map)
  - docs sweep: ROADMAP, CURRENT_STATE, SECURITY_CLAIMS (Claim 33),
    AGENT-SESSION (session 27)
  - renames PROMPTS/M17-federation-control-plane.md to M-Track--DONE/
- control-plane repo (working tree):
  - .scratch/m17-federation/{spec.md, 04, 05, 01, 02}: tickets 04/05 marked
    resolved; prompt path updated
  - ROADMAP: M17 status → [DONE]
  - README: gap-tickets note replaced with endpoints-landed note

| #  | ref | command run | raw output (paste the exact line(s)) |
|----|-----|-------------|--------------------------------------|
| E1 | rest-anchors import | Read src/rest-anchors.ts | `import { randomUUID } from 'node:crypto';` `import type { Principal } from './domain.ts';` `import type { EventStore } from './events.ts';` `import { RestRejection, optStr, str, type RestApi, type RestResponse } from './rest-api.ts';` |
| E2 | rest-anchors shape | Read src/rest-anchors.ts | class with `lastHeadByTenant: Map<string,string>`, `record(principal,input)`, regex `SHA256_HEX = /^[0-9a-f]{64}$/` |
| E3 | route guard tenant | Read src/rest-anchors.ts:111-112 | `const tenant = str(ctx.body.tenant, 'tenant');` `if (tenant !== ctx.principal.tenantId) throw new RestRejection(403, 'tenant-mismatch');` |
| E4 | route guard hash | Read src/rest-anchors.ts:113-115 | `const headHash = sha256Field(ctx.body.headHash, 'headHash');` `const rawPrevious = optStr(ctx.body.previousHeadHash, 'previousHeadHash');` `const previousHeadHash = rawPrevious !== undefined ? sha256Field(rawPrevious, 'previousHeadHash') : undefined;` |
| E5 | tamper predicate | Read src/rest-anchors.ts:56-58 | `const previous = this.lastHeadByTenant.get(input.tenant);` `const tamper =` `  input.previousHeadHash !== undefined && previous !== undefined && input.previousHeadHash !== previous;` |
| E6 | state-mutate order | Read src/rest-anchors.ts:59-63 | `const id = randomUUID();` `const acceptedAt = this.now();` `this.lastHeadByTenant.set(input.tenant, input.headHash);` `this.eventLog.append({` ... |
| E7 | event metadata keys | Read src/rest-anchors.ts:71-78 | `metadata: { phase: 'federation-anchor', headHash: input.headHash, eventCount: input.eventCount, anchoredAt: input.anchoredAt, ...(input.previousHeadHash !== undefined ? { previousHeadHash: input.previousHeadHash } : {}), ...(tamper ? { tamper: true, expectedHeadHash: previous } : {}) }` |
| E8 | response body shape | Read src/rest-anchors.ts:127-134 | `body: { id: recorded.id, acceptedAt: recorded.acceptedAt, ...(recorded.tamper ? { tamper: true } : {}) }` |
| E9 | route wiring | git diff HEAD src/rest-api.ts | `+import { registerAnchorRoutes, type AnchorRouteDeps } from './rest-anchors.ts';` `+ registerAnchorRoutes(api, deps);` `+export interface RestApiFullDeps extends RestApiDeps, SessionRouteDeps, AuditRouteDeps, AnchorRouteDeps {}` |
| E10 | KnownAction union | git diff HEAD src/domain.ts | `| 'audit.export'` `+ | 'anchor.register';` |
| E11 | GET status route | git diff HEAD src/rest-sessions.ts | adds `GET /v1/capability-requests/:id`, body `{ request: projectRequest(request), ...(capability !== undefined ? { capability: projectCapability(capability) } : {}) }` |
| E12 | capabilityFor plumbing | git diff HEAD src/capability-request.ts | `+ private readonly minted = new Map<string, Capability>();` `+ this.minted.set(requestId, capability);` `+ capabilityFor(requestId: string): Capability | undefined { return this.minted.get(requestId); }` |
| E13 | M17 test coverage | Read tests/m17-federation.test.ts | 13 cases across 3 `describe` blocks (POST /v1/anchors × 6, GET status × 6, AnchorRegistry poisoning × 1 — was 12 pre-fix) |
| E14 | first-anchor with prevHead claim | rest-anchors.ts:57 — see E5 | `previous === undefined` ⇒ tamper = false regardless of claimed previousHeadHash. UNVERIFIED behaviour — see probe P1 below. |
| E15 | matchRoute length | rest-api.ts:336 — read in this run | `if (route.method !== method || route.segments.length !== parts.length) continue;` (length-distinct so `GET /v1/capability-requests` and `GET /v1/capability-requests/:id` do not collide) |
| E16 | docs rename | git status --short | `R  PROMPTS/M17-federation-control-plane.md -> PROMPTS/M-Track--DONE/M17-federation-control-plane.md` (similarity 100%) |
| E17 | docs sweep markers (ASL) | git diff HEAD ROADMAP.md | `[DONE]` on Federation table row M17 (line 392 in patched file), M17 spec header (line 644), working order (line 144) |
| E18 | docs sweep markers (cp) | git diff HEAD ROADMAP.md (cp) | M17 status `[client built — end-to-end blocked on ASL gap routes]` → `[DONE]`; ticket 04/05 status: open → resolved |
| E19 | control-plane scratch refs to prompt path | git diff HEAD .scratch/m17-federation/{spec.md,issues/01,02,04,05}.md | all `PROMPTS/M17-federation-control-plane.md` → `PROMPTS/M-Track--DONE/M17-federation-control-plane.md` |
| E20 | gate: typecheck (ASL) | run npm run typecheck | `> tsc --noEmit` exit 0 (see Gates section) |
| E21 | gate: tests (ASL) | run npm test | 540 tests / 525 pass / 15 PG-skip / 0 fail (post-ticket-01; pre-fix run was 539/524) |
| E22 | gate: typecheck (cp) | run npm run typecheck | exit 0 |
| E23 | gate: tests (cp) | run npm test | 538 passed / 3 skipped |
| E24 | secret scan in anchor response | Read rest-anchors.ts:127-134 + tests/m17-federation.test.ts:144 | response is `{id, acceptedAt, tamper?}`; test asserts no `"signature"` substring |
| E25 | known limitations called out | SECURITY_CLAIMS Claim 33 "Known limitations" | "the anchor registry is in-memory, so 'first anchor' vs 'lost predecessor' is not distinguished across an ASL restart ... mismatch detection is advisory" — matches the ponytail marker at rest-anchors.ts:11-14 |
| E26 | ponytail marker | Read rest-anchors.ts:11-14 | "ponytail: the registry is in-memory (mismatch detection is advisory; the durable attestation is the event itself, which the EventStore already persists append-only). Upgrade: persist accepted heads to a table if a restart must distinguish 'first anchor' from 'lost predecessor'." |
| E27 | no `as any` / `as never` in changed files | grep | none in rest-anchors.ts, tests/m17-federation.test.ts, rest-sessions.ts, capability-request.ts, rest-api.ts, domain.ts |
| E28 | no new runtime dependency | package.json diff | unchanged — both gates ran without additions |
| E29 | probe P1 — first-anchor claim prevHead | run tests/probe-m17-first-anchor.ts (below) | tampered:false on first anchor with bogus previousHeadHash |
| E30 | probe P2 — registry updates before event append | code path rest-anchors.ts:59-63 | registry.set happens before eventLog.append; if append throws, registry is poisoned (covered by probe P3) |
| E31 | probe P3 — what happens if eventLog.append throws | run tests/probe-m17-poisoned-registry.ts (below) | observed: registry updated to HASH_B before append throws; subsequent anchor with correct previousHeadHash=HASH_A is silently flagged tamper (Bug verified) |
| E32 | ticket 01 red | node --test tests/m17-federation.test.ts (before fix) | `AssertionError [ERR_ASSERTION]: a failed append must leave the last accepted head unchanged` `actual: true, expected: false, operator: 'strictEqual'` |
| E33 | ticket 01 fix | Read src/rest-anchors.ts (after fix) | `// Advance only after the append landed (session-audit ticket 01): a throwing` / `// event log must not leave the registry claiming a head the evidence plane` / `// never accepted — otherwise the next honest anchor is flagged tamper.` / `this.lastHeadByTenant.set(input.tenant, input.headHash);` |
| E34 | ticket 01 green | node --test tests/m17-federation.test.ts (after fix) | `tests 13`, `pass 13`, `fail 0` |
| E35 | gate re-run (ASL) | npm run typecheck; npm test | typecheck exit 0; `tests 540`, `pass 525`, `skipped 15`, `fail 0` |
