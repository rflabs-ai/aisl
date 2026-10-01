Status: resolved (fix/h13-audit-tickets-10-19)

Source: session-audit 2026-10-01, `feat/h13-incident-response` (audit notes → ticketed on request)

## What's wrong

Two H13 paths are claimed but have no suite test:
1. Cross-node `unfreeze` propagation (`pdp.ts` `case 'unfreeze'`, the `lift`
   path of Claim 35) — `tests/h13-incident-response.test.ts` has no remote-lift
   case (`Select-String ... -Pattern "unfreeze"` matches only a channel fixture
   at test:356).
2. The `revoke-caps` issuance-time fence (`src/pdp.ts:414:
   if ((this.registeredAt.get(cap.id) ?? 0) > record.at) continue;` — the
   Claim 35 sentence "fenced by local issuance time").

## Why it matters

Both behaviors were probe-verified during the audit (P1: `P1 after lift+sync:
B.isFrozen = false`; P6: `P6 cap registered at 2000 (>1000): revoked = false`),
so they work — but a regression would be invisible until an incident.

## Minimal fix

Add two cases to `tests/h13-incident-response.test.ts`: (a) engage + lift on
node A, sync node B, assert `B.isFrozen(tenant) === false` while the revoked
capability stays `capability-revoked`; (b) `applyIncidentRecord('revoke-caps',
at)` revokes a cap registered before `at` and spares one registered after.

## Evidence:

- audit report Notes; probes P1/P6 outputs in
  `.scratch/session-audit/2026-10-01-h13-incident-response/evidence.md`
  (rows 25–26)

## Resolution (fix/h13-audit-tickets-10-19)

Both cases added to `tests/h13-incident-response.test.ts`:
- `ticket 10: a lifted freeze propagates cross-node while revoked authority stays revoked` — engage + lift on node A, one sync on B: `isFrozen` false, the revoked capability stays revoked.
- `ticket 10: revoke-caps is fenced by local issuance time` — authority issued before the record is revoked; authority issued after the record survives the replay.
