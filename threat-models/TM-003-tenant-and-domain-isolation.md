# TM-003 — Tenant and sensitivity-domain isolation

## Scope

Isolation between organizations (tenants), between customers inside one tenant,
and between classification levels.

## Adversary

An agent or user belonging to tenant A / customer A / low clearance, attempting
to reach tenant B / customer B / restricted material.

## Entry points

1. Any `authorize()` call with a resource id from another domain.
2. Capability issuance across tenants.
3. Direct resource lookup by id (id guessing, enumeration).

## Attack paths

| Path | Expected outcome |
| --- | --- |
| Read another tenant's document by id | denied (`tenant-mismatch`) |
| Foreign agent presents tenant A's capability | denied (subject and tenant bind) |
| Root of tenant A issues for tenant B | refused at issuance |
| Read above the capability ceiling | denied (`classification-ceiling`) |
| Read customer B while scoped to customer A | denied (`no-capability`/`capability-scope`) |
| Unknown resource id | denied (`unknown-resource`), never defaulted to public |

## Controls

- `src/pdp.ts:273` — tenant equality checked before policy.
- `src/policy.ts:157` — `@tenant-isolation` deny, independent of any rule set.
- `src/capability.ts:39` — capabilities bind `subject` and `tenantId`.
- Classification ceilings enforced twice: capability (`src/capability.ts:239`)
  and policy rule (`src/policy.ts:171`).
- Unknown classification labels rank at the ceiling (`src/domain.ts:109`).

## Assumptions

- Single process, single trust domain for the control plane.
- Resource ids are not themselves secret; authorization is the boundary.

## Failure modes

- A rule authored with `tenant: 'any'` — the schema allows it, and only
  `@tenant-isolation` stands in the way. Should be removed from the schema.
- Shared in-memory registries mean a memory-disclosure bug crosses tenants.
- No row-level isolation: SQLite stores all tenants' events in one table.

## Test methodology

Invariant 9 and 11; `security-attacks/ATK-003`, `ATK-009`, `ATK-010`;
`tests/policy.test.ts` cross-tenant case.

## Residual risk

Isolation is logical, enforced in one process. A memory-safety bug, a
serialization bug, or a compromised operator collapses it. Real isolation
(separate processes, microVMs, separate keys per tenant) is a VERY HARD stage
item.
