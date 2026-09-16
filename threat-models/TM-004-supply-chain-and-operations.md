# TM-004 — Supply chain, operators, and evidence integrity

## Scope

Everything that can change what the system *is*: dependencies, the policy set,
the signing key, the event store, and the people who administer them.

## Adversary

A compromised dependency, a malicious or coerced operator, or an attacker who
has already gained write access to infrastructure.

## Entry points

1. `npm install` — dependencies (currently: `typescript`, `@types/node`, dev only).
2. The policy set, which is TypeScript compiled into the process.
3. `CAPABILITY_SIGNING_KEY` and its storage.
4. The SQLite event store.
5. Direct code change.

## Attack paths

| Path | Expected outcome today |
| --- | --- |
| Edit a policy rule to allow anything | **succeeds** — no signature, no attestation |
| Steal the signing key | forge capabilities; detection depends on audit review |
| Rewrite the event log in place | **detected** by chain verification, but not prevented |
| Delete the event log entirely | **succeeds**; no external anchoring |
| Add a malicious dependency | **succeeds**; no pinning, lockfile ignored, no SBOM |
| Administrator mints a broad capability | succeeds and is logged |

## Controls

- Hash-chained events detect *modification* (`src/events.ts:119`).
- Capability signatures detect *forgery without the key* (`src/capability.ts:110`).
- Every issuance is logged with provenance (`src/pdp.ts:70`).
- Runtime dependency count is zero, so the production attack surface from
  third-party code is currently nil.

## Assumptions

- Operators are honest but fallible. **This is known to be insufficient** for
  high-assurance deployments.
- The filesystem and database are not adversarially mutable at rest.

## Failure modes

- Chain verification only proves internal consistency. An attacker with write
  access can recompute the whole chain.
- No append-only or WORM storage; no external timestamping.
- No separation between "can deploy" and "can read data".

## Test methodology

Invariant 8 (tamper detection); `tests/policy.test.ts` deterministic evaluation;
benchmark reports `hashChainValid` and `auditCompleteness` on every run.

## Residual risk

High, and deliberately acknowledged. This is the largest gap between the current
foundation and the stated end state. Closing it requires signed and reproducible
builds, external anchoring of the event chain, hardware-backed keys, dual
control for policy changes, and background checks and privileged-access
management for operators — none of which is a software feature.
