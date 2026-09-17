# TM-004 — Supply chain, operators, and evidence integrity

## Scope

Everything that can change what the system *is*: dependencies, the policy set,
the signing key, the event store, and the people who administer them.

## Adversary

A compromised dependency, a malicious or coerced operator, or an attacker who
has already gained write access to infrastructure.

## Entry points

1. `npm install` — dependencies (`typescript`, `@types/node` dev-only; one runtime
   dep `jose` admitted under ADR-015 with pinning, lockfile, SBOM policy, and a
   maintainer review gate).
2. The policy set, which is TypeScript compiled into the process.
3. `CAPABILITY_SIGNING_KEY` and its storage.
4. The SQLite event store.
5. Direct code change.

## Attack paths

| Path | Expected outcome today |
| --- | --- |
| Edit a policy rule to allow anything | **succeeds** — no signature, no attestation |
| Steal the signing key | forge capabilities; detection depends on audit review |
| Rewrite the event log in place | **detected** by chain + signature verification; SQLite UPDATE/DELETE refused by append-only triggers |
| Delete the event log entirely | **detected** when the bundle is reconciled against the head-hash anchor file (and the anchor is on a different trust domain); still **succeeds** as a destruction if both store and anchor are on attacker-controlled storage |
| Add a malicious dependency | **detected/limited** by the dependency admission policy (ADR-015): pinned in `package.json`, lockfile committed, SBOM diffed on build, no transitive runtime deps allowed, maintainer review gate. A malicious update to an already-trusted dep is the residual. |
| Administrator mints a broad capability | succeeds and is logged |

## Controls

- Hash-chained events detect *modification*; Ed25519 per-event signatures
  detect *forgery without the signing key*; the head-hash anchor file plus
  append-only SQLite triggers raise the bar from "edit one row" to "edit
  one row and one file in lock-step".
- Capability signatures detect *forgery without the key* (`src/capability.ts:110`).
- Every issuance is logged with provenance (`src/pdp.ts:85`).
- Runtime dependency count is one (`jose`), admitted under ADR-015 with a
  documented admission policy. The third-party attack surface in production is
  small but not nil; the residual is what `jose` itself does.

## Assumptions

- Operators are honest but fallible. **This is known to be insufficient** for
  high-assurance deployments.
- The filesystem and database are not adversarially mutable at rest *unless*
  the anchor file is on a different trust domain.

## Failure modes

- Chain + signature verification proves internal consistency with cryptographic
  attribution. An attacker with host access can still rewrite both the
  SQLite store and the anchor file *consistently* if they hold the signing
  key — which is why the anchor is meant to live on a witness the runtime
  does not control.
- No transparency-log publication yet (HARD stage).
- No separation between "can deploy" and "can read data".

## Test methodology

Invariant 8 (tamper detection); `tests/m3-evidence-hardening.test.ts`
(signature tamper, tail truncation, anchor reconciliation, offline verifier,
structural API check); `tests/policy.test.ts` deterministic evaluation;
benchmark reports `hashChainValid` and `auditCompleteness` on every run.

## Residual risk

MEDIUM when the anchor is on attacker-accessible storage (the default in
the demo), LOW when the anchor is on a customer-held WORM bucket or a
transparency log the runtime cannot rewrite. Closing the gap requires
hardware-backed keys, signed-key bundles, periodic transparency-log
publication, and dual control for policy changes — none of which is a
software feature alone.
