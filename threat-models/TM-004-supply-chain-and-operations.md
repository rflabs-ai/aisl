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
| Add a malicious dependency | **detected/limited** by the supply-chain gate (H10/ADR-024): exact pins, sha512 integrity + registry-pinned resolved URLs verified per lockfile entry, deterministic SBOM diffed against the committed `artifacts/sbom.json` baseline, and the `ADMITTED_RUNTIME_DEPS` allowlist — a new runtime dep fails the gate until an admission ADR lands in the same reviewed PR. A malicious update to an already-trusted dep is the residual (a version bump is a visible diff; content compromise inside a trusted version is outside this control). |
| Direct code change | **detected/limited** since H10 (ADR-024): the signed build manifest binds `treeDigest` (git blob SHAs over all tracked files, outputs excluded), `sbomDigest`, and the gate result under an Ed25519 signature; `build verify` recomputes and refuses stale-source/stale-dependencies/bad-signature/gate-not-passed at deploy. Before a manifest exists, or with the signing key compromised, this path **succeeds** — that is the residual. |
| Administrator mints a broad capability | succeeds and is logged |

## Controls

- Hash-chained events detect *modification*; Ed25519 per-event signatures
  detect *forgery without the signing key*; the head-hash anchor file plus
  append-only SQLite triggers raise the bar from "edit one row" to "edit
  one row and one file in lock-step".
- Capability signatures detect *forgery without the key* (`src/capability.ts:110`).
- Every issuance is logged with provenance (`src/pdp.ts:85`).
- Runtime dependency count is two (`jose`, `postgres`), exact-pinned, each
  admitted by an ADR (ADR-015, ADR-018) and enforced by the supply-chain gate
  (`src/supply-chain.ts`, H10): SBOM diff vs the committed baseline, sha512
  integrity, registry-pinned resolved URLs, and the code-enforced
  `ADMITTED_RUNTIME_DEPS` allowlist.
- The signed build manifest (`artifacts/build-manifest.json` + `.sig`) binds
  source, dependencies, and gate result under an Ed25519 signature; deploy
  verifies it before start (DEPLOYMENT.md). Residual: key custody is an env
  var until ADR-008's KMS path; no transparency log (H11/Stage-3).
- The third-party attack surface in production is small but not nil; the
  residual is what `jose` and `postgres` themselves do.

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
benchmark reports `hashChainValid` and `auditCompleteness` on every run;
`tests/h10-supply-chain.test.ts` (SBOM determinism + drift gate, pin/integrity
refusals, tree-digest staleness, manifest sign/verify fail-closed).

## Residual risk

MEDIUM when the anchor is on attacker-accessible storage (the default in
the demo), LOW when the anchor is on a customer-held WORM bucket or a
transparency log the runtime cannot rewrite. Closing the gap requires
hardware-backed keys, signed-key bundles, periodic transparency-log
publication, and dual control for policy changes — none of which is a
software feature alone.
