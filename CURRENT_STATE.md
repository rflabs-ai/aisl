# CURRENT STATE

Honest snapshot. Last updated after the foundation landed.

## What exists

Zero-dependency TypeScript foundation on Node 24, ~1,900 lines of source across
14 modules (`src/`), 70 test assertions (`tests/`, `security-tests/`), a 10-case
attack corpus (`security-attacks/`), legitimate-task fixtures and a document
corpus (`security-fixtures/`), four threat models (`threat-models/`), a measured
benchmark (`benchmarks/results.json`), and this documentation set.

Runtime dependencies: **none**. Dev dependencies: `typescript`, `@types/node`.

## What works

- Capability issuance with issuer-kind enforcement, attenuation, HMAC signing,
  expiry, single-use, constraints, and classification ceilings.
- Policy evaluation: default deny, deny-overrides, approval gating, classification
  ceilings, tenant isolation, deterministic output.
- Authorization: capability AND policy, fail-closed on any internal error.
- Enforcement: one path (`AgentSession.attempt`) for every agent action.
- Gates: network egress decisions, secret access decisions.
- Evidence: SHA-256 hash-chained append-only log with SQLite persistence and a
  verifier.
- Verification plane: post-execution checks with recorded results.
- Demo (`npm run demo`), attack harness (`npm run attack`), benchmark
  (`npm run benchmark`).
- Typecheck: clean (`npx tsc --noEmit`).

## What was tested

All 72 assertions pass. Coverage of the twelve invariants:

1 no capability -> deny (3 cases) | 2 model cannot mint (3) | 3 document cannot
mint (2) | 4 tool cannot expand (2) | 5 expiry (2) | 6 attenuation (4) | 7
decisions logged (2) | 8 tamper-evidence (3) | 9 tenant isolation (3) | 10
network (3) | 11 secrets (2) | 12 fail closed (3).

Plus: policy semantics (8), capability integrity (5), full attack corpus (10 +
3 aggregate), legitimate workload (2), ten hostile-model behaviours.

Measured this run (`benchmarks/results.json`):

- 10/10 attack cases behaved as required; 15/15 adversarial requests denied.
- Prompt-injection-driven requests: 4; successes: 0.
- Legitimate tasks: 2/2 allowed; false-denial rate 0.
- Audit completeness: 17/17 decisions recorded; hash chain valid.

These numbers describe a 10-case corpus written by the same person who wrote the
code. They are not evidence of security against a competent adversary.

## What failed

- Parameter-property syntax (`constructor(private x)`) is not supported by Node's
  type stripping: three modules had to be rewritten with explicit fields.
- Two test bugs found and fixed: a leak-detection regex that matched the benign
  `capabilityId` attribution field, and a self-referential `world` initialization.
- `tsc` initially rejected `.ts` import extensions until
  `allowImportingTsExtensions` was enabled.

No security-relevant test failure was suppressed. Nothing was skipped or marked
`todo` to make the suite green.

## Known vulnerabilities and gaps

Ordered by severity.

1. **No isolation.** `LocalSandbox` executes tool code in-process with full
   runtime privileges. Malicious tool code owns the process.
2. **No authentication.** Any code that can build a `Principal` can act as one.
3. **No egress enforcement.** The gateway decides; nothing enforces. A component
   that opens its own socket is unconstrained.
4. **Secrets in plaintext** in process memory; no encryption, rotation, or
   hardware backing.
5. **Event log is writable.** The chain detects modification and mid-history
   deletion, and a tampered store is now refused on open. It does not detect tail
   truncation or a full recomputation. No signatures, no external anchoring, no
   append-only storage.
6. **Signing key from an environment variable**, unrotated, symmetric.
7. **No resource limits.** No quotas, timeouts, budgets, or rate limiting: a
   resource-exhaustion attack is unmitigated.
8. **Policy is code.** Anyone who can edit the repository can edit the security
   boundary. No signature, versioning, review gate, or attribution.
9. **Shared process for all tenants.** Logical isolation only; one memory-safety
   bug crosses every boundary.
10. **No transport security** because there is no transport.
11. **Detector risk.** `detectInjectionSignals` could be mistaken for a control by
    a future maintainer. It is telemetry.
12. **Unknown-unknowns in the corpus.** 10 cases is a start, not coverage.

## Known assumptions

- The runtime process is not compromised.
- The clock is monotonic and not manipulated by an operator.
- Operators who can change policy are honest.
- The filesystem and SQLite file are not adversarially mutable at rest.
- Resource ids are not secret; authorization is the boundary.
- TypeScript types hold at runtime (no attacker rewriting the module graph).
- Customers will author sane capabilities. The platform constrains scope; it
  cannot constrain judgment.

## Next milestone

**M1 — Real enforcement boundaries** (ROADMAP.md): container sandbox, real egress
proxy, real secret backend. Until then, claims 4, 10, and 11 are interface-level
only: the platform refuses to *hand out* authority or secrets, but it cannot
*contain* code that already has them.

Runner-up: M2 (identity and approvals), because a capability is only as
trustworthy as the human behind it, and today there is no human behind it.

## Reproducing this snapshot

```bash
npm install
npm run typecheck
npm test
npm run demo
npm run attack
npm run benchmark
```
