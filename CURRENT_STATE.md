# CURRENT STATE

Honest snapshot. Updated after M1 — real enforcement boundaries landed.

## What exists

Zero-dependency TypeScript foundation on Node 24, ~2,400 lines of source across
17 modules (`src/`), 101 test assertions (`tests/`, `security-tests/`), a 10-case
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
- **Container sandbox** (`src/container-sandbox.ts`): Docker-backed isolation
  with non-root, read-only rootfs, no network namespace, seccomp, memory/CPU/PID
  limits. Falls back to `LocalSandbox` when Docker is unavailable.
- **Egress proxy** (`src/egress-proxy.ts`): HTTP proxy that intercepts traffic,
  blocks IP literals, and routes every request through the PDP before forwarding.
  Sessions have no route out except through the proxy.
- **Envelope encryption** (`src/envelope-secrets.ts`): AES-256-GCM envelope
  encryption with HKDF-derived DEKs. Secrets are never stored in plaintext.
  Evidence records get a redacted placeholder.
- Gates: network egress decisions (PDP-gated + proxy-enforced), secret access
  decisions (PDP-gated + envelope-encrypted).
- Evidence: SHA-256 hash-chained append-only log with SQLite persistence, a
  verifier, resume across restart, and refusal to extend a tampered store.
- Evidence confidentiality: every output is sealed (AES-256-GCM, one key per
  classification, HKDF from a master key) and digestable; content is readable
  only with an `evidence.decrypt` capability for that level, and reading it is
  itself an audited decision.
- Verification plane: post-execution checks with recorded results.
- Demo (`npm run demo`), attack harness (`npm run attack`), benchmark
  (`npm run benchmark`).
- Typecheck: clean (`npx tsc --noEmit`).

## What was tested

All 101 assertions pass. Coverage of the twelve invariants:

1 no capability -> deny (3) | 2 model cannot mint (3) | 3 document cannot
mint (2) | 4 tool cannot expand (2) | 5 expiry (2) | 6 attenuation (4) | 7
decisions logged (2) | 8 tamper-evidence (5) | 9 tenant isolation (3) | 10
network (3) | 11 secrets (2) | 12 fail closed (3).

Plus: policy semantics (8), capability integrity (5), evidence sealing (6),
model output parsing (2), full attack corpus (10 + 3 aggregate), legitimate
workload (2), ten hostile-model behaviours, **21 M1 enforcement tests**
(container sandbox, egress proxy, envelope secrets, canary exfiltration,
secret-unreachable-from-sandbox, attack corpus with real backends).

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

1. **No authentication.** Any code that can build a `Principal` can act as one.
2. **Event log is writable.** The chain detects modification and mid-history
   deletion, and a tampered store is now refused on open. It does not detect tail
   truncation or a full recomputation. No signatures, no external anchoring, no
   append-only storage.
3. **Signing key from an environment variable**, unrotated, symmetric.
4. **No resource limits at the process level.** The container sandbox enforces
   memory/CPU/PID limits when Docker is available; the host process itself has no
   quotas, timeouts, budgets, or rate limiting.
5. **Policy is code.** Anyone who can edit the repository can edit the security
   boundary. No signature, versioning, review gate, or attribution.
6. **Shared process for all tenants.** Logical isolation only; one memory-safety
   bug crosses every boundary. Container sandbox isolates per-task when Docker is
   available.
7. **No transport security** because there is no transport.
8. **Detector risk.** `detectInjectionSignals` could be mistaken for a control by
   a future maintainer. It is telemetry.
9. **Unknown-unknowns in the corpus.** 10 cases is a start, not coverage.
10. **Attenuation is declared, not proven.** `issuerAuthority` is an object the
    caller supplies; a caller can overstate it. Delegation must carry the
    parent's signature (ADR-002, H1).
11. **No capability revocation.** Only expiry and single-use exist. There is no
    way to withdraw a capability that is already issued (MEDIUM stage, H13).
12. **Fail-closed is incompressible.** A broken engine, full disk, or closed
    evidence store denies everything silently, with no health signal or degraded
    mode (H15).
13. **Policy cannot express resource hierarchy.** Matching is exact id, type, or
    classification ceiling — no prefixes or globs, so "all docs under project X"
    is inexpressible (MEDIUM stage).
14. **Zero runtime dependencies is temporary.** It ends at M2 (OIDC, drivers,
    HTTP). The admission policy must land before the first runtime dep, not
    after.
15. **Structural invariants are maintenance-dependent.** "No path from text to
    authority" holds only while nobody adds one. It is enforced by tests over
    today's paths, not by a lint rule.

## What M1 closed

1. ~~**No isolation.**~~ `ContainerSandbox` provides Docker-backed isolation
   (non-root, read-only rootfs, no network, seccomp, resource limits) when
   Docker is available. Falls back to `LocalSandbox` with the ceiling documented
   in the `kind` string.
2. ~~**No egress enforcement.**~~ `EgressProxy` intercepts HTTP traffic, blocks
   IP literals, and routes through the PDP. Sandbox `--network none` ensures no
   bypass path when Docker is available.
3. ~~**Secrets in plaintext.~~ `EnvelopeSecretBroker` stores secrets encrypted
   with AES-256-GCM. Evidence records contain `[decrypted-withheld]`, not
   plaintext values.

## Known assumptions

- The runtime process is not compromised.
- The clock is monotonic and not manipulated by an operator.
- Operators who can change policy are honest.
- The filesystem and SQLite file are not adversarially mutable at rest.
- Resource ids are not secret; authorization is the boundary.
- TypeScript types hold at runtime (no attacker rewriting the module graph).
- Customers will author sane capabilities. The platform constrains scope; it
  cannot constrain judgment.
- Docker is available for full isolation; without it, the sandbox falls back to
  in-process execution.

## Reproducing this snapshot

```bash
npm install
npm run typecheck
npm test
npm run demo
npm run attack
npm run benchmark
```
