# THREAT MODEL

Top-level model. Per-boundary detail lives in `threat-models/`.

## 1. Assets

| Asset | Why it matters |
| --- | --- |
| Customer documents, source, PHI/PII, secrets | confidentiality |
| Source repositories, infrastructure configuration | integrity of the business |
| Production systems reachable by tools | availability, integrity |
| The policy set | defines the security boundary itself |
| Capability signing key | forging it means forging authority |
| The event log | the only record of what happened |
| Model provider credentials | cost, and a path to data egress |

## 2. Actors

| Actor | Assumed capability |
| --- | --- |
| Legitimate user | acts within granted authority; may be careless |
| Malicious insider | valid identity, valid approvals, intent to exfiltrate |
| AI model | **assumed hostile**: lies, hallucinates, retries, escalates |
| Document / web page / repo / email | contains adversarial instructions |
| Tool | returns malicious output; attempts scope expansion |
| External attacker | no identity; targets the API, the sandbox, the supply chain |
| Operator / administrator | can change policy and code (see B10) |

## 3. Trust boundaries

See `ARCHITECTURE.md` §4 for B1–B10 with enforcement points. Summary of failure
direction: all boundaries fail closed except B10, which is an accepted open risk
at this stage.

## 4. Attack classes and current status

| Attack class | Control today | Status | Residual risk |
| --- | --- | --- | --- |
| Prompt injection (direct) | data/authority split | **mitigated by construction** | model may still refuse to work |
| Indirect injection (docs, repos, web, email) | same | **mitigated by construction** | same |
| Tool-output injection | same; tool context has no issuance handle | **mitigated** | none identified |
| Cross-tenant access | `@tenant-isolation` + PDP tenant check | **mitigated** | shared-process memory safety |
| Cross-customer (same tenant) | capability scope | **mitigated** | policy authoring errors |
| Privilege escalation | issuer-kind allowlist + attenuation | **mitigated** | operator-issued over-broad caps |
| Secret theft | no allow rule by default; broker gate | **mitigated** | secrets are in memory, unencrypted |
| Network exfiltration | egress gateway, allowlist | **mitigated (decision only)** | no real proxy yet; see below |
| Destructive action | no write/delete capability issued | **mitigated** | depends on issued scope |
| Resource exhaustion | no in-process quotas; decision-latency budget measured (p99 with/without persistence, advisory) | **limited** | rate limiting is deployment territory (reverse proxy, H15/ADR-027); an induced dependency fault is a DoS |
| Sandbox escape | none — `LocalSandbox` is not isolation | **open** | arbitrary code runs in-process |
| Evidence tampering | hash chain + per-event Ed25519 + head-hash anchor + append-only triggers | **detected**; durable when anchor lives outside runtime trust domain | anchor rewrite by an attacker with host access to both the SQLite store and the anchor; key compromise |
| Policy tampering (operator) | none | **open** | B10 |
| Supply chain | supply-chain gate (SBOM diff vs committed baseline, exact pins, sha512 integrity, runtime-dep allowlist) + signed build manifest verified at deploy (H10) | **limited** | signing-key custody (env var); a coerced maintainer; no transparency log |
| Update channel | signed update descriptor chained to the build manifest against the live tree, high-water mark anti-rollback, signed single-use backward-only rollback grant, staged rollout with sticky canary halt (H12) | **limited** | a signed-but-malicious release; caller-supplied health signal; one release key (env); the per-instance state file must sit outside untrusted write reach |
| Model provider compromise | no provider is wired in | **not applicable yet** | becomes critical at provider integration |
| Replay | single-use consumption, expiry; update replay refused by the high-water mark — stale signed descriptors are `rollback-blocked` (H12) | **mitigated** | multi-node consistency not solved |
| Active incident (cannot revoke/freeze/reconstruct/preserve fast enough) | tenant/global kill switch: freeze issuance + `incident-frozen` deny at both chokepoints, bulk capability + session revocation, multi-writer revocation channel (pull <= 1 s default, forced on issuance), paged `asl-incident-bundle` preservation + reconstruction (H13) | **mitigated** | poll-based propagation; a channel writer can freeze (DoS is the H15 accepted trade); in-memory freeze state lost on restart without the Postgres channel; response can still be slower than the attack |
| Safety mechanism failure (broken policy engine, full disk, stalled clock) | per-dependency fault injection with distinct deny reasons (`evaluation-error`, `store-unavailable`/`evidence-write-failure`, `clock-unavailable`), observed `HealthState` with one loud signal per transition, automatic recovery, `/healthz` `{ idp, store, engine, clock }`, kill switch completes under a store outage (H15) | **mitigated/loud** | an adversary who can induce the fault still gets a DoS — accepted trade, now loud, bounded, recoverable; in-memory health resets on restart until the next observed fault |

## 5. Out of scope at this stage

Authentication (nothing authenticates anyone yet), transport security (no
transport), DoS, physical security, side channels, insider abuse of legitimate
authority, model-data memorisation, and anything requiring hardware trust.

## 6. How to extend this model

1. Add a file under `threat-models/` using the same structure.
2. For each new attack path, add a case to `security-attacks/`.
3. A case with no matching test is a claim with no evidence — do not ship it.
4. Re-run `npm run benchmark`; the numbers in `benchmarks/results.json` change
   only when behaviour changes.
