# ARCHITECTURE

The model is not the authority. The infrastructure is.

This document describes the architecture **as built**, not as imagined. Where a
component is a stub, it says so.

## 1. Planes and where they live

```text
                     HUMAN / SYSTEM
                           |
                    identity (OIDC/OAuth2/MFA — see ADR-016)
                           |
                           v
        +----------------------------------------------+
        |                CONTROL PLANE                 |
        |  registry.ts    resources + classifications  |
        |  policy.ts      policy-as-data evaluator     |
        |  pdp.ts         decision point (fail closed) |
        |  capability.ts  capability minting + verify  |
        +----------------------+-----------------------+
                               |
                    CAPABILITY BOUNDARY  (issueCapability, capability.ts:128)
                               |
        +----------------------------------------------+
        |                AGENT PLANE                   |
        |  model.ts    untrusted model behind a port   |
        |  runtime.ts  agent session = enforcement pt  |
        +----------------------+-----------------------+
                               |
            +------------------+------------------+
            v                  v                  v
        COMPUTE             DATA              NETWORK
      runtime.ts        registry.ts          gates.ts
     (LocalSandbox:    (documents are      (egress decisions
      NOT isolation)     inert data)        only, no sockets)
            |                  |                  |
            +------------------+------------------+
                               |
                               v
        +----------------------------------------------+
        |             VERIFICATION PLANE               |
        |  verification.ts  post-execution checks      |
        +----------------------+-----------------------+
                               |
                               v
        +----------------------------------------------+
        |              EVIDENCE PLANE                  |
        |  events.ts  hash-chained append-only log     |
        |  digest in clear; content sealed per level  |
        |  decrypt = evidence.decrypt capability      |
        +----------------------------------------------+
```

## 2. The one boundary that matters: DATA != AUTHORITY

Two types, never convertible:

| Type | Meaning | Who may produce it |
| --- | --- | --- |
| `ActionRequest` (`src/domain.ts:152`) | intent — "I want to do X" | a model, a document, a tool |
| `Capability` (`src/capability.ts:39`) | authority — "I may do X" | `issueCapability` only (`src/capability.ts:128`) |

`ActionRequest` has exactly three fields: `action`, `resourceId`, optional
`params`/`justification`. There is no field on it that any code path reads as
authority. A capability is minted in exactly one function, and that function's
first act is to reject any issuer whose `kind` is `model`, `tool`, or `agent`
(`src/capability.ts:134`).

Consequently, hostile text cannot escalate: there is no parser from text to
authority to attack.

## 3. Request lifecycle

```text
model output (untrusted JSON)
   -> parseModelOutput            src/model.ts:42    whitelist; unknown keys dropped
   -> AgentSession.attempt        src/runtime.ts:139
         -> AuthorizationService.authorize   src/pdp.ts:159
             1. resource must exist                     (unknown -> deny)
              2. tenant must match                       (mismatch -> deny, src/pdp.ts:273)
             3. a capability must cover resource+action (none -> deny)
             4. verifyCapability: signature, subject, tenant, expiry,
                single-use, scope, classification ceiling, constraints
                                                        src/capability.ts:217
              5. policy evaluate: default deny, deny-overrides
                                                        src/policy.ts:295
              6. event appended, always                  src/pdp.ts:159
        -> deny: return, nothing executes
        -> allow: sandbox.run(tool.invoke(scoped ctx))
             -> verification checks                     src/verification.ts
             -> single-use capability consumed
             -> execution event appended
```

Authorization is **capability AND policy**. Both must pass. Both are checked
inside one `try`; any thrown error becomes a deny with reason
`evaluation-error` (invariant 12).

## 4. Trust boundaries

| # | Boundary | Enforcement | Fails |
| --- | --- | --- | --- |
| B1 | Model -> runtime | `parseModelOutput` whitelist; output type carries intent only | closed |
| B2 | Document/tool output -> runtime | Same as B1; `IngestedData.authority === 'none'` | closed |
| B3 | Agent -> resources | `AgentSession.attempt` is the only path | closed |
| B4 | Issuer -> capability | `CAPABILITY_ISSUER_KINDS` allowlist + attenuation | closed |
| B5 | Tenant -> tenant | `src/pdp.ts:273`, plus `@tenant-isolation` in the engine | closed |
| B6 | Session -> network | `NetworkGateway` (decision only, no socket) | closed |
| B7 | Session -> secrets | `SecretBroker` (no rule allows it by default) | closed |
| B8 | Process -> evidence store | Hash chain + per-event Ed25519 + append-only SQLite + head-hash anchor (`src/events.ts`) | detected (durable when anchor is on a different trust domain) |
| B9 | Tool -> authority | `ExecutionContext` has no issuance handle (test asserts it) | closed |
| B10 | Operator -> policy | Policy is data in code, not yet signed/attested | **open** |

B10 is the honest weak point: today a person who can edit the repository can
edit policy. That is a supply-chain and privileged-access problem, tracked as
ADR-012 and the HARD/VERY HARD roadmap stages.

## 5. Deliberate stubs (do not mistake these for controls)

| Component | Status | Reality |
| --- | --- | --- |
| Identity / MFA / SSO | implemented (M2) | OIDC via `jose`; MFA enforced at the IdP and re-checked by the PDP. No SPIFFE/workload identity yet (HARD). |
| `LocalSandbox` (`src/runtime.ts:75`) | stub | Runs in-process. Provides **zero** isolation. `ContainerSandbox` is the real backend when Docker is available. |
| `NetworkGateway` | stub | Decides, never connects. The `EgressProxy` is the real backend. |
| `SecretBroker` | implemented (M1) | `EnvelopeSecretBroker`: AES-256-GCM + HKDF-derived per-secret DEKs. KMS/HSM backing is HARD. |
| Policy distribution | stub | Rules are TypeScript objects; no signature, no versioning. |
| Model provider | stub | Scripted models only. No network call to any provider. |
| Storage | minimal | SQLite for events; everything else in memory. |
| Injection detector | **not a control** | Telemetry only (`src/registry.ts:95`). Authorization never reads it. |

## 6. Improvements made to the proposed architecture

The brief's plane diagram was sound. Four changes, all recorded in DECISIONS.md:

1. **The policy decision point is collocated, not a sidecar.** A network hop for
   every authorization decision adds an availability dependency to the one
   component that must always answer. In-process, fail-closed (ADR-001).
2. **Capabilities are signed at issuance and verified at use.** The brief lists
   capability fields but not integrity. Unsigned capabilities are bearer
   tokens; a signed one cannot be edited by its holder (ADR-002).
3. **Verification sits between execution and evidence, not after it.** A failed
   verification is recorded as an execution error, so "allowed" and "checked
   out clean" are distinct facts in the log.
4. **Injection detection was demoted from control to telemetry.** Filtering is
   not a boundary; the data/authority split is. The detector exists so an
   investigator can see attempts, not to stop them (ADR-011).

## 7. Extension seams

Each seam is an interface with one trivial implementation today:

- `PolicyEngine` (`src/policy.ts:175`) — swap in Cedar or OPA without touching callers.
- `ModelPort` (`src/model.ts:26`) — any provider, any local model.
- `Sandbox` (`src/runtime.ts:64`) — container today, microVM later.
- `Check` (`src/verification.ts:30`) — arbitrary post-execution verification.
- `EventLog` storage — SQLite now (with append-only triggers and per-event signatures), head-hash anchor file, append-only WORM/object storage later.

## 8. Deployment shapes (architected, not yet built)

| Shape | Control plane | Data plane | Status |
| --- | --- | --- | --- |
| Development | local process | in-memory + SQLite | **works today** |
| Single-node private | same process | local disk | near |
| SaaS multi-tenant | shared | shared, tenant-keyed | needs B5 hardening + Postgres |
| Customer VPC | vendor | customer | needs split-plane packaging |
| On-prem | customer | customer | needs packaging + updates |
| Offline / air-gapped | customer | customer | needs signed bundles + local models |

See DEPLOYMENT.md for the per-shape breakdown.
