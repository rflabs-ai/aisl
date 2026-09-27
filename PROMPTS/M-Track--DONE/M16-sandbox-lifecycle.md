# M16 — Sandbox lifecycle management (ROADMAP row 61)

Baseline: M15 (Stage-0 cleanup) fully [DONE] and merged; 450 tests pass (14
PG-mode skips). M13 introduced the container sandbox (`src/container-sandbox.ts`)
with Docker-backed isolation, resource limits (memory/CPU/PID), non-root user,
read-only rootfs, and seccomp — but the sandbox itself is created once and
left running. Sandbox lifecycle management is the only Stage-1 row still
open: create, limit, destroy, attest. The container-sandbox module already
has Docker plumbing; the missing surface is the lifecycle around it.

Zero new runtime dependencies. The attestation surface reuses the existing
`sealFor` / per-tenant key machinery (ADR-018) — sandbox attestation is a
sealed event with a tenant key, no new crypto. The sandbox runs in-process
via `LocalSandbox` when Docker is unavailable; the lifecycle applies to both.

## Phase 0 — ADR-021 (docs only)

ADR-021 must decide:
- **Create:** how a sandbox is spawned — synchronous or async; who holds the
  handle; what the sandbox id is and how it's named; whether it inherits
  ambient env or starts from a minimal one (the existing `spawnSync` posture
  in `CommandCheck` is the precedent for minimal env).
- **Limit:** what the limits mean and how they fail closed. The existing
  `ContainerSandbox` already takes `memoryBytes` / `cpuShares` / `pidsLimit`
  in its constructor; the lifecycle needs to expose these as a typed config
  record so an embedder can declare them and the runtime can audit them.
- **Destroy:** deterministic teardown; no orphaned containers. On process
  exit, a `beforeExit` (or signal handler) sweeps active sandboxes. Destroy
  must remove the Docker container (`docker rm -f`) and any tmpdir mounts.
- **Attest:** a `sandbox.attest` event that records the sandbox id, tenant,
  resource limits, and a tamper-evident sealed payload (the sandbox's own
  process metadata: PID, start time, image digest when available). The event
  carries `metadata.sealed` via `sealFor` (ADR-018, one key per tenant +
  classification) and a SHA-256 digest of the limit config — no plaintext
  secrets in the event, same posture as `document.ingest` (ADR-020).
- **Capability:** the agent does NOT get the sandbox handle directly; it
  gets a `Capability` with action `tool.invoke` (or a new action
  `sandbox.execute`) scoped to the sandbox resource id. The lifecycle is
  the authority surface; the PDP gates every execute().

Phase 0 is the ADR. Nothing else ships until ADR-021 lands.

## Phase 1 — SandboxRegistry + lifecycle surface

A new `src/sandbox-registry.ts` (single class, no framework) that owns:
- `create({ tenantId, sandboxId, limits, attestationPolicy })` — spawns a
  sandbox, records a `sandbox.create` event (sealed), returns the handle.
- `get(id)` / `list(tenantId)` — tenant-scoped lookups.
- `destroy(id)` — teardown, records `sandbox.destroy` event with sealed
  payload (PID, duration, resource limits actually applied vs declared).
- `attest(id)` — records `sandbox.attest` event with current state, sealed.

The registry holds `ContainerSandbox | LocalSandbox` instances keyed by
sandbox id. The `execute()` path on the sandbox stays where it is
(`ContainerSandbox.runTool`); the registry just wraps the lifecycle.

Events use the existing `EventStore.append` with:
- `action: 'sandbox.create' | 'sandbox.destroy' | 'sandbox.attest'`
- `resourceId: sandboxId`
- `decision: 'allow'`
- `metadata.sealed: sealFor(tenant, payload, 'public')` — sandbox lifecycle
  is not a data label boundary, but sealing the attestation payload keeps
  the tamper-evident invariant (Claim 13)
- `metadata.digest: sha256(canonicalJson({limits, image, ...}))`

The sandbox resource id is registered with the `ResourceRegistry` as
type `'system'` (existing vocabulary), tenant-bound, classification
`'public'` (sandbox metadata is not a data label — same posture as
`audit-log`). PDP gates every `execute()` call on a capability for the
sandbox resource id.

## Phase 2 — CLI demo + tests

- `tests/m16-sandbox-lifecycle.test.ts`: create/destroy round trip, limits
  recorded in event metadata, attest produces sealed payload, destroy
  refuses on unknown id, cross-tenant get returns undefined, missing Docker
  falls back to LocalSandbox (the existing container-sandbox fallback path).
- CLI demo: one new section showing `sandbox.create → execute → attest →
  destroy` with event log output. Mirrors the M13 command-check demo
  section.

## Hard requirements (never simplify away)

- **Tamper-evident attestation:** every `sandbox.create` / `sandbox.destroy`
  / `sandbox.attest` event carries a sealed payload; the plaintext event log
  shows only the digest. Same posture as `document.ingest` (Claim 29).
- **Tenant isolation:** the registry refuses cross-tenant get/destroy; the
  resource registry is the authority for which tenant a sandbox belongs to.
- **No ambient secrets:** sandbox spawn environment is minimal (the
  `CommandCheck` precedent — PATH + SYSTEMROOT on win32, nothing else).
- **Fail-closed:** a sandbox that fails to create does NOT leave an
  orphaned container; the destroy path is idempotent and called on every
  error. Process exit sweeps active sandboxes.
- **Zero new runtime dependencies:** attestation uses `sealFor`; sandbox
  limits use the existing `ContainerSandbox` constructor params; no new
  Docker CLI wrapping beyond what `ContainerSandbox` already shells out to.

## Tests / acceptance

- `tests/m16-sandbox-lifecycle.test.ts`: create/destroy round trip, limits
  sealed in event metadata, destroy on unknown id, cross-tenant get denied,
  LocalSandbox fallback when Docker unavailable, attest payload sealed.
- `tests/m15-persistence-capability-requests.test.ts` still skips without
  `DATABASE_URL` — same posture as the rest of the PG-mode suite.
- The existing `ContainerSandbox` test stays green (no behavior change to
  the sandbox itself).
- Demo exits 0 with the new lifecycle section visible.

## Docs sweep

- ROADMAP row 61 → [DONE] with M16 ref.
- CURRENT_STATE: counts, what-works entry for sandbox lifecycle, what-M16-
  closed section.
- DEPLOYMENT.md: sandbox lifecycle notes (who creates, who destroys, what
  happens on process exit).
- SECURITY_CLAIMS: new Claim 31 — sandbox lifecycle is attested and
  tenant-scoped.
- AGENT-SESSION entry.

## Constraints

- No runtime dependencies. `sealFor` already exists. `ContainerSandbox` already
  exists. The lifecycle is a wrapper, not a reimplementation.
- No `as any` / `as never`. Sandbox ids are strings; limits are typed.
- No secrets in logs/events/errors. The sealed payload covers the attestation
  content; the event metadata carries only the digest.

## Acceptance + skip list

Acceptance: gate green; new suite green; demo exits 0 with lifecycle section;
ROADMAP row 61 → [DONE]; docs updated.

skipped: per-sandbox policy (which actions it may execute), multi-tenant
sandbox sharing, sandbox snapshot/restore, remote attestation via HSM.
add when: a real workflow or customer demands them.

skipped: replacing `LocalSandbox` with a microVM (Firecracker/gVisor) —
add when a deployment cannot trust the host kernel.
