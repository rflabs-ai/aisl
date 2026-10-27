/**
 * Sandbox lifecycle management (M16, ADR-021): create, limit, destroy, attest.
 *
 * A wrapper over the existing sandbox seam, not a reimplementation: the handle
 * wraps a `ContainerSandbox` (which falls back to `LocalSandbox` without
 * Docker); limits are `ContainerSandboxOptions`; attestation reuses `sealFor`
 * (ADR-018) and the event chain (Claim 13).
 *
 * Authority surface: the agent never receives the handle. Execution goes
 * through `execute()`, which authorizes `sandbox.execute` on the sandbox
 * resource id via the ordinary PDP path before `runTool`. The ResourceRegistry
 * is the authority for which tenant a sandbox belongs to; every lifecycle call
 * re-checks the binding and refuses cross-tenant access.
 */

import { createHash } from 'node:crypto';
import { type Principal, type PrincipalKind, canonicalJson } from './domain.ts';
import { ContainerSandbox, effectiveLimits, type ContainerSandboxOptions } from './container-sandbox.ts';
import { type EventStore } from './events.ts';
import { type ResourceRegistry } from './registry.ts';
import { type AuthorizationService } from './pdp.ts';
import { type ExecutionContext, type Sandbox, type Tool, type ToolResult, LocalSandbox } from './runtime.ts';
import { sealFor, type Sealed } from './seal.ts';

/** The limits contract IS the container sandbox's constructor options (ADR-021). */
export type SandboxLimits = ContainerSandboxOptions;

/** Action the PDP gates execution on, scoped to the sandbox resource id. */
export const SANDBOX_EXECUTE_ACTION = 'sandbox.execute';

export interface SandboxHandle {
  /** Namespaced id: `sandbox:<tenantId>:<name>`. */
  readonly id: string;
  readonly tenantId: string;
  readonly name: string;
  /** Honest about degradation: `container/...` or `fallback/...`. */
  readonly kind: string;
  readonly limits: SandboxLimits;
  /** The executable seam. Held by the embedder/runtime, never handed to the agent. */
  readonly sandbox: Sandbox;
  readonly createdAt: number;
}

export interface SandboxRegistryDeps {
  readonly registry: ResourceRegistry;
  readonly eventLog: EventStore;
  readonly authorization: AuthorizationService;
  /** Attribution only — the actor id/kind recorded on lifecycle events. */
  readonly actorId: string;
  readonly actorKind: PrincipalKind;
}

export class UnknownSandboxError extends Error {
  constructor(id: string) {
    super(`unknown sandbox: ${id}`);
    this.name = 'UnknownSandboxError';
  }
}

export class SandboxRegistry {
  private readonly deps: SandboxRegistryDeps;
  private readonly active = new Map<string, SandboxHandle>();
  private readonly created: Map<string, SandboxHandle> = new Map();
  private exitSweepInstalled = false;

  constructor(deps: SandboxRegistryDeps) {
    this.deps = deps;
  }

  /**
   * Spawn a sandbox, register it as a tenant-bound system resource, and record
   * a sealed `sandbox.create` event. Spawn happens BEFORE registration, so a
   * failure leaves no half-registered handle (fail closed, no orphan).
   */
  create(input: {
    readonly tenantId: string;
    readonly sandboxId: string;
    readonly limits?: SandboxLimits;
  }): SandboxHandle {
    const id = this.fullId(input.tenantId, input.sandboxId);
    if (input.sandboxId.length === 0) throw new Error('sandboxId must be non-empty');
    if (this.created.has(id)) throw new Error(`sandbox already exists: ${id}`);

    const limits = input.limits ?? {};
    const sandbox: Sandbox = new ContainerSandbox(new LocalSandbox(), limits);
    const handle: SandboxHandle = {
      id,
      tenantId: input.tenantId,
      name: input.sandboxId,
      kind: sandbox.kind,
      limits,
      sandbox,
      createdAt: Date.now(),
    };

    this.deps.registry.add({
      id,
      type: 'system',
      tenantId: input.tenantId,
      classification: 'public',
      attributes: { purpose: 'sandbox', kind: sandbox.kind },
    });

    const payload = canonicalJson({
      id,
      tenantId: input.tenantId,
      kind: sandbox.kind,
      limits,
      effectiveLimits: effectiveLimits(limits),
      pid: process.pid,
      createdAt: handle.createdAt,
    });
    this.append('sandbox.create', id, input.tenantId, sandbox.kind, limits, payload);

    this.active.set(id, handle);
    this.created.set(id, handle);
    return handle;
  }

  /** Tenant-scoped lookup. A sandbox bound to another tenant reads as absent. */
  get(tenantId: string, sandboxId: string): SandboxHandle | undefined {
    const handle = this.active.get(this.fullId(tenantId, sandboxId));
    if (!handle) return undefined;
    this.assertTenant(handle, tenantId);
    return handle;
  }

  list(tenantId: string): readonly SandboxHandle[] {
    return [...this.active.values()].filter((h) => h.tenantId === tenantId);
  }

  /**
   * Execute a tool inside the sandbox. The PDP gates every call:
   * `sandbox.execute` on the sandbox resource id, through the ordinary
   * authorize path (which appends its own decision event). No capability, no
   * execution — the registry holds no grant of its own.
   */
  execute(input: {
    readonly tenantId: string;
    readonly sandboxId: string;
    readonly principal: Principal;
    readonly tool: Tool;
    readonly params?: Readonly<Record<string, unknown>>;
  }): { executed: boolean; reason: string; output?: unknown } {
    const id = this.fullId(input.tenantId, input.sandboxId);
    const decision = this.deps.authorization.authorize({
      principal: input.principal,
      action: SANDBOX_EXECUTE_ACTION,
      resourceId: id,
    });
    if (decision.decision === 'deny' || !decision.capabilityId) {
      return { executed: false, reason: decision.reason };
    }
    const handle = this.get(input.tenantId, input.sandboxId);
    if (!handle) return { executed: false, reason: 'sandbox is not active' };

    const ctx: ExecutionContext = {
      sessionId: `sandbox:${input.sandboxId}`,
      capabilityId: decision.capabilityId,
      resourceId: id,
      resourceType: 'system',
      resourceClassification: this.deps.registry.get(id)?.classification ?? 'x-unknown-resource',
      action: SANDBOX_EXECUTE_ACTION,
      params: input.params ?? {},
      content: undefined,
      now: Date.now(),
    };
    const result: ToolResult = handle.sandbox.runTool(input.tool, ctx);
    return { executed: true, reason: decision.reason, output: result.output };
  }

  /** Record current state as a sealed `sandbox.attest` event. */
  attest(tenantId: string, sandboxId: string): { handle: SandboxHandle; sealed: Sealed; digest: string } {
    const handle = this.get(tenantId, sandboxId);
    if (!handle) throw new UnknownSandboxError(this.fullId(tenantId, sandboxId));
    const payload = canonicalJson({
      id: handle.id,
      tenantId: handle.tenantId,
      kind: handle.kind,
      limits: handle.limits,
      effectiveLimits: effectiveLimits(handle.limits),
      pid: process.pid,
      uptimeMs: Date.now() - handle.createdAt,
      attestedAt: Date.now(),
    });
    const { sealed, digest } = this.append('sandbox.attest', handle.id, tenantId, handle.kind, handle.limits, payload);
    return { handle, sealed, digest };
  }

  /**
   * Tear down: drop the handle, record a sealed `sandbox.destroy` event.
   * Refuses unknown ids; idempotent on already-destroyed ones (the exit sweep
   * and an explicit destroy must not race into a throw). The current sandbox
   * is ephemeral per invocation (`docker run --rm`, tmpdirs removed in
   * `finally`), so there is no resident container to kill — the event IS the
   * teardown evidence.
   */
  destroy(tenantId: string, sandboxId: string): void {
    const id = this.fullId(tenantId, sandboxId);
    const handle = this.created.get(id);
    if (!handle) throw new UnknownSandboxError(id);
    if (!this.active.has(id)) return;
    this.assertTenant(handle, tenantId);
    this.active.delete(id);
    const now = Date.now();
    const payload = canonicalJson({
      id,
      tenantId,
      kind: handle.kind,
      limits: handle.limits,
      effectiveLimits: effectiveLimits(handle.limits),
      pid: process.pid,
      durationMs: now - handle.createdAt,
      destroyedAt: now,
    });
    this.append('sandbox.destroy', id, tenantId, handle.kind, handle.limits, payload);
  }

  /**
   * Sweep every active sandbox on process exit (`beforeExit` + SIGINT/SIGTERM).
   * Opt-in: installs process-level handlers, so tests drive `sweepExit()`
   * directly instead. Individual destroy failures are swallowed — one broken
   * teardown must not strand the others.
   */
  installExitSweep(): void {
    if (this.exitSweepInstalled) return;
    this.exitSweepInstalled = true;
    process.on('beforeExit', () => this.sweepExit());
    for (const signal of ['SIGINT', 'SIGTERM'] as const) {
      process.on(signal, () => {
        this.sweepExit();
        process.exit(0);
      });
    }
  }

  /** Destroy every active sandbox, recording destroy events. Returns swept ids. */
  sweepExit(): readonly string[] {
    const swept: string[] = [];
    for (const handle of [...this.active.values()]) {
      try {
        this.destroy(handle.tenantId, handle.name);
        swept.push(handle.id);
      } catch {
        // ponytail: swallow per-sandbox sweep failures — evidence for the rest
        // of the fleet outweighs a clean exit code on one broken teardown.
      }
    }
    return swept;
  }

  private assertTenant(handle: SandboxHandle, tenantId: string): void {
    const resource = this.deps.registry.get(handle.id);
    const boundTenant = resource?.tenantId ?? handle.tenantId;
    if (boundTenant !== tenantId) {
      throw new Error(`sandbox ${handle.id} belongs to tenant ${boundTenant}`);
    }
  }

  private fullId(tenantId: string, sandboxId: string): string {
    return `sandbox:${tenantId}:${sandboxId}`;
  }

  /**
   * One sealed lifecycle event. The plaintext metadata carries only the kind
   * and the limit-config digest; the payload (pid, limits, timestamps) is
   * sealed under the tenant's 'public' key (Claim 13 posture).
   */
  private append(
    action: 'sandbox.create' | 'sandbox.destroy' | 'sandbox.attest',
    id: string,
    tenantId: string,
    kind: string,
    limits: SandboxLimits,
    payload: string,
  ): { sealed: Sealed; digest: string } {
    const digest = createHash('sha256').update(canonicalJson({ limits, kind })).digest('hex');
    const sealed = sealFor(tenantId, payload, 'public');
    this.deps.eventLog.append({
      tenantId,
      principal: this.deps.actorId,
      actor: this.deps.actorId,
      actorKind: this.deps.actorKind,
      action,
      resourceId: id,
      decision: 'allow',
      result: 'success',
      metadata: {
        phase: 'sandbox',
        kind,
        limitsDigest: digest,
        sealed,
      },
    });
    return { sealed, digest };
  }
}
