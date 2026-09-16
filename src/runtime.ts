/**
 * Policy Enforcement Point: the agent session.
 *
 * Everything an agent does funnels through `attempt()`. The session never holds
 * a credential, never holds the AuthorizationService, and cannot mint authority.
 * Tools receive an `ExecutionContext` that deliberately has no issuance handle,
 * so a compromised tool cannot expand its own scope (invariant 4).
 */

import { createHash, randomUUID } from 'node:crypto';
import {
  type Action,
  type ActionRequest,
  type AuthorizationDecision,
  type Principal,
  type ResourceType,
  canonicalJson,
} from './domain.ts';
import { seal } from './seal.ts';
import { type EventLog } from './events.ts';
import { type Approval } from './policy.ts';
import { type AuthorizationService } from './pdp.ts';
import { type ResourceRegistry, type IngestedData, detectInjectionSignals } from './registry.ts';
import { type ModelPort } from './model.ts';
import { type Check, type Verification, runVerifications } from './verification.ts';

export interface ExecutionContext {
  readonly sessionId: string;
  readonly capabilityId: string;
  readonly resourceId: string;
  readonly resourceType: ResourceType;
  readonly action: Action;
  readonly params: Readonly<Record<string, unknown>>;
  readonly content: string | undefined;
  readonly now: number;
}

export interface ToolResult {
  readonly output?: unknown;
  readonly changed?: boolean;
}

export interface Tool {
  readonly name: string;
  invoke(ctx: ExecutionContext): ToolResult;
}

export class ToolRegistry {
  private readonly tools = new Map<string, Tool>();

  register(tool: Tool): void {
    this.tools.set(tool.name, tool);
  }

  get(name: string): Tool | undefined {
    return this.tools.get(name);
  }

  names(): readonly string[] {
    return [...this.tools.keys()];
  }
}

export interface Sandbox {
  readonly kind: string;
  run<T>(fn: () => T): T;
  runTool(tool: Tool, ctx: ExecutionContext): ToolResult;
}

/**
 * MVP executor. NOT a security boundary — it provides no isolation. It exists so
 * the enforcement seam is real and testable before a container/microVM backend
 * replaces it (ADR-003).
 */
export class LocalSandbox implements Sandbox {
  readonly kind = 'in-process/no-isolation';
  run<T>(fn: () => T): T {
    return fn();
  }
  runTool(tool: Tool, ctx: ExecutionContext): ToolResult {
    return tool.invoke(ctx);
  }
}

export interface StepRecord {
  readonly request: ActionRequest;
  readonly decision: AuthorizationDecision;
  readonly executed: boolean;
  readonly output?: unknown;
  readonly error?: string;
  readonly verifications: readonly Verification[];
}

export interface SessionTrace {
  readonly sessionId: string;
  readonly principal: string;
  readonly agentId: string;
  readonly modelId: string;
  readonly modelText: string;
  readonly steps: readonly StepRecord[];
  readonly injectionSignals: readonly { resourceId: string; signals: readonly string[] }[];
  readonly startedAt: number;
  readonly endedAt: number;
}

export interface SessionConfig {
  readonly principal: Principal;
  readonly agentId: string;
  readonly model: ModelPort;
  readonly task: string;
  readonly registry: ResourceRegistry;
  readonly authorization: AuthorizationService;
  readonly eventLog: EventLog;
  readonly tools: ToolRegistry;
  readonly sandbox: Sandbox;
  readonly content?: ReadonlyMap<string, string>;
  readonly checks?: readonly Check[];
  readonly approvals?: readonly Approval[];
  readonly now?: () => number;
  readonly sessionId?: string;
}

export class AgentSession {
  readonly sessionId: string;
  private readonly cfg: SessionConfig;
  private readonly clock: () => number;

  constructor(cfg: SessionConfig) {
    this.cfg = cfg;
    this.sessionId = cfg.sessionId ?? randomUUID();
    this.clock = cfg.now ?? Date.now;
  }

  get principal(): Principal {
    return this.cfg.principal;
  }

  /** Execute one requested action through the enforcement seam. */
  attempt(request: ActionRequest): StepRecord {
    const at = this.clock();
    const decision = this.cfg.authorization.authorize({
      principal: this.cfg.principal,
      action: request.action,
      resourceId: request.resourceId,
      params: request.params,
      approvals: this.cfg.approvals,
    });

    if (decision.decision === 'deny' || !decision.capabilityId) {
      return { request, decision, executed: false, verifications: [] };
    }

    const resource = this.cfg.registry.get(request.resourceId);
    const tool = this.cfg.tools.get(request.action);
    if (!tool) {
      const error = `no tool registered for action '${request.action}'`;
      this.record('error', request, decision, error);
      return { request, decision, executed: false, error, verifications: [] };
    }

    const ctx: ExecutionContext = {
      sessionId: this.sessionId,
      capabilityId: decision.capabilityId,
      resourceId: request.resourceId,
      resourceType: resource?.type ?? 'system',
      action: request.action,
      params: request.params ?? {},
      content: this.cfg.content?.get(request.resourceId),
      now: at,
    };

    let output: unknown;
    try {
      output = this.cfg.sandbox.runTool(tool, ctx).output;
    } catch (error) {
      const message = (error as Error).message;
      this.record('error', request, decision, message);
      return { request, decision, executed: false, error: message, verifications: [] };
    }

    const verifications = runVerifications(
      request.resourceId,
      this.cfg.checks ?? [],
      { resourceId: request.resourceId, action: request.action, params: ctx.params, output },
      at,
    );

    const failed = verifications.filter((v) => v.result !== 'pass');
    this.record(failed.length > 0 ? 'error' : 'success', request, decision, undefined, { verifications }, output);

    this.cfg.authorization.consume(decision.capabilityId);

    return { request, decision, executed: true, output, verifications };
  }

  /** One turn: give the model the task and untrusted context, then enforce its requests. */
  run(data: readonly IngestedData[], prompt = this.cfg.task): SessionTrace {
    const startedAt = this.clock();
    this.cfg.eventLog.append({
      tenantId: this.cfg.principal.tenantId,
      principal: this.cfg.principal.id,
      actor: this.cfg.agentId,
      actorKind: this.cfg.principal.kind,
      action: 'session.start',
      result: 'success',
      metadata: { phase: 'session', sessionId: this.sessionId, model: this.cfg.model.id, task: this.cfg.task },
    });

    const injectionSignals = data.map((d) => ({
      resourceId: d.resourceId,
      signals: detectInjectionSignals(d.content),
    }));
    for (const s of injectionSignals) {
      if (s.signals.length > 0) {
        this.cfg.eventLog.append({
          tenantId: this.cfg.principal.tenantId,
          principal: this.cfg.principal.id,
          actor: this.cfg.agentId,
          actorKind: this.cfg.principal.kind,
          action: 'session.injection-signal',
          resourceId: s.resourceId,
          result: 'success',
          metadata: { phase: 'telemetry', signals: s.signals, note: 'detector is informational, not a control' },
        });
      }
    }

    const modelOutput = this.cfg.model.complete({
      prompt,
      context: data.map((d) => d.content),
      availableActions: this.cfg.tools.names() as Action[],
    });

    const steps = modelOutput.requests.map((r) => this.attempt(r));
    const endedAt = this.clock();

    this.cfg.eventLog.append({
      tenantId: this.cfg.principal.tenantId,
      principal: this.cfg.principal.id,
      actor: this.cfg.agentId,
      actorKind: this.cfg.principal.kind,
      action: 'session.end',
      result: 'success',
      metadata: {
        phase: 'session',
        sessionId: this.sessionId,
        requests: steps.length,
        allowed: steps.filter((s) => s.decision.decision === 'allow').length,
        denied: steps.filter((s) => s.decision.decision === 'deny').length,
      },
    });

    return {
      sessionId: this.sessionId,
      principal: this.cfg.principal.id,
      agentId: this.cfg.agentId,
      modelId: this.cfg.model.id,
      modelText: modelOutput.text,
      steps,
      injectionSignals,
      startedAt,
      endedAt,
    };
  }

  private record(
    result: 'success' | 'error',
    request: ActionRequest,
    decision: AuthorizationDecision,
    error?: string,
    extra: Record<string, unknown> = {},
    output?: unknown,
  ): void {
    const rendered = output === undefined ? null : typeof output === 'string' ? output : canonicalJson(output);
    const digest = rendered === null ? null : createHash('sha256').update(rendered).digest('hex');
    const classification = this.cfg.registry.get(request.resourceId)?.classification ?? 'x-unknown-resource';
    const sealed = rendered === null ? null : seal(rendered, classification);

    this.cfg.eventLog.append({
      tenantId: this.cfg.principal.tenantId,
      principal: this.cfg.principal.id,
      actor: this.cfg.agentId,
      actorKind: this.cfg.principal.kind,
      action: request.action,
      resourceId: request.resourceId,
      decision: decision.decision,
      policyId: decision.policyId,
      capabilityId: decision.capabilityId,
      result,
      metadata: {
        phase: 'execution',
        sessionId: this.sessionId,
        error: error ?? null,
        outputDigest: digest,
        sealed,
        ...extra,
      },
    });
  }
}
