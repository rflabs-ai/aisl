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
  type Classification,
  type Principal,
  type ResourceType,
  canonicalJson,
  classificationRank,
} from './domain.ts';
import { sealFor } from './seal.ts';
import { type EventStore } from './events.ts';
import { type Approval } from './policy.ts';
import { type AuthorizationService } from './pdp.ts';
import { type ResourceRegistry, type IngestedData, detectInjectionSignals } from './registry.ts';
import { type ModelPort } from './model.ts';
import { type Check, type Verification, runVerifications } from './verification.ts';
import { type GuardedResponse, type ResponseGuard, GroundedResponseGuard } from './guard.ts';
import { type CapabilityRequestService } from './capability-request.ts';
import { denyReasonCounts } from './telemetry.ts';
import { type TelemetryPort } from './telemetry.ts';
import {
  CLEAN_TAINT,
  UNKNOWN_TAINT,
  combine,
  taintFor,
  taintMetadata,
  type TaintLabel,
} from './taint.ts';
import { assertDeclaration, validateParams, ToolProtocolError, type ToolDeclaration } from './tool-protocol.ts';

export interface ExecutionContext {
  readonly sessionId: string;
  readonly capabilityId: string;
  readonly resourceId: string;
  readonly resourceType: ResourceType;
  /** The target's registry label, so a tool can declare accurate provenance. */
  readonly resourceClassification: Classification;
  readonly action: Action;
  readonly params: Readonly<Record<string, unknown>>;
  readonly content: string | undefined;
  readonly now: number;
}

/**
 * Per-invocation limits for a tool (H5, ADR-038). In-process code cannot be
 * preempted, so the duration limit is *detected*, not enforced - the container
 * sandbox owns real preemption (ADR-003, Stage 3). The byte limits are enforced
 * before the tool runs (params) and after it returns (output).
 */
export interface ToolQuota {
  readonly maxParamBytes: number;
  readonly maxOutputBytes: number;
  readonly maxDurationMs: number;
}

export const DEFAULT_TOOL_QUOTA: ToolQuota = {
  maxParamBytes: 65_536,
  maxOutputBytes: 1_048_576,
  maxDurationMs: 30_000,
};

/**
 * Params keys that name authority. A tool acting on them would be taking scope
 * from the request instead of from the decision (H5: scope expansion at
 * runtime), so their presence is refused rather than ignored.
 */
const AUTHORITY_PARAM_KEYS = ['resourceId', 'tenantId', 'capabilityId', 'principal', 'approvals'] as const;

export interface ToolResult {
  readonly output?: unknown;
  readonly changed?: boolean;
  /**
   * Provenance of `output` (H4). Declaring can only raise the label — the
   * runtime combines it with what the session has already seen and with the
   * target resource, and never substitutes it. Omitted means "same as the
   * resource I was given", which is wrong for a tool that fetched something
   * else; declaring is required at H6's protocol boundary.
   */
  readonly taint?: TaintLabel;
}

export interface Tool {
  readonly name: string;
  /** H6 (ADR-039): what the tool is for, which actions it serves, its params. */
  readonly declaration?: ToolDeclaration;
  invoke(ctx: ExecutionContext): ToolResult;
}

export class ToolRegistry {
  private readonly tools = new Map<string, Tool>();

  /** A declaration is validated on registration — a bad schema never reaches a call. */
  register(tool: Tool): void {
    if (tool.declaration !== undefined) {
      assertDeclaration(tool.declaration);
      if (tool.declaration.name !== tool.name) {
        throw new ToolProtocolError(tool.name, [`declaration names '${tool.declaration.name}'`]);
      }
    }
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

/**
 * Highest classification visible to this session: every capability ceiling, every
 * registry resource the session holds content for, and every resource the model
 * requested. Unknown ids are ignored; nothing visible defaults to `public`.
 * Read-only — never mutates the registry.
 */
export function deriveClassification(input: {
  readonly capabilities: readonly { readonly maxClassification: Classification }[];
  readonly content?: ReadonlyMap<string, string>;
  readonly registry: ResourceRegistry;
  readonly requestedResourceIds: readonly string[];
}): Classification {
  let best: Classification = 'public';
  const consider = (label: Classification): void => {
    if (classificationRank(label) > classificationRank(best)) best = label;
  };
  for (const cap of input.capabilities) consider(cap.maxClassification);
  for (const id of input.content?.keys() ?? []) {
    const resource = input.registry.get(id);
    if (resource) consider(resource.classification);
  }
  for (const id of input.requestedResourceIds) {
    const resource = input.registry.get(id);
    if (resource) consider(resource.classification);
  }
  return best;
}

/** A quota breach is evidence, not a log line: it rides the verification plane. */
function quotaVerification(request: ActionRequest, _bytes: number, detail: string, at: number): Verification {
  return {
    id: `tool-quota:${request.action}`,
    subject: request.resourceId,
    test: 'tool-quota',
    command: 'session',
    result: 'fail',
    evidence: detail,
    timestamp: at,
  };
}

export interface StepRecord {
  readonly request: ActionRequest;
  readonly decision: AuthorizationDecision;
  readonly executed: boolean;
  readonly output?: unknown;
  readonly error?: string;
  readonly verifications: readonly Verification[];
  /** What this step's inputs and outputs had seen (H4, ADR-036). */
  readonly taint: TaintLabel;
}

export interface SessionTrace {
  readonly sessionId: string;
  readonly principal: string;
  readonly agentId: string;
  readonly modelId: string;
  /** Raw model output, sealed into evidence via `guarded.originalSealed`; the user-facing text is `guarded.text` when present, otherwise this raw string. */
  readonly modelText: string;
  readonly steps: readonly StepRecord[];
  readonly injectionSignals: readonly { resourceId: string; signals: readonly string[] }[];
  readonly startedAt: number;
  readonly endedAt: number;
  /** Result of the output reliability guard. `undefined` only when guard is disabled (cfg.guard === null). */
  readonly guarded?: GuardedResponse;
}

export interface SessionConfig {
  readonly principal: Principal;
  readonly agentId: string;
  readonly model: ModelPort;
  readonly task: string;
  readonly registry: ResourceRegistry;
  readonly authorization: AuthorizationService;
  readonly eventLog: EventStore;
  readonly tools: ToolRegistry;
  readonly sandbox: Sandbox;
  readonly content?: ReadonlyMap<string, string>;
  readonly checks?: readonly Check[];
  readonly approvals?: readonly Approval[];
  /** H5 (ADR-038): per-invocation tool limits. */
  readonly quota?: ToolQuota;
  readonly now?: () => number;
  readonly sessionId?: string;
  /** Output reliability guard. `undefined` (default) = `new GroundedResponseGuard()`; `null` = guard disabled (tests only). */
  readonly guard?: ResponseGuard | null;
  /** Canary / secret values the guard must never let through to prose. Defaults to []. */
  readonly canaries?: readonly string[];
  readonly telemetry?: TelemetryPort;
  readonly capabilityRequestService?: CapabilityRequestService;
}

export class AgentSession {
  readonly sessionId: string;
  private readonly cfg: SessionConfig;
  private readonly clock: () => number;
  /** What this session has seen so far, across steps (H4, ADR-036). */
  private carried: TaintLabel = CLEAN_TAINT;

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

    // H4: the taint of acting on this target, before it does anything. An
    // unknown resource ranks at the ceiling (fail closed), matching `record()`.
    const resource = this.cfg.registry.get(request.resourceId);
    const targetTaint = resource === undefined
      ? UNKNOWN_TAINT
      : taintFor(resource.id, resource.classification, false);
    const inputTaint = combine(this.carried, targetTaint);

    if (decision.decision === 'deny' || !decision.capabilityId) {
      return { request, decision, executed: false, verifications: [], taint: inputTaint };
    }

    // H5: the request cannot carry authority in its params. A tool that reads
    // `ctx.params.resourceId` would be acting on a scope the decision never
    // granted, so the key is refused outright rather than silently ignored.
    const quota = this.cfg.quota ?? DEFAULT_TOOL_QUOTA;
    const smuggled = AUTHORITY_PARAM_KEYS.filter((key) => request.params !== undefined && key in request.params);
    if (smuggled.length > 0) {
      const error = `params carry authority keys: ${smuggled.join(', ')}`;
      this.record('error', request, decision, error, {}, undefined, undefined, inputTaint);
      return { request, decision, executed: false, error, verifications: [], taint: inputTaint };
    }
    const paramBytes = request.params === undefined ? 0 : Buffer.byteLength(canonicalJson(request.params), 'utf8');
    if (paramBytes > quota.maxParamBytes) {
      const error = `params exceed ${quota.maxParamBytes} bytes (${paramBytes})`;
      this.record('error', request, decision, error, {}, undefined, undefined, inputTaint);
      return { request, decision, executed: false, error, verifications: [], taint: inputTaint };
    }

    const tool = this.cfg.tools.get(request.action);
    if (!tool) {
      const error = `no tool registered for action '${request.action}'`;
      this.record('error', request, decision, error, {}, undefined, undefined, inputTaint);
      return { request, decision, executed: false, error, verifications: [], taint: inputTaint };
    }

    // H6: a declared tool accepts exactly its declared params. Undeclared keys
    // are refused, not ignored — ignoring leaves the tool free to read them.
    if (tool.declaration !== undefined) {
      const check = validateParams(tool.declaration, request.params);
      if (!check.ok) {
        const error = check.error ?? 'params rejected by the tool protocol';
        this.record('error', request, decision, error, {}, undefined, undefined, inputTaint);
        return { request, decision, executed: false, error, verifications: [], taint: inputTaint };
      }
    }

    const ctx: ExecutionContext = {
      sessionId: this.sessionId,
      capabilityId: decision.capabilityId,
      resourceId: request.resourceId,
      resourceType: resource?.type ?? 'system',
      resourceClassification: resource?.classification ?? 'x-unknown-resource',
      action: request.action,
      params: request.params ?? {},
      content: this.cfg.content?.get(request.resourceId),
      now: at,
    };

    let output: unknown;
    let toolResult: ToolResult | undefined;
    try {
      toolResult = this.cfg.sandbox.runTool(tool, ctx);
      output = toolResult.output;
    } catch (error) {
      const message = (error as Error).message;
      this.record('error', request, decision, message, {}, undefined, undefined, inputTaint);
      return { request, decision, executed: false, error: message, verifications: [], taint: inputTaint };
    }

    // H5: the tool already ran, so this is detection, not prevention - the
    // result is recorded as a failed verification rather than a silent success.
    const durationMs = this.clock() - at;
    const outputBytes =
      output === undefined
        ? 0
        : Buffer.byteLength(typeof output === 'string' ? output : canonicalJson(output), 'utf8');
    const quotaFindings: Verification[] = [];
    if (outputBytes > quota.maxOutputBytes) {
      quotaFindings.push(quotaVerification(request, outputBytes, `output ${outputBytes} bytes > ${quota.maxOutputBytes}`, at));
    }
    if (durationMs > quota.maxDurationMs) {
      quotaFindings.push(quotaVerification(request, outputBytes, `duration ${durationMs}ms > ${quota.maxDurationMs}ms`, at));
    }

    // H6 retires the H4 marker: provenance is mandatory. An output with no
    // declared taint is UNKNOWN_TAINT - untrusted, ranked at the ceiling - so a
    // tool cannot under-state where its data came from by staying silent. A
    // tool that returns the resource it was given declares exactly that.
    const outputTaint =
      output !== undefined
        ? combine(inputTaint, toolResult.taint ?? UNKNOWN_TAINT)
        : combine(inputTaint, targetTaint);
    const stepTaint = combine(outputTaint, targetTaint);
    // Carried across steps: what this session has seen stays seen, even after
    // the capability that justified seeing it has been consumed or revoked.
    this.carried = combine(this.carried, stepTaint);

    // M11 propagation: a mutating write lifts the target's label to the max of
    // everything the session can see. Clearance ceilings are not data labels,
    // so derivation uses data sources only. Labels only raise, never lower.
    // H4 folds the taint label in: the coarse floor stays, taint can only add.
    let derived: Classification | undefined;
    if (toolResult.changed === true && resource) {
      const coarse = deriveClassification({
        capabilities: [],
        content: this.cfg.content,
        registry: this.cfg.registry,
        requestedResourceIds: [request.resourceId],
      });
      derived =
        classificationRank(stepTaint.classification) > classificationRank(coarse)
          ? stepTaint.classification
          : coarse;
      this.cfg.registry.raiseClassification(request.resourceId, derived);
    }

    const verifications = [
      ...quotaFindings,
      ...runVerifications(
        request.resourceId,
        this.cfg.checks ?? [],
        { resourceId: request.resourceId, action: request.action, params: ctx.params, output },
        at,
      ),
    ];

    const failed = verifications.filter((v) => v.result !== 'pass');
    this.record(
      failed.length > 0 ? 'error' : 'success',
      request,
      decision,
      undefined,
      { verifications },
      output,
      derived,
      stepTaint,
    );

    this.cfg.authorization.consume(decision.capabilityId);

    return { request, decision, executed: true, output, verifications, taint: stepTaint };
  }

  /** One turn: give the model the task and untrusted context, then enforce its requests. */
  async run(data: readonly IngestedData[], prompt = this.cfg.task): Promise<SessionTrace> {
    const startedAt = this.clock();
    this.cfg.telemetry?.emit('session.start', { sessionId: this.sessionId, principal: this.cfg.principal.id, agentId: this.cfg.agentId, model: this.cfg.model.id });
    this.cfg.eventLog.append({
      tenantId: this.cfg.principal.tenantId,
      principal: this.cfg.principal.id,
      actor: this.cfg.agentId,
      actorKind: this.cfg.principal.kind,
      action: 'session.start',
      result: 'success',
      metadata: { phase: 'session', sessionId: this.sessionId, model: this.cfg.model.id, task: this.cfg.task },
    });

    // H4: everything this turn read is now part of what the session has seen.
    // Untrusted by default — a document is attacker-influenceable, the operator's
    // task prompt is not.
    for (const d of data) {
      const source = this.cfg.registry.get(d.resourceId);
      this.carried = combine(
        this.carried,
        taintFor(d.resourceId, source?.classification ?? 'x-unknown-resource'),
      );
    }

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

    const modelOutput = await this.cfg.model.complete({
      prompt,
      context: data.map((d) => d.content),
      availableActions: this.cfg.tools.names() as Action[],
      contextResourceIds: data.map((d) => d.resourceId),
    });

    // ponytail: classification is the max over ALL principal capabilities + the whole
    // content map, so it is coarse — every session in a mixed-sensitivity world derives
    // a high label. Conservative by design (more withholding, never less). Upgrade path:
    // derive from the session's granted caps and actually-ingested resources only, if
    // coarseness bites. See Claim 23 limitations.
    const classification = deriveClassification({
      capabilities: this.cfg.authorization.capabilitiesFor(this.cfg.principal.id),
      content: this.cfg.content,
      registry: this.cfg.registry,
      requestedResourceIds: modelOutput.requests.map((r) => r.resourceId),
    });

    const guard = this.cfg.guard === null ? null : (this.cfg.guard ?? new GroundedResponseGuard());
    const first = guard === null ? null : guard.guard({
      sessionId: this.sessionId,
      modelText: modelOutput.text,
      context: this.cfg.content ?? new Map<string, string>(),
      steps: [],
      canaries: this.cfg.canaries ?? [],
      classification,
      principal: this.cfg.principal,
      capabilityRequestService: this.cfg.capabilityRequestService,
    });

    const steps = modelOutput.requests.map((r) => this.attempt(r));

    // Second pass runs post-execution so action-claim-mismatch sees the real steps.
    // No capabilityRequestService here: the first pass already queued any escalate
    // request, and re-submitting would double-queue.
    const second = guard === null ? null : guard.guard({
      sessionId: this.sessionId,
      modelText: modelOutput.text,
      context: this.cfg.content ?? new Map<string, string>(),
      steps,
      canaries: this.cfg.canaries ?? [],
      classification,
      principal: this.cfg.principal,
    });

    const verdictKey = (g: GuardedResponse | null): string =>
      g === null ? 'none' : canonicalJson({ status: g.status, flags: g.flags });
    const firstKey = verdictKey(first);
    const verdictChanged = verdictKey(second) !== firstKey;
    // The post-execution pass is strictly better informed; today flags can only
    // shrink or change reason, and the extra event preserves the first verdict for
    // investigators.
    const guarded = verdictChanged ? second : first;
    const endedAt = this.clock();

    if (first !== null) this.appendGuardEvent('guard', first);
    if (verdictChanged && second !== null) this.appendGuardEvent('guard-second-pass', second);

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

    this.cfg.telemetry?.emit('session.end', {
      sessionId: this.sessionId, principal: this.cfg.principal.id, agentId: this.cfg.agentId, model: this.cfg.model.id,
      durationMs: endedAt - startedAt, requests: steps.length,
      allowed: steps.filter((s) => s.decision.decision === 'allow').length,
      denied: steps.filter((s) => s.decision.decision === 'deny').length,
    });
    const denyCounts = denyReasonCounts(steps.map((s) => s.decision));
    if (Object.keys(denyCounts).length > 0) {
      this.cfg.telemetry?.emit('pdp.denyReasons', { sessionId: this.sessionId, counts: denyCounts });
    }

    return {
      sessionId: this.sessionId,
      principal: this.cfg.principal.id,
      agentId: this.cfg.agentId,
      modelId: this.cfg.model.id,
      modelText: guarded !== null ? guarded.text : modelOutput.text,
      steps,
      injectionSignals,
      startedAt,
      endedAt,
      ...(guarded !== null ? { guarded } : {}),
    };
  }

  private appendGuardEvent(phase: 'guard' | 'guard-second-pass', guarded: GuardedResponse): void {
    const outputDigest = guarded.text === null
      ? null
      : createHash('sha256').update(guarded.text).digest('hex');
    this.cfg.eventLog.append({
      tenantId: this.cfg.principal.tenantId,
      principal: this.cfg.principal.id,
      actor: this.cfg.agentId,
      actorKind: this.cfg.principal.kind,
      action: 'session.guard',
      result: guarded.status === 'withheld' ? 'error' : 'success',
      decision: 'allow',
      metadata: {
        phase,
        sessionId: this.sessionId,
        guardId: guarded.guardId,
        status: guarded.status,
        flags: guarded.flags,
        citations: guarded.citations,
        outputDigest,
        sealed: guarded.originalSealed,
        ladderRung: guarded.ladderRung,
        ...(guarded.requestId !== undefined ? { requestId: guarded.requestId } : {}),
      },
    });
  }

  private record(
    result: 'success' | 'error',
    request: ActionRequest,
    decision: AuthorizationDecision,
    error?: string,
    extra: Record<string, unknown> = {},
    output?: unknown,
    derivedClassification?: Classification,
    taint: TaintLabel = CLEAN_TAINT,
  ): void {
    const rendered = output === undefined ? null : typeof output === 'string' ? output : canonicalJson(output);
    const digest = rendered === null ? null : createHash('sha256').update(rendered).digest('hex');
    const classification =
      derivedClassification ?? this.cfg.registry.get(request.resourceId)?.classification ?? 'x-unknown-resource';
    const sealed = rendered === null ? null : sealFor(this.cfg.principal.tenantId, rendered, classification);

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
        // H4: ids and labels only — never content.
        taint: taintMetadata(taint),
        ...(derivedClassification !== undefined ? { derivedClassification } : {}),
        ...extra,
      },
    });
  }
}
