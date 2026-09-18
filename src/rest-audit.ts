/**
 * rest-audit: REST audit-query + task-execution routes (ADR-019 endpoint
 * contract). GET /v1/audit translates a whitelisted query-string into
 * AuditFilters and calls `AuditQueryService.query()` UNCHANGED — the service
 * owns every rule (capability, policy, filter bounds, evidence parity).
 * POST /v1/tasks executes through the ONE existing `AgentSession.run()` path
 * via the embedder-supplied `runTask`; absent → honestly 503.
 *
 * Tenant pass-through parity (ADR-019 "Tenant derivation", invariant 7): a
 * client-supplied `tenantId` query param is passed through to the service as-is
 * — never silently rewritten to the principal's tenant. The in-process path
 * denies cross-tenant with `tenant-mismatch` AND appends the deny event; the
 * REST surface must produce exactly the events the in-process path produces.
 */

import type { Principal } from './domain.ts';
import type { AuditFilters } from './events.ts';
import { AuditFilterError, type AuditQueryService } from './audit-query.ts';
import type { SessionTrace } from './runtime.ts';
import { RestRejection, optStr, str, type RestApi, type RestResponse } from './rest-api.ts';

export type TaskRunner = (principal: Principal, task: string) => Promise<SessionTrace>;

export interface AuditRouteDeps {
  readonly audit: AuditQueryService;
  /** Execution surface: MUST be the one existing AgentSession.run() path — the embedder wires it. Absent → the tasks endpoint is honestly unavailable. */
  readonly runTask?: TaskRunner;
}

function intParam(value: string | undefined): number | undefined {
  if (value === undefined || value === '') return undefined;
  const n = Number(value);
  if (Number.isNaN(n) || !Number.isInteger(n)) {
    throw new RestRejection(400, 'invalid-filter');
  }
  return n;
}

function isPlainRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}

export function registerAuditRoutes(api: RestApi, deps: AuditRouteDeps): void {
  api.addRoute('GET', '/v1/audit', (ctx): RestResponse => {
    const fromSeq = intParam(ctx.query.fromSeq);
    const toSeq = intParam(ctx.query.toSeq);
    const fromTime = intParam(ctx.query.fromTime);
    const toTime = intParam(ctx.query.toTime);
    const limit = intParam(ctx.query.limit);
    const offset = intParam(ctx.query.offset);
    const decisionRaw = ctx.query.decision;
    if (decisionRaw !== undefined && decisionRaw !== '' && decisionRaw !== 'allow' && decisionRaw !== 'deny') {
      throw new RestRejection(400, 'invalid-query');
    }
    const actor = optStr(ctx.query.actor, 'actor');
    const action = optStr(ctx.query.action, 'action');
    const resourceId = optStr(ctx.query.resourceId, 'resourceId');

    const filters: AuditFilters = {
      tenantId: ctx.query.tenantId ?? ctx.principal.tenantId,
      ...(fromSeq !== undefined ? { fromSeq } : {}),
      ...(toSeq !== undefined ? { toSeq } : {}),
      ...(fromTime !== undefined ? { fromTime } : {}),
      ...(toTime !== undefined ? { toTime } : {}),
      ...(actor !== undefined ? { actor } : {}),
      ...(action !== undefined ? { action } : {}),
      ...(decisionRaw !== undefined && decisionRaw !== '' ? { decision: decisionRaw as 'allow' | 'deny' } : {}),
      ...(resourceId !== undefined ? { resourceId } : {}),
      ...(limit !== undefined ? { limit } : {}),
      ...(offset !== undefined ? { offset } : {}),
    };

    let result;
    try {
      result = deps.audit.query(ctx.principal, filters);
    } catch (error) {
      if (error instanceof AuditFilterError) throw new RestRejection(400, 'invalid-filter');
      throw error;
    }
    if (result.decision.decision !== 'allow') {
      return {
        status: 403,
        body: { denyReason: result.decision.denyReason ?? 'no-capability', reason: result.decision.reason },
      };
    }
    return { status: 200, body: { events: [...result.events] } };
  });

  api.addRoute('POST', '/v1/tasks', async (ctx): Promise<RestResponse> => {
    if (deps.runTask === undefined) throw new RestRejection(503, 'tasks-unconfigured');
    if (!isPlainRecord(ctx.body)) {
      throw new RestRejection(400, 'invalid-body', 'tasks body must be a JSON object');
    }
    const task = str(ctx.body.task, 'task');
    const trace = await deps.runTask(ctx.principal, task);
    return {
      status: 200,
      body: {
        sessionId: trace.sessionId,
        principal: trace.principal,
        agentId: trace.agentId,
        modelId: trace.modelId,
        modelText: trace.modelText,
        startedAt: trace.startedAt,
        endedAt: trace.endedAt,
        steps: trace.steps.map((s) => ({
          action: s.request.action,
          resourceId: s.request.resourceId,
          decision: s.decision.decision,
          ...(s.decision.denyReason !== undefined ? { denyReason: s.decision.denyReason } : {}),
          executed: s.executed,
        })),
        ...(trace.guarded !== undefined ? { guard: { status: trace.guarded.status, flags: trace.guarded.flags } } : {}),
      },
    };
  });
}
