/**
 * REST session + capability-request routes (ADR-019 endpoint contract): the
 * /v1/sessions lifecycle and the M4 /v1/capability-requests flow. Handlers are
 * whitelist translations over `SessionManager` and `CapabilityRequestService`
 * — no new authority path exists here; the mint is exactly what M4 mints and
 * every response is a freshly constructed projection (principal, auth/token
 * claims, and attestation internals never reach the wire).
 *
 * Ceilings (deliberate simplifications):
 * - ponytail: DELETE /v1/sessions/:id is owner-only (same principal id) and
 *   node-local: it does not publish through the H13 revocation channel —
 *   cross-node session revocation is `incident revoke-session` (ADR-026). A
 *   deployment/service layer widens to admin revocation when one exists.
 * - ponytail: approval MFA is enforced HERE at the HTTP boundary (the M4
 *   approve() path itself does not check MFA); in-process callers need the
 *   same guard if approvals ever arrive without a verified token.
 */

import { type Action, type Classification } from './domain.ts';
import { type Capability } from './capability.ts';
import { hasMfa } from './identity.ts';
import { type SessionManager } from './session-manager.ts';
import { CapabilityRequestService, type CapabilityRequest } from './capability-request.ts';
import type { PersistenceStore } from './persistence.ts';
import { RestRejection, optStr, str, strArray, type RestApi, type RestResponse } from './rest-api.ts';

export interface SessionRouteDeps {
  readonly sessions: SessionManager;
  readonly requests: CapabilityRequestService;
  /**
   * M15 (ADR-020): optional durable mirror over the migration-3
   * capability_requests table. Submit/approve/deny mirror to it; the
   * in-memory service stays the decision surface. Mirror failures
   * propagate (fail closed) — the caller sees an error instead of a
   * silently unpersisted request.
   */
  readonly requestsStore?: PersistenceStore;
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}

function projectRequest(request: CapabilityRequest): Record<string, unknown> {
  const reviewed =
    request.reviewedBy !== undefined
      ? { reviewedBy: request.reviewedBy, reviewedAt: request.reviewedAt }
      : {};
  const capability = request.capabilityId !== undefined ? { capabilityId: request.capabilityId } : {};
  return {
    id: request.id,
    sessionId: request.sessionId,
    principalId: request.principalId,
    tenantId: request.tenantId,
    requestedResources: request.requestedResources,
    requestedActions: request.requestedActions,
    maxClassification: request.maxClassification,
    justification: request.justification,
    createdAt: request.createdAt,
    status: request.status,
    ...reviewed,
    ...capability,
  };
}

function projectCapability(capability: Capability): Record<string, unknown> {
  return {
    id: capability.id,
    subject: capability.subject,
    tenantId: capability.tenantId,
    resourceIds: capability.resourceIds,
    actions: capability.actions,
    maxClassification: capability.maxClassification,
    expiresAt: capability.expiresAt,
    singleUse: capability.singleUse,
    provenance: capability.provenance,
  };
}

export function registerSessionRoutes(api: RestApi, deps: SessionRouteDeps): void {
  api.addRoute('POST', '/v1/sessions', (ctx): RestResponse => {
    if (!hasMfa(ctx.auth)) throw new RestRejection(403, 'approval-mfa-required');
    const session = deps.sessions.create(ctx.principal, ctx.auth);
    return {
      status: 201,
      body: {
        id: session.id,
        createdAt: session.createdAt,
        expiresAt: session.expiresAt,
        mfaVerified: session.mfaVerified,
      },
    };
  });

  api.addRoute('DELETE', '/v1/sessions/:id', (ctx): RestResponse => {
    const id = ctx.params.id ?? '';
    const session = deps.sessions.get(id);
    if (session === undefined) throw new RestRejection(404, 'not-found');
    if (session.principal.tenantId !== ctx.principal.tenantId) throw new RestRejection(403, 'tenant-mismatch');
    if (session.principal.id !== ctx.principal.id) throw new RestRejection(403, 'no-capability');
    deps.sessions.revoke(id);
    return { status: 200, body: { revoked: true } };
  });

  api.addRoute('POST', '/v1/capability-requests', async (ctx): Promise<RestResponse> => {
    if (!isRecord(ctx.body)) throw new RestRejection(400, 'invalid-body', 'body must be a JSON object');
    const maxClassification = str(ctx.body.maxClassification, 'maxClassification');
    const justification = optStr(ctx.body.justification, 'justification') ?? '';
    const request = deps.requests.submit(
      ctx.principal,
      str(ctx.body.sessionId, 'sessionId'),
      strArray(ctx.body.resources, 'resources'),
      strArray(ctx.body.actions, 'actions'),
      maxClassification,
      justification,
    );
    if (deps.requestsStore) {
      // Whitelisted projection into the durable mirror — nothing beyond these fields persists.
      await deps.requestsStore.createCapabilityRequest(
        ctx.principal.tenantId,
        request.id,
        request.principalId,
        {
          sessionId: request.sessionId,
          resources: [...request.requestedResources],
          actions: [...request.requestedActions],
          maxClassification: request.maxClassification,
          justification: request.justification,
        },
        new Date(request.createdAt + 300_000),
      );
    }
    return { status: 201, body: projectRequest(request) };
  });

  api.addRoute('GET', '/v1/capability-requests', (ctx): RestResponse => {
    const pending = deps.requests
      .all()
      .filter((request) => request.status === 'pending' && request.tenantId === ctx.principal.tenantId)
      .map(projectRequest);
    return { status: 200, body: { requests: pending } };
  });

  api.addRoute('GET', '/v1/capability-requests/:id', (ctx): RestResponse => {
    const id = ctx.params.id ?? '';
    const request = deps.requests.get(id);
    if (request === undefined) throw new RestRejection(404, 'not-found');
    if (request.tenantId !== ctx.principal.tenantId) throw new RestRejection(403, 'tenant-mismatch');
    const capability = deps.requests.capabilityFor(id);
    return {
      status: 200,
      body: {
        request: projectRequest(request),
        ...(capability !== undefined ? { capability: projectCapability(capability) } : {}),
      },
    };
  });

  api.addRoute('POST', '/v1/capability-requests/:id/approvals', async (ctx): Promise<RestResponse> => {
    if (!hasMfa(ctx.auth)) throw new RestRejection(403, 'approval-mfa-required');
    const id = ctx.params.id ?? '';
    const request = deps.requests.get(id);
    if (request === undefined) throw new RestRejection(404, 'not-found');
    if (request.tenantId !== ctx.principal.tenantId) throw new RestRejection(403, 'tenant-mismatch');
    if (!isRecord(ctx.body)) throw new RestRejection(400, 'invalid-body', 'body must be a JSON object');
    let scope: { resources?: readonly string[]; actions?: readonly Action[]; maxClassification?: Classification } | undefined;
    const rawScope = ctx.body.scope;
    if (rawScope !== undefined) {
      if (!isRecord(rawScope)) throw new RestRejection(400, 'invalid-body', 'scope must be an object');
      const parsed: { resources?: readonly string[]; actions?: readonly Action[]; maxClassification?: Classification } = {};
      if (rawScope.resources !== undefined) parsed.resources = strArray(rawScope.resources, 'scope.resources');
      if (rawScope.actions !== undefined) parsed.actions = strArray(rawScope.actions, 'scope.actions');
      if (rawScope.maxClassification !== undefined) {
        parsed.maxClassification = str(rawScope.maxClassification, 'scope.maxClassification');
      }
      scope = parsed;
    }
    // Persist BEFORE consuming the single-use capability: if persist fails,
    // the in-memory service is untouched and the capability is never minted.
    // A stale persisted row (persist succeeded, service threw) is acceptable —
    // no capability was consumed, so no permanent data loss (audit ticket 01).
    if (deps.requestsStore) {
      await deps.requestsStore.updateCapabilityRequestStatus(
        ctx.principal.tenantId,
        id,
        'approved',
        ctx.principal.id,
      );
    }
    let approved;
    try {
      approved = deps.requests.approve(id, ctx.principal, scope);
    } catch (error) {
      const message = error instanceof Error ? error.message : String(error);
      if (message.includes('not found')) throw new RestRejection(404, 'not-found');
      if (message.includes('not pending')) throw new RestRejection(409, 'not-pending');
      throw new RestRejection(403, 'capability-request-denied');
    }
    return {
      status: 201,
      body: { request: projectRequest(approved.request), capability: projectCapability(approved.capability) },
    };
  });
}
