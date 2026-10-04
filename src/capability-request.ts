/**
 * Capability request flow.
 *
 * An agent cannot mint its own authority (invariant 2), but it can request
 * capabilities it doesn't have. A human reviewer approves, and the approval
 * produces a narrow, single-use capability scoped to exactly what was
 * requested (or less — the reviewer can narrow scope).
 *
 * M4 invariant: capability requests are evidence — they go in the event log.
 */

import { randomUUID } from 'node:crypto';
import { type Action, type Classification, type Principal } from './domain.ts';
import { type Capability, type IssueRequest } from './capability.ts';
import { type EventStore } from './events.ts';
import { type AuthorizationService } from './pdp.ts';
import { type Approval } from './policy.ts';

export type CapabilityRequestStatus = 'pending' | 'approved' | 'denied' | 'expired';

export interface CapabilityRequest {
  readonly id: string;
  readonly sessionId: string;
  readonly principalId: string;
  readonly tenantId: string;
  readonly requestedResources: readonly string[];
  readonly requestedActions: readonly Action[];
  readonly maxClassification: Classification;
  readonly justification: string;
  readonly createdAt: number;
  readonly status: CapabilityRequestStatus;
  readonly reviewedBy?: string;
  readonly reviewedAt?: number;
  readonly capabilityId?: string;
}

/**
 * Validate that a CapabilityRequest has no authority fields.
 * A capability request is intent, not authority — the same boundary as
 * ActionRequest vs Capability.
 */
const AUTHORITY_FIELDS = ['issuer', 'signature', 'authority', 'grant', 'secret', 'admin', 'mfa'];

export function requestHasNoAuthority(request: CapabilityRequest): boolean {
  const keys = Object.keys(request);
  return !keys.some((k) => AUTHORITY_FIELDS.some((af) => k.toLowerCase().includes(af)));
}

export class CapabilityRequestService {
  private readonly requests = new Map<string, CapabilityRequest>();
  /**
   * Capabilities minted by approval, keyed by request id. Kept so a requester
   * can read back the granted scope over REST (M17 `GET /v1/capability-requests/:id`)
   * instead of the request vanishing from the pending-only list. In-memory,
   * same lifetime as `requests` — the durable decision surface stays this service.
   */
  private readonly minted = new Map<string, Capability>();
  private readonly eventLog: EventStore;
  private readonly authorization: AuthorizationService;
  private readonly root: Principal;
  private readonly clock: () => number;

  constructor(eventLog: EventStore, authorization: AuthorizationService, root: Principal, clock: () => number = Date.now) {
    this.eventLog = eventLog;
    this.authorization = authorization;
    this.root = root;
    this.clock = clock;
  }

  /**
   * Submit a capability request. The requesting principal cannot be the
   * reviewer — only a human principal can approve.
   */
  submit(
    principal: Principal,
    sessionId: string,
    resources: readonly string[],
    actions: readonly Action[],
    maxClassification: Classification,
    justification: string,
  ): CapabilityRequest {
    const now = this.clock();
    const request: CapabilityRequest = {
      id: randomUUID(),
      sessionId,
      principalId: principal.id,
      tenantId: principal.tenantId,
      requestedResources: [...resources],
      requestedActions: [...actions],
      maxClassification,
      justification,
      createdAt: now,
      status: 'pending',
    };
    this.requests.set(request.id, request);

    this.eventLog.append({
      tenantId: principal.tenantId,
      principal: principal.id,
      actor: principal.id,
      actorKind: principal.kind,
      action: 'capability.request',
      resourceId: resources.join(','),
      decision: 'allow',
      result: 'success',
      metadata: {
        phase: 'capability-request',
        requestId: request.id,
        sessionId,
        requestedResources: resources,
        requestedActions: actions,
        maxClassification,
        justification,
      },
    });

    return request;
  }

  /**
   * Approve a capability request. The reviewer must be a different principal
   * (no self-approval), must be a user (human), and must have a valid session.
   * The approval mints a capability scoped to exactly the requested resources
   * and actions (or less if the reviewer narrows scope).
   */
  approve(
    requestId: string,
    reviewer: Principal,
    scope?: {
      resources?: readonly string[];
      actions?: readonly Action[];
      maxClassification?: Classification;
    },
  ): { request: CapabilityRequest; capability: Capability } {
    const request = this.requests.get(requestId);
    if (!request) throw new Error(`request ${requestId} not found`);
    if (request.status !== 'pending') throw new Error(`request ${requestId} is not pending`);

    // Only a user (human) can approve. Agents cannot approve their own requests.
    if (reviewer.kind !== 'user') {
      throw new Error(`principal of kind '${reviewer.kind}' may not approve capability requests`);
    }

    // No self-approval: the requester cannot also be the reviewer.
    if (reviewer.id === request.principalId) {
      throw new Error('a principal cannot approve its own capability request');
    }

    // H8 (ADR-030): tenancy is enforced at the decision surface, not only at
    // the REST boundary. A reviewer from another tenant can never decide this
    // request or be recorded on it.
    this.requireSameTenant(request, reviewer);

    const now = this.clock();
    const resources = scope?.resources ?? request.requestedResources;
    const actions = scope?.actions ?? request.requestedActions;
    const classification = scope?.maxClassification ?? request.maxClassification;

    // Issue the capability via the authorization root (reviewer is the approver, root is the issuer).
    // Only the root can issue capabilities without attenuation checks.
    const capability = this.authorization.issue(
      this.root,
      {
        subject: request.principalId,
        tenantId: request.tenantId,
        resourceIds: [...resources],
        actions: [...actions],
        maxClassification: classification,
        expiresAt: now + 3_600_000,
        singleUse: true,
        provenance: { source: 'human-approval', approvedBy: reviewer.id, sessionId: request.sessionId, taskId: request.id },
      },
    );

    const approved: CapabilityRequest = {
      ...request,
      status: 'approved',
      reviewedBy: reviewer.id,
      reviewedAt: now,
      capabilityId: capability.id,
    };
    this.requests.set(requestId, approved);
    this.minted.set(requestId, capability);

    this.eventLog.append({
      tenantId: request.tenantId,
      principal: reviewer.id,
      actor: reviewer.id,
      actorKind: reviewer.kind,
      action: 'capability.approve',
      resourceId: resources.join(','),
      decision: 'allow',
      capabilityId: capability.id,
      result: 'success',
      metadata: {
        phase: 'capability-approval',
        requestId,
        approvedBy: reviewer.id,
        capabilityId: capability.id,
        resources,
        actions,
        maxClassification: classification,
      },
    });

    return { request: approved, capability };
  }

  /**
   * H8 (ADR-030): a reviewer may only decide a request from their own tenant.
   * The REST boundary checks this too; the service is the decision surface and
   * must hold on its own (embedders call it directly; the guard's escalation
   * lane submits through it; no REST route calls `deny`).
   */
  private requireSameTenant(request: CapabilityRequest, reviewer: Principal): void {
    if (reviewer.tenantId !== request.tenantId) {
      throw new Error(
        `reviewer ${reviewer.id} belongs to tenant '${reviewer.tenantId}', not '${request.tenantId}': refusing cross-tenant review`,
      );
    }
  }

  /**
   * Deny a capability request. No capability is minted.
   */
  deny(requestId: string, reviewer: Principal): CapabilityRequest {
    const request = this.requests.get(requestId);
    if (!request) throw new Error(`request ${requestId} not found`);
    if (request.status !== 'pending') throw new Error(`request ${requestId} is not pending`);

    if (reviewer.kind !== 'user') {
      throw new Error(`principal of kind '${reviewer.kind}' may not deny capability requests`);
    }

    this.requireSameTenant(request, reviewer);

    const now = this.clock();
    const denied: CapabilityRequest = {
      ...request,
      status: 'denied',
      reviewedBy: reviewer.id,
      reviewedAt: now,
    };
    this.requests.set(requestId, denied);

    this.eventLog.append({
      tenantId: request.tenantId,
      principal: reviewer.id,
      actor: reviewer.id,
      actorKind: reviewer.kind,
      action: 'capability.deny',
      resourceId: request.requestedResources.join(','),
      decision: 'deny',
      denyReason: 'capability-request-denied',
      result: 'denied',
      metadata: {
        phase: 'capability-denial',
        requestId,
        deniedBy: reviewer.id,
      },
    });

    return denied;
  }

  /**
   * Expire all pending requests that have passed their creation time +
   * the configured timeout. Default timeout: 5 minutes.
   */
  expirePending(timeoutMs: number = 300_000): CapabilityRequest[] {
    const now = this.clock();
    const expired: CapabilityRequest[] = [];
    for (const [id, request] of this.requests) {
      if (request.status !== 'pending') continue;
      if (now - request.createdAt > timeoutMs) {
        const e: CapabilityRequest = { ...request, status: 'expired' };
        this.requests.set(id, e);
        expired.push(e);
      }
    }
    return expired;
  }

  get(requestId: string): CapabilityRequest | undefined {
    return this.requests.get(requestId);
  }

  /** The capability minted by approving this request, if it was approved. */
  capabilityFor(requestId: string): Capability | undefined {
    return this.minted.get(requestId);
  }

  all(): readonly CapabilityRequest[] {
    return [...this.requests.values()];
  }
}