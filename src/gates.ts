/**
 * Data-plane gates: network egress and secrets.
 *
 * Both are ordinary authorization checks against synthetic resources. Neither
 * gate holds credentials or opens sockets in the MVP — the point is that the
 * *decision* lives in the PDP, so when a real proxy or a real secret store is
 * wired in later, the policy surface does not change.
 */

import type { Approval } from './policy.ts';
import type { AuthorizationService, AuthorizeInput } from './pdp.ts';
import { type EventStore } from './events.ts';
import { type AuthorizationDecision, type Principal } from './domain.ts';
import { type ResourceRegistry, defineResource } from './registry.ts';

/**
 * Both data-plane gates ask the PDP and then record the answer. The event is a
 * security record, so it lives here once: a field added to one copy and not the
 * other would be a silent audit gap (ticket 14). The gate supplies only the
 * metadata that differs; `reason` is read from the decision.
 */
function authorizeAndRecord(
  authorization: AuthorizationService,
  eventLog: EventStore,
  input: AuthorizeInput,
  metadata: (decision: AuthorizationDecision) => Readonly<Record<string, unknown>>,
): AuthorizationDecision {
  const decision = authorization.authorize(input);
  eventLog.append({
    tenantId: input.principal.tenantId,
    principal: input.principal.id,
    actor: input.principal.id,
    actorKind: input.principal.kind,
    action: input.action,
    resourceId: input.resourceId,
    decision: decision.decision,
    denyReason: decision.denyReason,
    result: decision.decision === 'deny' ? 'denied' : 'success',
    metadata: metadata(decision),
  });
  return decision;
}

export interface NetworkRequest {
  readonly principal: Principal;
  readonly host: string;
  readonly port?: number;
  readonly approvals?: readonly Approval[];
}

export interface NetworkResult {
  readonly allowed: boolean;
  readonly host: string;
  readonly reason: string;
}

/**
 * Egress control. MVP enforces the decision only — no socket is opened, so a
 * bug here fails closed by having nothing to leak through (ADR-009).
 */
export class NetworkGateway {
  private readonly registry: ResourceRegistry;
  private readonly authorization: AuthorizationService;
  private readonly eventLog: EventStore;

  constructor(registry: ResourceRegistry, authorization: AuthorizationService, eventLog: EventStore) {
    this.registry = registry;
    this.authorization = authorization;
    this.eventLog = eventLog;
  }

  request(req: NetworkRequest): NetworkResult {
    const host = normalizeHost(req.host);
    const resourceId = `net:${host}`;
    if (!this.registry.get(resourceId)) {
      this.registry.add(
        defineResource({
          id: resourceId,
          type: 'network-destination',
          tenantId: req.principal.tenantId,
          classification: 'restricted',
          attributes: { host },
        }),
      );
    }

    const decision = authorizeAndRecord(
      this.authorization,
      this.eventLog,
      {
        principal: req.principal,
        action: 'network.egress',
        resourceId,
        networkHost: host,
        approvals: req.approvals,
        params: req.port === undefined ? {} : { port: req.port },
      },
      (d) => ({ phase: 'network-gateway', host, port: req.port ?? null, reason: d.reason }),
    );

    return { allowed: decision.decision === 'allow', host, reason: decision.reason };
  }
}

function normalizeHost(host: string): string {
  return host.trim().toLowerCase().replace(/\.$/, '');
}

export interface SecretRecord {
  readonly id: string;
  readonly tenantId: string;
  readonly value: string;
  readonly label: string;
}

export interface SecretResult {
  readonly allowed: boolean;
  readonly value?: string;
  readonly reason: string;
}

/**
 * Secret broker. Values are returned only after an explicit `secret.use`
 * authorization against a capability; baseline policy grants none, so the
 * default answer is denial (invariant 11).
 */
export class SecretBroker {
  private readonly secrets = new Map<string, SecretRecord>();
  private readonly registry: ResourceRegistry;
  private readonly authorization: AuthorizationService;
  private readonly eventLog: EventStore;

  constructor(registry: ResourceRegistry, authorization: AuthorizationService, eventLog: EventStore) {
    this.registry = registry;
    this.authorization = authorization;
    this.eventLog = eventLog;
  }

  register(secret: SecretRecord): void {
    this.secrets.set(secret.id, secret);
    this.registry.add(
      defineResource({
        id: secret.id,
        type: 'secret',
        tenantId: secret.tenantId,
        classification: 'restricted',
        attributes: { label: secret.label },
      }),
    );
  }

  request(req: { principal: Principal; secretId: string; approvals?: readonly Approval[] }): SecretResult {
    const secret = this.secrets.get(req.secretId);
    if (!secret || secret.tenantId !== req.principal.tenantId) {
      return { allowed: false, reason: 'unknown secret' };
    }

    const decision = authorizeAndRecord(
      this.authorization,
      this.eventLog,
      {
        principal: req.principal,
        action: 'secret.use',
        resourceId: secret.id,
        approvals: req.approvals,
      },
      () => ({ phase: 'secret-broker', label: secret.label }),
    );

    return decision.decision === 'allow'
      ? { allowed: true, value: secret.value, reason: decision.reason }
      : { allowed: false, reason: decision.reason };
  }
}
