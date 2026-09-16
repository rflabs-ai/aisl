/**
 * Data-plane gates: network egress and secrets.
 *
 * Both are ordinary authorization checks against synthetic resources. Neither
 * gate holds credentials or opens sockets in the MVP — the point is that the
 * *decision* lives in the PDP, so when a real proxy or a real secret store is
 * wired in later, the policy surface does not change.
 */

import type { Approval } from './policy.ts';
import type { AuthorizationService } from './pdp.ts';
import { type EventLog } from './events.ts';
import { type Principal } from './domain.ts';
import { type ResourceRegistry, defineResource } from './registry.ts';

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
  private readonly eventLog: EventLog;

  constructor(registry: ResourceRegistry, authorization: AuthorizationService, eventLog: EventLog) {
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

    const decision = this.authorization.authorize({
      principal: req.principal,
      action: 'network.egress',
      resourceId,
      networkHost: host,
      approvals: req.approvals,
      params: req.port === undefined ? {} : { port: req.port },
    });

    this.eventLog.append({
      tenantId: req.principal.tenantId,
      principal: req.principal.id,
      actor: req.principal.id,
      actorKind: req.principal.kind,
      action: 'network.egress',
      resourceId,
      decision: decision.decision,
      denyReason: decision.denyReason,
      result: decision.decision === 'deny' ? 'denied' : 'success',
      metadata: { phase: 'network-gateway', host, port: req.port ?? null, reason: decision.reason },
    });

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
  private readonly eventLog: EventLog;

  constructor(registry: ResourceRegistry, authorization: AuthorizationService, eventLog: EventLog) {
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

    const decision = this.authorization.authorize({
      principal: req.principal,
      action: 'secret.use',
      resourceId: secret.id,
      approvals: req.approvals,
    });

    this.eventLog.append({
      tenantId: req.principal.tenantId,
      principal: req.principal.id,
      actor: req.principal.id,
      actorKind: req.principal.kind,
      action: 'secret.use',
      resourceId: secret.id,
      decision: decision.decision,
      denyReason: decision.denyReason,
      result: decision.decision === 'deny' ? 'denied' : 'success',
      metadata: { phase: 'secret-broker', label: secret.label },
    });

    return decision.decision === 'allow'
      ? { allowed: true, value: secret.value, reason: decision.reason }
      : { allowed: false, reason: decision.reason };
  }
}
