/**
 * Policy Decision Point.
 *
 * Authorization = capability AND policy. Both must pass. Every call returns a
 * decision and appends an audit event — there is no path that decides silently.
 * Any internal error is converted into a deny (fail closed, invariant 12).
 */

import {
  type Capability,
  type IssueRequest,
  type IssuerAuthority,
  issueCapability,
  markUsed,
  verifyCapability,
} from './capability.ts';
import {
  type Action,
  type AuthorizationDecision,
  type DenyReason,
  type Principal,
  allow,
  deny,
  isAuthenticated,
} from './domain.ts';
import { type EventLog, type SecurityEvent } from './events.ts';
import { type Approval, type PolicyEngine } from './policy.ts';
import { type ResourceRegistry, UnknownResourceError, defineResource } from './registry.ts';
import { type Sealed, classificationFromKeyId, open } from './seal.ts';
import { hasMfa, type IdPHealth } from './identity.ts';

export interface AuthorizeInput {
  readonly principal: Principal;
  readonly action: Action;
  readonly resourceId: string;
  readonly params?: Readonly<Record<string, unknown>>;
  readonly networkHost?: string;
  readonly approvals?: readonly Approval[];
}

const REASON_PRIORITY: readonly DenyReason[] = [
  'capability-expired',
  'capability-consumed',
  'capability-signature-invalid',
  'capability-tenant-mismatch',
  'classification-ceiling',
  'capability-scope',
];

export class AuthorizationService {
  private readonly capabilities = new Map<string, Capability>();
  private readonly registry: ResourceRegistry;
  private readonly engine: PolicyEngine;
  private readonly eventLog: EventLog;
  private readonly now: () => number;
  private readonly idpHealth?: () => IdPHealth;

  constructor(
    registry: ResourceRegistry,
    engine: PolicyEngine,
    eventLog: EventLog,
    now: () => number = Date.now,
    idpHealth?: () => IdPHealth,
  ) {
    this.registry = registry;
    this.engine = engine;
    this.eventLog = eventLog;
    this.now = now;
    this.idpHealth = idpHealth;
  }

  issue(
    issuer: Principal,
    request: IssueRequest,
    issuerAuthority?: IssuerAuthority,
  ): Capability {
    const cap = issueCapability(issuer, request, this.now(), issuerAuthority);
    this.capabilities.set(cap.id, cap);
    this.eventLog.append({
      tenantId: cap.tenantId,
      principal: issuer.id,
      actor: issuer.id,
      actorKind: issuer.kind,
      action: 'capability.issue',
      resourceId: cap.resourceIds.join(','),
      decision: 'allow',
      capabilityId: cap.id,
      result: 'success',
      metadata: {
        phase: 'capability-issuance',
        subject: cap.subject,
        provenance: cap.provenance,
        expiresAt: cap.expiresAt,
        maxClassification: cap.maxClassification,
      },
    });
    return cap;
  }

  grant(cap: Capability): void {
    this.capabilities.set(cap.id, cap);
  }

  capabilitiesFor(subject: string): readonly Capability[] {
    return [...this.capabilities.values()].filter((c) => c.subject === subject);
  }

  get(id: string): Capability | undefined {
    return this.capabilities.get(id);
  }

  /** Consume a single-use capability after a successful execution. */
  consume(capabilityId: string): void {
    const cap = this.capabilities.get(capabilityId);
    if (!cap || !cap.singleUse) return;
    this.capabilities.set(capabilityId, markUsed(cap, this.now()));
  }

  authorize(input: AuthorizeInput): AuthorizationDecision {
    const at = this.now();
    const { principal, action, resourceId } = input;

    // M2: single guard — no unauthenticated principal reaches the PDP.
    // System principals (kind: 'authorization') are internal bootstrap and bypass
    // this check. All human, agent, and service principals must carry valid auth.
    if (principal.kind !== 'authorization' && !isAuthenticated(principal, at)) {
      // Distinguish IdP outage from bad credentials: if the IdP is unreachable,
      // emit 'idp-unavailable' so operators can see the degraded state.
      const idpDown = this.idpHealth?.().status === 'unreachable';
      const denyReason: DenyReason = idpDown ? 'idp-unavailable' : 'unauthenticated-principal';
      const decision = deny(
        principal.id,
        action,
        resourceId,
        denyReason,
        `principal ${principal.id} has no valid authentication context`,
        at,
      );
      try {
        this.eventLog.append({
          tenantId: principal.tenantId,
          principal: principal.id,
          actor: principal.id,
          actorKind: principal.kind,
          action,
          resourceId,
          decision: 'deny',
          denyReason,
          result: 'denied',
          metadata: { phase: 'decision', reason: decision.reason, authCheck: 'failed' },
        });
      } catch {
        // Evidence write failure on an auth check — still deny
      }
      return decision;
    }

    const decision = this.evaluate(input, at);
    try {
      this.eventLog.append({
        tenantId: principal.tenantId,
        principal: principal.id,
        actor: principal.id,
        actorKind: principal.kind,
        action,
        resourceId,
        decision: decision.decision,
        denyReason: decision.denyReason,
        policyId: decision.policyId,
        capabilityId: decision.capabilityId,
        result: decision.decision === 'deny' ? 'denied' : 'success',
        metadata: { phase: 'decision', reason: decision.reason },
      });
    } catch (error) {
      // A decision we cannot record is a decision we do not make.
      return deny(
        principal.id,
        action,
        resourceId,
        'evidence-write-failure',
        `decision not recorded, failing closed: ${(error as Error).message}`,
        at,
      );
    }
    return decision;
  }

  /**
   * Decrypt sealed evidence content. Requires `evidence.decrypt` authority on the
   * classification key resource. The attempt is authorized and audited like any
   * other action, so reading the evidence is itself part of the evidence.
   */
  revealEvidence(principal: Principal, event: SecurityEvent, approvals?: readonly Approval[]): string | undefined {
    const sealed = (event.metadata as { sealed?: Sealed } | undefined)?.sealed;
    if (!sealed) return undefined;

    const classification = classificationFromKeyId(sealed.keyId);
    if (!this.registry.get(sealed.keyId)) {
      this.registry.add(
        defineResource({
          id: sealed.keyId,
          type: 'system',
          tenantId: principal.tenantId,
          classification,
          attributes: { purpose: 'evidence-decryption-key' },
        }),
      );
    }

    const decision = this.authorize({
      principal,
      action: 'evidence.decrypt',
      resourceId: sealed.keyId,
      approvals,
    });
    if (decision.decision !== 'allow') return undefined;
    return open(sealed);
  }

  private evaluate(input: AuthorizeInput, at: number): AuthorizationDecision {
    const { principal, action, resourceId, params, networkHost, approvals } = input;
    try {
      let resource;
      try {
        resource = this.registry.require(resourceId);
      } catch (e) {
        if (e instanceof UnknownResourceError) {
          return deny(principal.id, action, resourceId, 'unknown-resource', e.message, at);
        }
        throw e;
      }

      if (resource.tenantId !== principal.tenantId) {
        return deny(
          principal.id,
          action,
          resourceId,
          'tenant-mismatch',
          'resource belongs to another tenant',
          at,
          '@tenant-isolation',
        );
      }

      const candidates = this.capabilitiesFor(principal.id).filter(
        (c) => c.resourceIds.includes(resourceId) && c.actions.includes(action),
      );

      if (candidates.length === 0) {
        return deny(
          principal.id,
          action,
          resourceId,
          'no-capability',
          `no capability grants '${action}' on ${resourceId} to ${principal.id}`,
          at,
        );
      }

      const failures: { reason: DenyReason; detail: string }[] = [];
      for (const cap of candidates) {
        const check = verifyCapability(cap, {
          subject: principal.id,
          tenantId: resource.tenantId,
          action,
          resourceId,
          classification: resource.classification,
          now: at,
          params,
          networkHost,
        });
        if (!check.ok) {
          failures.push({ reason: check.reason, detail: check.detail });
          continue;
        }

        const result = this.engine.evaluate({
          principal,
          resource,
          action,
          now: at,
          params,
          approvals: approvals?.filter((a) => {
            // M2: every approval must come from an authenticated human with MFA.
            // Reject approvals where the reviewer lacks valid auth or MFA.
            if (!hasMfa(a.reviewerAuth)) {
              return false;
            }
            // Reject expired reviewer auth
            if (a.reviewerAuth.expiresAt <= at) {
              return false;
            }
            return true;
          }),
          networkHost,
        });

        if (result.effect === 'deny') {
          return deny(principal.id, action, resourceId, 'policy-deny', result.reason, at, result.ruleId);
        }
        return allow(principal.id, action, resourceId, result.reason, at, cap.id, result.ruleId ?? 'unknown');
      }

      const best =
        REASON_PRIORITY.map((r) => failures.find((f) => f.reason === r)).find((f) => f !== undefined) ??
        failures[0];
      return deny(
        principal.id,
        action,
        resourceId,
        best?.reason ?? 'no-capability',
        best?.detail ?? 'no usable capability',
        at,
      );
    } catch (error) {
      return deny(
        principal.id,
        action,
        resourceId,
        'evaluation-error',
        `authorization evaluation failed closed: ${(error as Error).message}`,
        at,
      );
    }
  }
}

export function authorizationRoot(tenantId: string): Principal {
  return { id: `authz-root:${tenantId}`, kind: 'authorization', tenantId, roles: ['authorization'], attributes: {} };
}
