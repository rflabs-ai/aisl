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
  type RoleIssuanceRequest,
  issueCapability,
  issueRequestForRole,
  markUsed,
  verifyCapability,
} from './capability.ts';
import {
  type Action,
  type AuthorizationDecision,
  type DenyReason,
  type Principal,
  type Role,
  allow,
  deny,
  isAuthenticated,
} from './domain.ts';
import { type EventStore, type SecurityEvent, type AuditFilters } from './events.ts';
import { BASELINE_ROLES, type Approval, type PolicyEngine } from './policy.ts';
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

export interface RevokedCapability {
  readonly capabilityId: string;
  readonly revokedAt: number;
  readonly reason: string;
}

const REASON_PRIORITY: readonly DenyReason[] = [
  'capability-revoked',
  'capability-expired',
  'capability-consumed',
  'capability-signature-invalid',
  'capability-tenant-mismatch',
  'classification-ceiling',
  'capability-scope',
];

export class AuthorizationService {
  private readonly capabilities = new Map<string, Capability>();
  private readonly revoked = new Map<string, RevokedCapability>();
  private readonly registry: ResourceRegistry;
  private readonly engine: PolicyEngine;
  private readonly eventLog: EventStore;
  private readonly now: () => number;
  private readonly idpHealth?: () => IdPHealth;
  private readonly roles: readonly Role[];

  constructor(
    registry: ResourceRegistry,
    engine: PolicyEngine,
    eventLog: EventStore,
    now: () => number = Date.now,
    idpHealth?: () => IdPHealth,
    roles: readonly Role[] = BASELINE_ROLES,
  ) {
    this.registry = registry;
    this.engine = engine;
    this.eventLog = eventLog;
    this.now = now;
    this.idpHealth = idpHealth;
    this.roles = roles;
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

  /**
   * M11: role-templated issuance. The role bounds the request; everything the
   * issue() pipeline enforces (issuer kinds, tenant match, attenuation,
   * registration, audit) applies unchanged. Roles narrow authority — they
   * never mint it.
   */
  issueForRole(
    issuer: Principal,
    roleId: string,
    subject: string,
    resourceIds: readonly string[],
    opts: RoleIssuanceRequest,
    issuerAuthority?: IssuerAuthority,
  ): Capability {
    const request = issueRequestForRole(this.roles, issuer, roleId, subject, resourceIds, opts);
    return this.issue(issuer, request, issuerAuthority);
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

  /** Revoke a capability. Immediate propagation — next authorize() call sees it. */
  revoke(capabilityId: string, reason: string): void {
    const revoked: RevokedCapability = {
      capabilityId,
      revokedAt: this.now(),
      reason,
    };
    this.revoked.set(capabilityId, revoked);
    this.eventLog.append({
      tenantId: this.capabilities.get(capabilityId)?.tenantId ?? '',
      principal: 'system',
      actor: 'system',
      actorKind: 'authorization',
      action: 'capability.revoke',
      resourceId: capabilityId,
      decision: 'allow',
      capabilityId,
      result: 'success',
      metadata: { phase: 'capability-revocation', reason },
    });
  }

  /** Check if a capability has been revoked. */
  isRevoked(capabilityId: string): boolean {
    return this.revoked.has(capabilityId);
  }

  /** Get all revoked capabilities. */
  revokedCapabilities(): readonly RevokedCapability[] {
    return [...this.revoked.values()];
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

  /**
   * M6: Authorize audit query or export for a tenant. Reuses the revealEvidence
   * pattern: auth check -> tenant check -> capability match -> policy evaluate ->
   * event log append. Default deny on every failure.
   */
  queryAudit(input: AuthorizeInput, filters: AuditFilters): AuthorizationDecision {
    const at = this.now();
    const { principal } = input;
    const action = input.action || 'query.audit';
    const derivedResourceId = `audit-log:${principal.tenantId}`;

    // 1. Auth check fires first (mirrors authorize / revealEvidence)
    if (principal.kind !== 'authorization' && !isAuthenticated(principal, at)) {
      const idpDown = this.idpHealth?.().status === 'unreachable';
      const denyReason: DenyReason = idpDown ? 'idp-unavailable' : 'unauthenticated-principal';
      const decision = deny(
        principal.id,
        action,
        derivedResourceId,
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
          resourceId: derivedResourceId,
          decision: 'deny',
          denyReason,
          result: 'denied',
          metadata: { phase: 'decision', reason: decision.reason, authCheck: 'failed' },
        });
      } catch {
        // Evidence write failure on auth check
      }
      return decision;
    }

    // 2. Tenant check on filters and caller-supplied resourceId
    if (
      (input.resourceId && input.resourceId !== derivedResourceId) ||
      filters.tenantId !== principal.tenantId
    ) {
      const decision = deny(
        principal.id,
        action,
        derivedResourceId,
        'tenant-mismatch',
        'cross-tenant audit query denied',
        at,
        '@tenant-isolation',
      );
      try {
        this.eventLog.append({
          tenantId: principal.tenantId,
          principal: principal.id,
          actor: principal.id,
          actorKind: principal.kind,
          action,
          resourceId: derivedResourceId,
          decision: 'deny',
          denyReason: 'tenant-mismatch',
          result: 'denied',
          metadata: { phase: 'decision', reason: decision.reason },
        });
      } catch {
        // Evidence write failure
      }
      return decision;
    }

    // 3. Ensure synthetic resource is defined in registry
    if (!this.registry.get(derivedResourceId)) {
      this.registry.add(
        defineResource({
          id: derivedResourceId,
          type: 'audit-log',
          tenantId: principal.tenantId,
          classification: 'internal',
          attributes: { purpose: 'audit-log' },
        }),
      );
    }

    // 4. Delegate to standard authorize pipeline
    return this.authorize({
      principal,
      action,
      resourceId: derivedResourceId,
      params: input.params,
      networkHost: input.networkHost,
      approvals: input.approvals,
    });
  }

  private evaluate(input: AuthorizeInput, at: number): AuthorizationDecision {
    const { principal, action, resourceId, params, networkHost, approvals } = input;
    try {
      // The synthetic audit-log resource is registered by queryAudit() before it
      // delegates here. A direct authorize() call on a caller-constructed
      // audit-log:* id has no such registration and fails closed as
      // unknown-resource.
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

      // M6 (Claim 21): audit.export is implied by query.audit in capability scope;
      // mirrors verifyCapability in src/capability.ts. Keep the two in sync.
      const candidates = this.capabilitiesFor(principal.id).filter(
        (c) =>
          c.resourceIds.includes(resourceId) &&
          (c.actions.includes(action) || (action === 'audit.export' && c.actions.includes('query.audit'))),
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
        if (this.revoked.has(cap.id)) {
          failures.push({ reason: 'capability-revoked', detail: `capability ${cap.id} has been revoked` });
          continue;
        }
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
