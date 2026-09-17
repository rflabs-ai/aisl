/**
 * M6: Audit Query + Export Service.
 *
 * Provides authorized, tenant-scoped access to the evidence plane.
 * Every query and export:
 * 1. Checks authentication and tenant boundaries fail-closed.
 * 2. Requires a capability for audit-log:<tenantId> and policy allow.
 * 3. Appends an audit event for the decision (Claim 7).
 * 4. Returns events with original Ed25519 signatures and hash intact for verifyBundle().
 * 5. Validates filter boundaries (<= 90 days, <= 1000 limit, offset >= 0).
 */

import {
  type Principal,
  type AuthorizationDecision,
} from './domain.ts';
import {
  EventLog,
  type SecurityEvent,
  type AuditFilters,
  type AuditExport,
} from './events.ts';
import { AuthorizationService } from './pdp.ts';
import { type ResourceRegistry } from './registry.ts';
import { type PolicyEngine } from './policy.ts';
import { type IdPHealth } from './identity.ts';

export { type AuditFilters, type AuditExport } from './events.ts';

export class AuditFilterError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'AuditFilterError';
  }
}

export interface QueryResult extends ReadonlyArray<SecurityEvent> {
  readonly decision: AuthorizationDecision;
  readonly events: readonly SecurityEvent[];
}

// ponytail: 90-day time window and 1000-event page size ceiling. upgrade: stream cursor pagination if datasets exceed memory.
const MAX_TIME_RANGE_MS = 90 * 24 * 60 * 60 * 1000; // 90 days in ms

export class AuditQueryService {
  private readonly authorization: AuthorizationService;
  private readonly eventLog: EventLog;
  private readonly clock: () => number;

  constructor(
    authorizationOrRegistry: AuthorizationService | ResourceRegistry,
    eventLog: EventLog,
    policyOrClock?: PolicyEngine | (() => number),
    clockOrIdp?: (() => number) | (() => IdPHealth),
    idpHealth?: () => IdPHealth,
  ) {
    this.eventLog = eventLog;
    if (authorizationOrRegistry instanceof AuthorizationService) {
      this.authorization = authorizationOrRegistry;
      this.clock = typeof policyOrClock === 'function' ? policyOrClock : Date.now;
    } else {
      this.clock = typeof clockOrIdp === 'function' ? (clockOrIdp as () => number) : Date.now;
      this.authorization = new AuthorizationService(
        authorizationOrRegistry,
        policyOrClock as PolicyEngine,
        eventLog,
        this.clock,
        idpHealth,
      );
    }
  }

  private validateFilters(filters: AuditFilters): void {
    if (!filters.tenantId || typeof filters.tenantId !== 'string' || filters.tenantId.trim() === '') {
      throw new AuditFilterError('tenantId is required');
    }
    if (filters.limit !== undefined) {
      if (filters.limit <= 0 || filters.limit > 1000 || !Number.isInteger(filters.limit)) {
        throw new AuditFilterError(`limit must be between 1 and 1000 (got ${filters.limit})`);
      }
    }
    if (filters.offset !== undefined) {
      if (filters.offset < 0 || !Number.isInteger(filters.offset)) {
        throw new AuditFilterError(`offset cannot be negative (got ${filters.offset})`);
      }
    }
    if (filters.fromSeq !== undefined && filters.fromSeq < 0) {
      throw new AuditFilterError(`fromSeq cannot be negative (got ${filters.fromSeq})`);
    }
    if (filters.toSeq !== undefined && filters.toSeq < 0) {
      throw new AuditFilterError(`toSeq cannot be negative (got ${filters.toSeq})`);
    }
    if (filters.fromSeq !== undefined && filters.toSeq !== undefined && filters.fromSeq > filters.toSeq) {
      throw new AuditFilterError(`fromSeq (${filters.fromSeq}) cannot exceed toSeq (${filters.toSeq})`);
    }
    if (filters.fromTime !== undefined && filters.toTime !== undefined) {
      if (filters.fromTime > filters.toTime) {
        throw new AuditFilterError(`fromTime (${filters.fromTime}) cannot be after toTime (${filters.toTime})`);
      }
      const rangeMs = filters.toTime - filters.fromTime;
      if (rangeMs > MAX_TIME_RANGE_MS) {
        throw new AuditFilterError(`time range exceeds 90 days (${rangeMs} ms > ${MAX_TIME_RANGE_MS} ms)`);
      }
    }
  }

  query(principal: Principal, filters: AuditFilters): QueryResult {
    this.validateFilters(filters);
    const decision = this.authorization.queryAudit(
      { principal, action: 'query.audit', resourceId: `audit-log:${principal.tenantId}` },
      filters,
    );
    if (decision.decision !== 'allow') {
      const emptyEvents: readonly SecurityEvent[] = [];
      return Object.assign([], { decision, events: emptyEvents });
    }
    const events = this.eventLog.query(filters);
    return Object.assign([...events], { decision, events });
  }

  exportFor(principal: Principal, filters: AuditFilters): AuditExport {
    this.validateFilters(filters);
    const decision = this.authorization.queryAudit(
      { principal, action: 'audit.export', resourceId: `audit-log:${principal.tenantId}` },
      filters,
    );
    if (decision.decision !== 'allow') {
      return {
        tenantId: filters.tenantId,
        generatedAt: this.clock(),
        fromSeq: filters.fromSeq ?? 0,
        toSeq: filters.toSeq ?? 0,
        events: [],
        head: '',
        previousHead: null,
      };
    }
    return this.eventLog.exportFor(filters);
  }
}
