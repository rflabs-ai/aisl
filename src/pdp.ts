/**
 * Policy Decision Point.
 *
 * Authorization = capability AND policy. Both must pass. Every call returns a
 * decision and appends an audit event — there is no path that decides silently.
 * Any internal error is converted into a deny (fail closed, invariant 12).
 */

import {
  CapabilityIssuanceError,
  type Capability,
  type IssueRequest,
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
import { type EventStore, type SecurityEvent, type AuditFilters, StoreUnavailableError } from './events.ts';
import { BASELINE_ROLES, type Approval, type PolicyEngine } from './policy.ts';
import { type ResourceRegistry, UnknownResourceError, defineResource } from './registry.ts';
import { type Sealed, classificationFromKeyId, openFor, tenantFromKeyId } from './seal.ts';
import { hasMfa, type IdPHealth } from './identity.ts';
import { ClockGuard, HealthState } from './health.ts';

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

/**
 * H13 (ADR-026): a freeze entry — the kill switch. Scope 'global' freezes every
 * tenant; scope 'tenant' freezes one. `reason`/`actor` are operator-supplied
 * and must not contain secrets (same posture as event metadata).
 */
export interface FreezeEntry {
  readonly scope: 'tenant' | 'global';
  readonly tenantId?: string;
  readonly reason: string;
  readonly at: number;
  readonly actor: string;
}

/**
 * Structural shape of a revocation-channel record, as the PDP needs it. The
 * channel types live in src/incident.ts; the PDP accepts this subset so the
 * dependency direction stays pdp <- incident (no cycle).
 */
export interface IncidentRecordLike {
  readonly action: string;
  readonly scope: 'tenant' | 'global';
  readonly tenantId?: string;
  readonly targetId?: string;
  readonly reason: string;
  readonly at: number;
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

/**
 * H13 (ADR-026): actions that read evidence rather than act. The kill switch
 * freezes acting authority; evidence reads stay authorized (under their own
 * capability + policy) so an incident can be reconstructed and preserved
 * while the switch is engaged. `revokeAll` also spares capabilities whose
 * action set is entirely evidence-read, so the responder's export ability
 * survives the kill switch and `lift` restores no authority — it only lifts
 * the freeze.
 */
const EVIDENCE_READ_ACTIONS: ReadonlySet<string> = new Set(['query.audit', 'audit.export', 'evidence.decrypt']);

export class AuthorizationService {
  private readonly capabilities = new Map<string, Capability>();
  private readonly revoked = new Map<string, RevokedCapability>();
  /**
   * H13: issuance timestamps (local bookkeeping, not part of the signed
   * capability). Used to fence replayed `revoke-caps` records: a bulk revoke
   * applies only to capabilities that existed at the record's timestamp, so a
   * capability issued after an incident (and after `lift`) is not killed by a
   * replayed channel record.
   */
  private readonly registeredAt = new Map<string, number>();
  private readonly frozenTenants = new Map<string, FreezeEntry>();
  private globalFreeze?: FreezeEntry;
  private broadcastSync?: (force: boolean) => void;
  private syncIntervalMs = 1_000;
  private lastSyncAt = Number.NEGATIVE_INFINITY;
  private readonly registry: ResourceRegistry;
  private readonly engine: PolicyEngine;
  private readonly eventLog: EventStore;
  private readonly now: () => number;
  private readonly idpHealth?: () => IdPHealth;
  private readonly roles: readonly Role[];
  /**
   * H15 (ADR-027): observed availability of the decision path's dependencies.
   * Self-owned by default so every construction gets health tracking; an
   * embedder (or a test) can install its own tracker to observe transitions.
   */
  private health = new HealthState();
  /** H15: lenient by default; install a strict guard (monotonic reference) to detect stall/backward jumps. */
  private clockGuard: ClockGuard;

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
    this.clockGuard = new ClockGuard(now);
  }

  // ---- H15 (ADR-027): fail-closed availability ----------------------------

  /** Install an observed-health tracker (default: one owned by this service). */
  setHealth(health: HealthState): void {
    this.health = health;
  }

  /** The health tracker; `/healthz` and operator surfaces read this. */
  get healthState(): HealthState {
    return this.health;
  }

  /** Install a clock guard (default: lenient over the decision clock). */
  setClockGuard(guard: ClockGuard): void {
    this.clockGuard = guard;
  }

  private readClock(): { ok: true; at: number } | { ok: false; detail: string } {
    const read = this.clockGuard.read();
    if (read.ok) this.health.mark('clock', 'ok');
    else this.health.mark('clock', 'unavailable', 'clock read failed');
    return read;
  }

  /**
   * H15 (ADR-027): a fault-tolerant reading for bookkeeping-only timestamps
   * (registration, consumption, revocation, freeze entries). These never gate
   * authority, and a clock fault must not disable the kill switch or leave a
   * single-use capability unconsumed. Authority decisions use `readClock`.
   */
  private bookkeepingNow(): number {
    const read = this.readClock();
    return read.ok ? read.at : Date.now();
  }

  /**
   * A faulted clock denies before any authority is examined: every time-based
   * check (capability expiry, auth expiry, approvals) is untrustworthy, and a
   * stalled clock must not silently extend authority past `expiresAt`.
   */
  private clockFaultDeny(input: AuthorizeInput, detail: string): AuthorizationDecision {
    const { principal, action, resourceId } = input;
    const decision = deny(
      principal.id,
      action,
      resourceId,
      'clock-unavailable',
      `clock unavailable, failing closed: ${detail}`,
      Date.now(),
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
        denyReason: 'clock-unavailable',
        result: 'denied',
        metadata: { phase: 'decision', reason: decision.reason, fault: 'clock' },
      });
      this.health.mark('store', 'ok');
    } catch {
      this.health.mark('store', 'unavailable', 'evidence append failed');
    }
    return decision;
  }

  /**
   * H1 (ADR-023): `parent` is the issuer's own signed capability. Beyond the
   * pure-function checks in issueCapability (signature, subject, tenant,
   * expiry, consumption), the service adds custody: the parent must be
   * registered here and not revoked. Fail closed on both.
   */
  issue(
    issuer: Principal,
    request: IssueRequest,
    parent?: Capability,
  ): Capability {
    // H13 (ADR-026): issuance force-syncs the revocation channel — issuance is
    // rare, and a kill switch published while this node's throttle window is
    // open must not let a mint through. Fail-closed: a sync failure is counted
    // but never blocks the decision path here; the local freeze check below
    // and the event store's own failure semantics still apply.
    this.syncBroadcast(true);
    // H15 (ADR-027): the clock is a checked dependency on the issuance path too.
    const clock = this.readClock();
    if (!clock.ok) {
      const refusal = `clock-unavailable: capability issuance refused (${clock.detail})`;
      try {
        this.eventLog.append({
          tenantId: issuer.tenantId,
          principal: issuer.id,
          actor: issuer.id,
          actorKind: issuer.kind,
          action: 'capability.issue',
          resourceId: request.resourceIds.join(','),
          decision: 'deny',
          denyReason: 'clock-unavailable',
          result: 'denied',
          metadata: { phase: 'capability-issuance-refused', refusal },
        });
      } catch {
        this.health.mark('store', 'unavailable', 'evidence append failed');
      }
      throw new CapabilityIssuanceError(`clock unavailable, capability issuance refused: ${clock.detail}`);
    }
    const at = clock.at;
    const freeze = this.freezeFor(issuer.tenantId);
    if (freeze) {
      const refusal = `incident-frozen: incident response has frozen issuance for tenant ${issuer.tenantId} (${freeze.reason})`;
      try {
        this.eventLog.append({
          tenantId: issuer.tenantId,
          principal: issuer.id,
          actor: issuer.id,
          actorKind: issuer.kind,
          action: 'capability.issue',
          resourceId: request.resourceIds.join(','),
          decision: 'deny',
          denyReason: 'incident-frozen',
          result: 'denied',
          metadata: { phase: 'capability-issuance-refused', refusal },
        });
      } catch {
        this.health.mark('store', 'unavailable', 'evidence append failed');
      }
      throw new CapabilityIssuanceError(refusal);
    }
    if (parent) {
      const custodyError = !this.capabilities.has(parent.id)
        ? `parent capability ${parent.id} is not registered with this authorization service`
        : this.revoked.has(parent.id)
          ? `parent capability ${parent.id} is revoked`
          : undefined;
      if (custodyError) {
        // H1 (audit 04): a refused delegation attempt is a security-relevant
        // refusal — record it before failing closed (invariant 7 spirit).
        try {
          this.eventLog.append({
            tenantId: issuer.tenantId,
            principal: issuer.id,
            actor: issuer.id,
            actorKind: issuer.kind,
            action: 'capability.issue',
            resourceId: request.resourceIds.join(','),
            decision: 'deny',
            capabilityId: parent.id,
            result: 'denied',
            metadata: { phase: 'capability-issuance-refused', refusal: custodyError },
          });
        } catch {
          this.health.mark('store', 'unavailable', 'evidence append failed');
        }
        throw new CapabilityIssuanceError(custodyError);
      }
    }
    const cap = issueCapability(issuer, request, at, parent);
    // H15 (ADR-027): evidence before authority. The issuance event is recorded
    // first; a capability is registered only after its evidence lands. A store
    // outage refuses the mint instead of leaving unaudited authority live.
    try {
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
      this.health.mark('store', 'ok');
    } catch (error) {
      this.health.mark('store', 'unavailable', 'evidence append failed');
      throw new CapabilityIssuanceError(
        `evidence store unavailable, capability issuance refused: ${(error as Error).message}`,
      );
    }
    this.capabilities.set(cap.id, cap);
    this.registeredAt.set(cap.id, at);
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
    parent?: Capability,
  ): Capability {
    const request = issueRequestForRole(this.roles, issuer, roleId, subject, resourceIds, opts);
    return this.issue(issuer, request, parent);
  }

  /**
   * H1 embedder seam: register a caller-supplied capability (rehydrated from
   * persistence or delegated) without the `issue()` pipeline. Deliberately
   * bypasses the revocation-channel force-sync and the issuance freeze (audit
   * ticket 16) — an embedder restarting during an incident must be able to
   * rebuild its map. Adding authority this way is not a bypass of the kill
   * switch: `evaluate()` still refuses to use it while its tenant is frozen,
   * and `lift` restores no revoked authority. New authority goes through
   * `issue()`.
   */
  grant(cap: Capability): void {
    this.capabilities.set(cap.id, cap);
    this.registeredAt.set(cap.id, this.bookkeepingNow());
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
    this.capabilities.set(capabilityId, markUsed(cap, this.bookkeepingNow()));
  }

  /** Revoke a capability. Immediate propagation — next authorize() call sees it. */
  revoke(capabilityId: string, reason: string): void {
    const revoked: RevokedCapability = {
      capabilityId,
      revokedAt: this.bookkeepingNow(),
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

  // ---- H13 (ADR-026): incident-response state -----------------------------

  /**
   * Install the revocation-channel sync hook. Called throttled from
   * `authorize` (bounded by `intervalMs`, default 1 s — inside the ≤ 5 s
   * propagation target) and forced from `issue`.
   */
  setBroadcastSync(sync: (force: boolean) => void, intervalMs = 1_000): void {
    this.broadcastSync = sync;
    this.syncIntervalMs = intervalMs;
  }

  private syncBroadcast(force: boolean): void {
    if (!this.broadcastSync) return;
    try {
      if (!force && this.now() - this.lastSyncAt < this.syncIntervalMs) return;
      this.lastSyncAt = this.now();
      this.broadcastSync(force);
    } catch {
      // A hook bug or a faulted clock must never block the decision path; the
      // service's own sync counters (IncidentService.status) are the
      // operator-visible health, and a clock fault is denied by `readClock`.
    }
  }

  /** The freeze covering this tenant, if any (a global freeze covers all). */
  freezeFor(tenantId: string): FreezeEntry | undefined {
    return this.globalFreeze ?? this.frozenTenants.get(tenantId);
  }

  isFrozen(tenantId: string): boolean {
    return this.freezeFor(tenantId) !== undefined;
  }

  freezeState(): readonly FreezeEntry[] {
    return [...(this.globalFreeze ? [this.globalFreeze] : []), ...this.frozenTenants.values()];
  }

  /** H13 kill switch: freeze issuance and authorization for a tenant (or all). */
  freeze(scope: 'tenant' | 'global', tenantId: string | undefined, reason: string, actor: string): void {
    if (scope === 'tenant' && (!tenantId || tenantId.trim() === '')) {
      throw new Error('a tenant freeze requires a tenant id');
    }
    const entry: FreezeEntry = { scope, ...(scope === 'tenant' ? { tenantId } : {}), reason, at: this.bookkeepingNow(), actor };
    if (scope === 'global') this.globalFreeze = entry;
    else this.frozenTenants.set(tenantId!, entry);
    this.eventLog.append({
      tenantId: scope === 'global' ? '' : tenantId!,
      principal: actor,
      actor: actor,
      actorKind: 'authorization',
      action: 'incident.freeze',
      resourceId: scope,
      decision: 'allow',
      result: 'success',
      metadata: { phase: 'incident-freeze', scope, tenantId: tenantId ?? null, reason },
    });
  }

  /** Lift a freeze. Revoked capabilities are NOT restored — freeze is reversible, revocation is not. */
  unfreeze(scope: 'tenant' | 'global', tenantId: string | undefined, reason: string, actor: string): boolean {
    // H15 (ADR-027): evidence before widening. The lift event is recorded
    // first; a freeze that cannot be recorded stays engaged (a stalled lift
    // must not silently restore authority during a store outage).
    const existed = scope === 'global' ? this.globalFreeze !== undefined : this.frozenTenants.has(tenantId ?? '');
    if (!existed) return false;
    this.eventLog.append({
      tenantId: scope === 'global' ? '' : tenantId!,
      principal: actor,
      actor: actor,
      actorKind: 'authorization',
      action: 'incident.lift',
      resourceId: scope,
      decision: 'allow',
      result: 'success',
      metadata: { phase: 'incident-lift', scope, tenantId: tenantId ?? null, reason },
    });
    this.health.mark('store', 'ok');
    if (scope === 'global') this.globalFreeze = undefined;
    else this.frozenTenants.delete(tenantId!);
    return true;
  }

  /**
   * H13 bulk revocation: revoke every registered capability in scope, one
   * audited `capability.revoke` event per capability (the evidence shows
   * exactly what was killed, not just a count).
   *
   * H15 (ADR-027): revocation is a narrowing action whose state applies
   * before its event; a per-capability evidence failure must not abort the
   * kill switch mid-loop. Failures are loud (health transition) and the
   * revocation still counts.
   */
  revokeAll(scope: 'tenant' | 'global', tenantId: string | undefined, reason: string): number {
    if (scope === 'tenant' && (!tenantId || tenantId.trim() === '')) {
      throw new Error('a tenant revokeAll requires a tenant id');
    }
    let count = 0;
    for (const cap of [...this.capabilities.values()]) {
      if (this.revoked.has(cap.id)) continue;
      if (scope === 'tenant' && cap.tenantId !== tenantId) continue;
      // Evidence-read capabilities (audit query/export, evidence decryption)
      // are not acting authority: an incident responder must still be able to
      // reconstruct and preserve evidence while the switch is engaged.
      if (cap.actions.every((a) => EVIDENCE_READ_ACTIONS.has(a))) continue;
      try {
        this.revoke(cap.id, reason);
      } catch {
        this.health.mark('store', 'unavailable', 'evidence append failed');
      }
      count++;
    }
    return count;
  }

  /**
   * Apply a revocation-channel record to local state (H13). Idempotent and
   * eventless by design: the channel record is the coordination evidence, and
   * the node's subsequent deny decisions are its local evidence. `revoke-caps`
   * is fenced by issuance time so replay cannot kill authority issued after
   * the incident.
   */
  applyIncidentRecord(record: IncidentRecordLike): void {
    const inScope = (tenantId: string): boolean => record.scope === 'global' || tenantId === record.tenantId;
    switch (record.action) {
      case 'freeze':
        if (record.scope === 'global') {
          this.globalFreeze = { scope: 'global', reason: record.reason, at: record.at, actor: 'channel' };
        } else if (record.tenantId) {
          this.frozenTenants.set(record.tenantId, { scope: 'tenant', tenantId: record.tenantId, reason: record.reason, at: record.at, actor: 'channel' });
        }
        break;
      case 'unfreeze':
        if (record.scope === 'global') this.globalFreeze = undefined;
        else if (record.tenantId) this.frozenTenants.delete(record.tenantId);
        break;
      case 'revoke-caps':
        for (const cap of this.capabilities.values()) {
          if (this.revoked.has(cap.id)) continue;
          if (!inScope(cap.tenantId)) continue;
          if (cap.actions.every((a) => EVIDENCE_READ_ACTIONS.has(a))) continue;
          if ((this.registeredAt.get(cap.id) ?? 0) > record.at) continue;
          this.revoked.set(cap.id, { capabilityId: cap.id, revokedAt: record.at, reason: record.reason });
        }
        break;
      case 'revoke-cap':
        if (record.targetId) {
          // Tenant isolation (audit ticket 12): a tenant-scoped record may only
          // revoke a target registered to that tenant. A target that is not
          // registered here is still recorded revoked — revocation ahead of
          // registration is the safe direction.
          const target = this.capabilities.get(record.targetId);
          if (target && !inScope(target.tenantId)) break;
          this.revoked.set(record.targetId, { capabilityId: record.targetId, revokedAt: record.at, reason: record.reason });
        }
        break;
      default:
        // Session-scoped actions are applied by IncidentService.
        break;
    }
  }

  authorize(input: AuthorizeInput): AuthorizationDecision {
    // H13: pull revocation-channel records (throttled). Bounded by the
    // configured interval, inside the ROADMAP ≤ 5 s propagation target.
    this.syncBroadcast(false);
    // H15 (ADR-027): the clock is a checked dependency; a fault denies before
    // any time-based authority check runs.
    const clock = this.readClock();
    if (!clock.ok) return this.clockFaultDeny(input, clock.detail);
    const at = clock.at;
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
        // Evidence write failure on an auth check — still deny, still observed.
        this.health.mark('store', 'unavailable', 'evidence append failed');
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
      this.health.mark('store', 'ok');
    } catch (error) {
      // H15 (ADR-027): the observed store fault drives the health transition
      // (one loud signal per transition, not one warning per denied decision).
      this.health.mark('store', 'unavailable', 'evidence append failed');
      if (error instanceof StoreUnavailableError) {
        // The store is DOWN (unreachable/unmigrated/failed write). Deny with
        // the distinct reason so an outage is not disguised as a generic
        // write failure — and no event can be appended while it is down.
        return deny(
          principal.id,
          action,
          resourceId,
          'store-unavailable',
          `evidence store unavailable, failing closed: ${(error as Error).message}`,
          at,
        );
      }
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

    // H8 (ADR-030): a v2 keyId names exactly one tenant. Refuse a seal bound
    // to another tenant BEFORE the lazy registry registration below — without
    // this check the foreign key id would be registered under the caller's
    // tenant, the caller's own capability (resource ids are opaque strings)
    // would match, and the keyId-derived key would decrypt the content. Fail
    // closed, and record the refusal in the caller's own evidence without
    // naming the foreign key. The check precedes the auth check by design: the
    // key binding must hold before any registration or authorization, so an
    // unauthorized caller can only ever produce a deny event.
    const keyTenant = tenantFromKeyId(sealed.keyId);
    if (keyTenant !== undefined && keyTenant !== principal.tenantId) {
      try {
        this.eventLog.append({
          tenantId: principal.tenantId,
          principal: principal.id,
          actor: principal.id,
          actorKind: principal.kind,
          action: 'evidence.decrypt',
          decision: 'deny',
          denyReason: 'tenant-mismatch',
          result: 'denied',
          metadata: { phase: 'evidence-reveal-refused', reason: 'sealed key belongs to another tenant' },
        });
        this.health.mark('store', 'ok');
      } catch {
        this.health.mark('store', 'unavailable', 'evidence append failed');
      }
      return undefined;
    }

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
    // H8 (ADR-030): open under the caller's tenant (v2) — a second binding on
    // top of the keyTenant check; legacy seals keep their documented behavior.
    return openFor(principal.tenantId, sealed);
  }

  /**
   * M6: Authorize audit query or export for a tenant. Reuses the revealEvidence
   * pattern: auth check -> tenant check -> capability match -> policy evaluate ->
   * event log append. Default deny on every failure.
   */
  queryAudit(input: AuthorizeInput, filters: AuditFilters): AuthorizationDecision {
    const { principal } = input;
    const action = input.action || 'query.audit';
    const derivedResourceId = `audit-log:${principal.tenantId}`;

    // H15 (ADR-027): same checked-clock contract as authorize().
    const clock = this.readClock();
    if (!clock.ok) {
      const decision = deny(
        principal.id,
        action,
        derivedResourceId,
        'clock-unavailable',
        `clock unavailable, failing closed: ${clock.detail}`,
        Date.now(),
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
          denyReason: 'clock-unavailable',
          result: 'denied',
          metadata: { phase: 'decision', reason: decision.reason, fault: 'clock' },
        });
      } catch {
        this.health.mark('store', 'unavailable', 'evidence append failed');
      }
      return decision;
    }
    const at = clock.at;

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
        this.health.mark('store', 'unavailable', 'evidence append failed');
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
        this.health.mark('store', 'unavailable', 'evidence append failed');
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
      // H13 (ADR-026): the kill switch trumps every other consideration for a
      // frozen tenant (or globally). Distinct reason so an incident is
      // operator-distinguishable from a policy or capability denial.
      const freeze = this.freezeFor(principal.tenantId);
      if (freeze && !EVIDENCE_READ_ACTIONS.has(action)) {
        return deny(
          principal.id,
          action,
          resourceId,
          'incident-frozen',
          freeze.scope === 'global'
            ? `global freeze active by incident response (${freeze.reason})`
            : `tenant ${principal.tenantId} is frozen by incident response (${freeze.reason})`,
          at,
          '@incident-response',
        );
      }

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

        let result;
        try {
          result = this.engine.evaluate({
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
        } catch (error) {
          // H15 (ADR-027): the engine is a checked dependency. Its throw is
          // observed (health transition) and denies with the distinct
          // evaluation-error reason; degradation never widens authority.
          this.health.mark('engine', 'unavailable', 'policy engine threw');
          return deny(
            principal.id,
            action,
            resourceId,
            'evaluation-error',
            `policy engine failed closed: ${(error as Error).message}`,
            at,
          );
        }
        this.health.mark('engine', 'ok');

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
