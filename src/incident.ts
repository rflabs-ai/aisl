/**
 * H13 incident response (ADR-026): kill switch, revocation channel, evidence
 * preservation.
 *
 * Three mechanisms, one module:
 *
 * 1. `IncidentService.engage` is the operator kill switch — it freezes
 *    issuance + authorization, revokes every registered capability in scope,
 *    and revokes sessions in scope. Local enforcement happens first; a channel
 *    outage never blocks the emergency action, it is reported
 *    (`broadcastOk: false` + status counters).
 * 2. `RevocationChannel` broadcasts scope/single-target revocation records
 *    across nodes (and from an operator CLI process) without touching the
 *    single-writer event chain. The in-memory backend is the default and the
 *    multi-node test seam; the Postgres backend is the multi-process story
 *    (mirror + async refresh, the PostgresEventLog pattern).
 * 3. `preserve` pages past M6's 1000-event export cap into an independently
 *    verifiable `asl-incident-bundle` artifact and records only digest + head
 *    + counts in the event log. `reconstruct` summarizes the same authorized
 *    slice.
 *
 * No new authority path: engage/lift/preserve/reconstruct call the existing
 * authorization, session, and audit services.
 */

import { createHash, type KeyObject } from 'node:crypto';
import { mkdirSync, writeFileSync } from 'node:fs';
import { dirname } from 'node:path';
import { canonicalJson, type Principal } from './domain.ts';
import {
  type AuditExport,
  type EventStore,
  type SecurityEvent,
  eventHash,
  eventPublicKey,
  verifyBundle,
  verifyEventSignature,
} from './events.ts';
import { AuthorizationService, type FreezeEntry } from './pdp.ts';
import { SessionManager } from './session-manager.ts';
import { AuditQueryService } from './audit-query.ts';

export type IncidentScope = 'tenant' | 'global';

export type RevocationAction =
  | 'freeze'
  | 'unfreeze'
  | 'revoke-caps'
  | 'revoke-sessions'
  | 'revoke-cap'
  | 'revoke-session'
  /** H2 (ADR-028): credential (jti) revocation; consumed by IdentityProvider feeds. */
  | 'revoke-token';

export interface RevocationInput {
  readonly action: RevocationAction;
  readonly scope: IncidentScope;
  readonly tenantId?: string;
  readonly targetId?: string;
  readonly reason: string;
  readonly at: number;
}

export interface RevocationRecord extends RevocationInput {
  readonly seq: number;
}

export interface ChannelHealth {
  readonly errors: number;
  readonly lastError?: string;
}

/**
 * H2 (ADR-028): the IdentityProvider surface the incident service needs to
 * apply credential revocations locally-first. Declared structurally so
 * incident.ts does not import identity.ts.
 */
export interface TokenRevoker {
  revokeToken(tokenId: string): void;
  isTokenRevoked(tokenId: string): boolean;
}

/**
 * The revocation-coordination port. `since`/`cursor` read a local mirror and
 * are synchronous by design: the decision path cannot await a database.
 * Async backends fill the mirror through `refresh()` (fired by sync) and
 * report failures through `health()`.
 */
export interface RevocationChannel {
  publish(input: RevocationInput): void;
  since(cursor: number): readonly RevocationRecord[];
  cursor(): number;
  refresh(): void;
  flush(): Promise<void>;
  health(): ChannelHealth;
  close(): void;
}

/** Single-process backend and the shared multi-node test seam. */
export class InMemoryRevocationChannel implements RevocationChannel {
  private readonly records: RevocationRecord[] = [];

  publish(input: RevocationInput): void {
    this.records.push({ ...input, seq: this.records.length });
  }

  since(cursor: number): readonly RevocationRecord[] {
    return this.records.filter((r) => r.seq > cursor);
  }

  cursor(): number {
    return this.records.length - 1;
  }

  refresh(): void {}

  flush(): Promise<void> {
    return Promise.resolve();
  }

  health(): ChannelHealth {
    return { errors: 0 };
  }

  close(): void {}
}

export interface IncidentActionInput {
  readonly scope: IncidentScope;
  readonly tenantId?: string;
  readonly reason: string;
  readonly actor: string;
}

export interface IncidentActionResult {
  readonly scope: IncidentScope;
  readonly tenantId?: string;
  readonly frozen: boolean;
  readonly capabilitiesRevoked: number;
  readonly sessionsRevoked: number;
  readonly broadcastOk: boolean;
  /**
   * H15 (ADR-027): false when local enforcement completed but the aggregate
   * action event could not be recorded (store outage). The safety actions'
   * own state changes are already applied; missed evidence is reported, never
   * silent.
   */
  readonly evidenceRecorded: boolean;
  readonly eventSeq?: number;
}

export interface IncidentSyncResult {
  readonly applied: number;
  readonly skipped: boolean;
  readonly failures: number;
  readonly cursor: number;
}

export interface IncidentStatus {
  readonly freezes: readonly FreezeEntry[];
  readonly frozen: boolean;
  readonly revokedCapabilities: number;
  readonly channelCursor: number;
  readonly syncCursor: number;
  readonly appliedRecords: number;
  readonly syncFailures: number;
  readonly channelErrors: number;
  readonly channelLastError?: string;
}

export interface PreservationInput {
  readonly principal: Principal;
  readonly tenantId: string;
  readonly fromSeq: number;
  readonly toSeq: number;
  readonly outPath: string;
}

export interface PreservationResult {
  readonly path: string;
  readonly digest: string;
  readonly events: number;
  readonly fromSeq: number;
  readonly toSeq: number;
  readonly head: string;
  readonly chainValid: boolean;
  readonly anchorMatch: boolean;
  readonly eventSeq: number;
}

export interface IncidentBundle {
  readonly type: 'asl-incident-bundle';
  readonly version: 1;
  /**
   * The tenant whose events are included; `'*'` is the global-incident
   * filtered view over events recorded with `tenantId: ''`.
   */
  readonly tenantId: string;
  readonly requestedFromSeq: number;
  readonly requestedToSeq: number;
  /** First seq actually present in the slice (tenant-scoped seqs are not contiguous). */
  readonly fromSeq: number;
  /** Last seq actually present in the slice. */
  readonly toSeq: number;
  readonly generatedAt: number;
  readonly events: readonly SecurityEvent[];
  readonly head: string;
  readonly previousHead: string | null;
  /**
   * True when the included events form an unbroken hash-chain slice (each
   * event links to the previous included event). A filtered view (global
   * incident, or a tenant interleaved with other tenants) is not contiguous;
   * verification then checks per-event authenticity + the recorded live-chain
   * state instead of linkage.
   */
  readonly contiguous: boolean;
  readonly chainValid: boolean;
  readonly anchorMatch: boolean;
  /** sha256 over canonicalJson(bundle minus digest) — independently recomputable. */
  readonly digest: string;
}

export interface BundleVerification {
  readonly valid: boolean;
  readonly digestMatches: boolean;
  readonly bundleValid: boolean;
  readonly errors: readonly string[];
}

export interface ReconstructionInput {
  readonly principal: Principal;
  readonly tenantId: string;
  readonly fromSeq: number;
  readonly toSeq: number;
}

export interface IncidentReport {
  readonly tenantId: string;
  readonly requestedFromSeq: number;
  readonly requestedToSeq: number;
  readonly events: number;
  readonly decisions: { readonly allow: number; readonly deny: number };
  readonly denyReasons: Readonly<Record<string, number>>;
  readonly actions: Readonly<Record<string, number>>;
  readonly revocations: number;
  readonly freezes: number;
  readonly lifts: number;
  readonly actors: readonly string[];
  readonly firstAt: number | null;
  readonly lastAt: number | null;
  readonly chainValid: boolean;
}

export class IncidentInputError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'IncidentInputError';
  }
}

export class IncidentEvidenceError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'IncidentEvidenceError';
  }
}

/**
 * sha256 over the bundle content (everything except its own digest). The
 * content is normalized through a JSON round-trip first: the in-memory event
 * objects carry explicit `undefined` fields that JSON serialization drops, and
 * the digest must be recomputable from the written file.
 */
export function bundleDigest(bundle: IncidentBundle): string {
  const { digest: _digest, ...content } = bundle;
  return createHash('sha256').update(canonicalJson(JSON.parse(JSON.stringify(content))), 'utf8').digest('hex');
}

/**
 * Offline bundle verification: content digest, recorded chain state, then the
 * event chain itself (hashes + Ed25519 signatures) via `verifyBundle`.
 */
export function verifyIncidentBundle(
  bundle: IncidentBundle,
  options: { publicKey?: KeyObject; anchorContent?: string } = {},
): BundleVerification {
  const errors: string[] = [];
  const digestMatches = /^[0-9a-f]{64}$/.test(bundle.digest) && bundle.digest === bundleDigest(bundle);
  if (!digestMatches) errors.push('digest does not match bundle content');
  if (!bundle.chainValid) errors.push('bundle recorded an invalid live chain at preservation time');

  const events = bundle.events;
  const first = events[0];
  const last = events.at(-1);
  if (events.length === 0) errors.push('bundle contains no events');
  if (last && bundle.head !== last.eventHash) errors.push('bundle head does not match the last event');
  if (first && bundle.fromSeq !== first.seq) errors.push('bundle fromSeq does not match the first event');
  if (last && bundle.toSeq !== last.seq) errors.push('bundle toSeq does not match the last event');
  if (first && bundle.previousHead !== (first.seq === 0 ? null : first.previousEventHash)) {
    errors.push('bundle previousHead does not match the first event');
  }

  const recomputedContiguous =
    events.length > 0 && events.every((e, i) => i === 0 || e.previousEventHash === events[i - 1]!.eventHash);
  if (bundle.contiguous && !recomputedContiguous) {
    errors.push('bundle claims a contiguous slice but the event linkage is broken');
  }

  const exported: AuditExport = {
    tenantId: bundle.tenantId,
    generatedAt: bundle.generatedAt,
    fromSeq: bundle.fromSeq,
    toSeq: bundle.toSeq,
    events,
    head: bundle.head,
    previousHead: bundle.previousHead,
  };
  const authenticity: string[] = [];
  let bundleValid: boolean;
  if (bundle.contiguous && recomputedContiguous) {
    // Strong path: the slice is an unbroken chain — verify linkage + hashes +
    // signatures (and the anchor head) with the shared bundle verifier.
    const offline = verifyBundle(exported, {
      ...(options.publicKey ? { publicKey: options.publicKey } : {}),
      ...(options.anchorContent ? { anchorContent: options.anchorContent } : {}),
    });
    bundleValid = offline.valid;
    authenticity.push(...offline.errors.map((e) => `offline: ${e}`));
  } else {
    // Filtered view (global incident, or a tenant interleaved with other
    // tenants): linkage is absent by construction. Verify each event's hash
    // and signature, the recorded live-chain state, and the anchor head.
    for (const e of events) {
      if (eventHash(e) !== e.eventHash) authenticity.push(`seq ${e.seq}: event hash mismatch`);
      if (options.publicKey && (!e.signature || !verifyEventSignature(e, options.publicKey))) {
        authenticity.push(`seq ${e.seq}: signature verification failed`);
      }
    }
    if (options.anchorContent !== undefined && last && !options.anchorContent.includes(`${last.seq}:${last.eventHash}`)) {
      authenticity.push(`head hash ${last.seq}:${last.eventHash} not present in anchor content`);
    }
    bundleValid = authenticity.length === 0;
  }
  errors.push(...authenticity);
  return { valid: errors.length === 0, digestMatches, bundleValid, errors };
}

// ponytail: 1000-event page size (the M6 boundary). upgrade: cursor/stream if incident windows routinely exceed memory.
const PRESERVE_PAGE_SIZE = 1000;

/**
 * Sentinel tenant id for the global-incident evidence view: reads the events
 * recorded with `tenantId: ''` (scope `'global'` incidents belong to no
 * tenant), authorized by the caller's own audit.export capability.
 */
const GLOBAL_EVIDENCE_VIEW = '*';

export interface IncidentServiceDeps {
  readonly authorization: AuthorizationService;
  readonly sessions: SessionManager;
  readonly audit: AuditQueryService;
  readonly eventLog: EventStore;
  readonly channel: RevocationChannel;
  readonly clock?: () => number;
  /** Channel poll interval on the authorize path. Default 1000 ms (≤ 5 s target). */
  readonly syncIntervalMs?: number;
  /**
   * H2 (ADR-028): optional credential-revocation target. When wired,
   * `revokeToken` applies locally before broadcasting and incoming
   * `revoke-token` records revoke on this node's IdP too.
   */
  readonly identity?: TokenRevoker;
}

export class IncidentService {
  private readonly authorization: AuthorizationService;
  private readonly sessions: SessionManager;
  private readonly audit: AuditQueryService;
  private readonly eventLog: EventStore;
  private readonly channel: RevocationChannel;
  private readonly clock: () => number;
  private readonly syncIntervalMs: number;
  private readonly identity: TokenRevoker | undefined;
  private cursor = -1;
  private lastSyncAt = Number.NEGATIVE_INFINITY;
  private syncFailures = 0;
  private appliedRecords = 0;

  constructor(deps: IncidentServiceDeps) {
    this.authorization = deps.authorization;
    this.sessions = deps.sessions;
    this.audit = deps.audit;
    this.eventLog = deps.eventLog;
    this.channel = deps.channel;
    this.clock = deps.clock ?? Date.now;
    this.syncIntervalMs = deps.syncIntervalMs ?? 1_000;
    this.identity = deps.identity;
    // The PDP pulls this on every authorize (throttled) and issue (forced).
    this.authorization.setBroadcastSync((force) => {
      this.sync(force);
    }, this.syncIntervalMs);
  }

  private validate(input: IncidentActionInput): void {
    if (input.scope !== 'tenant' && input.scope !== 'global') {
      throw new IncidentInputError(`unknown incident scope: ${String(input.scope)}`);
    }
    if (input.scope === 'tenant' && (!input.tenantId || input.tenantId.trim() === '')) {
      throw new IncidentInputError('a tenant-scoped incident action requires a tenantId');
    }
    if (!input.reason || input.reason.trim() === '') {
      throw new IncidentInputError('an incident action requires a non-empty reason');
    }
    if (!input.actor || input.actor.trim() === '') {
      throw new IncidentInputError('an incident action requires a non-empty actor');
    }
  }

  /**
   * The kill switch: freeze + revoke everything in scope, locally first (an
   * unavailable channel must not block the emergency action), then broadcast,
   * then audit with the honest broadcast outcome.
   */
  engage(input: IncidentActionInput): IncidentActionResult {
    this.validate(input);
    const at = this.clock();
    // H15 (ADR-027): the kill switch completes even when the evidence store is
    // down. Freezing and revoking are narrowing actions - their state applies
    // before their events - so an evidence failure must not abort the local
    // enforcement. Missed evidence is reported (`evidenceRecorded: false`).
    let evidenceRecorded = true;
    try {
      this.authorization.freeze(input.scope, input.tenantId, input.reason, input.actor);
    } catch (error) {
      // freeze() only throws after applying state when its event fails; a
      // throw without the freeze applied is a real error.
      if (!this.authorization.isFrozen(input.tenantId ?? '')) throw error;
      evidenceRecorded = false;
    }
    const capabilitiesRevoked = this.authorization.revokeAll(input.scope, input.tenantId, input.reason);
    const sessionsRevoked =
      input.scope === 'global' ? this.sessions.revokeAll() : this.sessions.revokeAllForTenant(input.tenantId!);

    let broadcastOk = true;
    try {
      this.channel.publish({ action: 'freeze', scope: input.scope, ...(input.tenantId ? { tenantId: input.tenantId } : {}), reason: input.reason, at });
      this.channel.publish({ action: 'revoke-caps', scope: input.scope, ...(input.tenantId ? { tenantId: input.tenantId } : {}), reason: input.reason, at });
      this.channel.publish({ action: 'revoke-sessions', scope: input.scope, ...(input.tenantId ? { tenantId: input.tenantId } : {}), reason: input.reason, at });
    } catch {
      broadcastOk = false;
    }
    // Async backends report a failed write through health() rather than a throw.
    if (this.channel.health().errors > 0) broadcastOk = false;

    let eventSeq: number | undefined;
    try {
      const event = this.eventLog.append({
        tenantId: input.scope === 'global' ? '' : input.tenantId!,
        principal: input.actor,
        actor: input.actor,
        actorKind: 'authorization',
        action: 'incident.engage',
        resourceId: input.scope,
        decision: 'allow',
        result: 'success',
        metadata: {
          phase: 'incident-engage',
          scope: input.scope,
          tenantId: input.tenantId ?? null,
          reason: input.reason,
          capabilitiesRevoked,
          sessionsRevoked,
          broadcastOk,
        },
      });
      eventSeq = event.seq;
    } catch {
      evidenceRecorded = false;
    }
    return {
      scope: input.scope,
      ...(input.tenantId ? { tenantId: input.tenantId } : {}),
      frozen: this.authorization.isFrozen(input.tenantId ?? ''),
      capabilitiesRevoked,
      sessionsRevoked,
      broadcastOk,
      evidenceRecorded,
      ...(eventSeq !== undefined ? { eventSeq } : {}),
    };
  }

  /** Lift the freeze. Revoked capabilities and sessions stay revoked. */
  lift(input: IncidentActionInput): IncidentActionResult {
    this.validate(input);
    // H15 (ADR-027): unfreeze records its evidence before clearing the freeze;
    // a lift that cannot be recorded refuses (state stays frozen), so a store
    // outage can never silently widen authority.
    const existed = this.authorization.unfreeze(input.scope, input.tenantId, input.reason, input.actor);
    let broadcastOk = true;
    try {
      this.channel.publish({
        action: 'unfreeze',
        scope: input.scope,
        ...(input.tenantId ? { tenantId: input.tenantId } : {}),
        reason: input.reason,
        at: this.clock(),
      });
    } catch {
      broadcastOk = false;
    }
    let evidenceRecorded = true;
    let eventSeq: number | undefined;
    try {
      const event = this.eventLog.append({
        tenantId: input.scope === 'global' ? '' : input.tenantId!,
        principal: input.actor,
        actor: input.actor,
        actorKind: 'authorization',
        action: 'incident.lift',
        resourceId: input.scope,
        decision: 'allow',
        result: 'success',
        metadata: { phase: 'incident-lift', scope: input.scope, tenantId: input.tenantId ?? null, reason: input.reason, previouslyFrozen: existed, broadcastOk },
      });
      eventSeq = event.seq;
    } catch {
      // The unfreeze event itself was recorded before the state cleared; this
      // is only the aggregate bookkeeping event.
      evidenceRecorded = false;
    }
    return {
      scope: input.scope,
      ...(input.tenantId ? { tenantId: input.tenantId } : {}),
      frozen: this.authorization.isFrozen(input.tenantId ?? ''),
      capabilitiesRevoked: 0,
      sessionsRevoked: 0,
      broadcastOk,
      evidenceRecorded,
      ...(eventSeq !== undefined ? { eventSeq } : {}),
    };
  }

  /** Single-target capability revocation, local audit + broadcast. */
  revokeCapability(capabilityId: string, tenantId: string, reason: string): void {
    if (!capabilityId || !tenantId || !reason) throw new IncidentInputError('revokeCapability requires capabilityId, tenantId, and reason');
    // Tenant isolation (audit ticket 12): a locally registered target must
    // belong to the record's tenant. An unregistered target is allowed — the
    // operator CLI does not hold the node's capability registry.
    const target = this.authorization.get(capabilityId);
    if (target && target.tenantId !== tenantId) {
      throw new IncidentInputError(`capability ${capabilityId} belongs to tenant ${target.tenantId}, not ${tenantId}`);
    }
    this.authorization.revoke(capabilityId, reason);
    this.channel.publish({ action: 'revoke-cap', scope: 'tenant', tenantId, targetId: capabilityId, reason, at: this.clock() });
  }

  /** Single-target session revocation, local audit + broadcast. */
  revokeSession(sessionId: string, tenantId: string, reason: string): void {
    if (!sessionId || !tenantId || !reason) throw new IncidentInputError('revokeSession requires sessionId, tenantId, and reason');
    const at = this.clock();
    const revoked = this.sessions.revoke(sessionId);
    // The channel row is coordination data; the signed log is the evidence of
    // record (mirrors revokeCapability → authorization.revoke's audit event).
    this.eventLog.append({
      tenantId,
      principal: 'system',
      actor: 'system',
      actorKind: 'authorization',
      action: 'incident.revoke',
      resourceId: sessionId,
      decision: 'allow',
      result: 'success',
      metadata: { phase: 'incident-revoke-session', sessionId, tenantId, reason, revoked },
    });
    this.channel.publish({ action: 'revoke-session', scope: 'tenant', tenantId, targetId: sessionId, reason, at });
  }

  /**
   * H2 (ADR-028): single-target credential (jti) revocation. Local enforcement
   * first — an unavailable channel must not leave this node accepting a
   * revoked token — then the channel record, then evidence (the signed log is
   * the evidence of record; the channel row is coordination data). The record
   * applies deployment-wide: a `jti` has no tenant until principal resolution,
   * so `tenantId` is coordination/evidence metadata.
   */
  revokeToken(targetId: string, tenantId: string, reason: string, actor = 'system'): void {
    if (!targetId || !tenantId || !reason) throw new IncidentInputError('revokeToken requires tokenId, tenantId, and reason');
    const at = this.clock();
    this.identity?.revokeToken(targetId);
    this.eventLog.append({
      tenantId,
      principal: actor,
      actor,
      actorKind: 'authorization',
      action: 'incident.revoke',
      resourceId: targetId,
      decision: 'allow',
      result: 'success',
      metadata: { phase: 'incident-revoke-token', tokenId: targetId, tenantId, reason },
    });
    this.channel.publish({ action: 'revoke-token', scope: 'tenant', tenantId, targetId, reason, at });
  }

  /**
   * Pull revocation-channel records into local state. Throttled unless
   * forced; the cursor only moves forward, and replay from -1 (a fresh node)
   * reconstructs freeze state and revocations.
   */
  sync(force = false): IncidentSyncResult {
    const at = this.clock();
    if (!force && at - this.lastSyncAt < this.syncIntervalMs) {
      return { applied: 0, skipped: true, failures: this.syncFailures, cursor: this.cursor };
    }
    this.lastSyncAt = at;
    this.channel.refresh();
    let records: readonly RevocationRecord[];
    try {
      records = this.channel.since(this.cursor);
    } catch {
      this.syncFailures++;
      return { applied: 0, skipped: false, failures: this.syncFailures, cursor: this.cursor };
    }
    let applied = 0;
    for (const record of records) {
      this.applyRecord(record);
      this.cursor = record.seq;
      applied++;
    }
    this.appliedRecords += applied;
    return { applied, skipped: false, failures: this.syncFailures, cursor: this.cursor };
  }

  private applyRecord(record: RevocationRecord): void {
    switch (record.action) {
      case 'revoke-sessions':
        if (record.scope === 'global') this.sessions.revokeAll(record.at);
        else if (record.tenantId) this.sessions.revokeAllForTenant(record.tenantId, record.at);
        return;
      case 'revoke-session':
        if (record.targetId) this.sessions.revoke(record.targetId);
        return;
      case 'revoke-token':
        // H2 (ADR-028): idempotent with the IdentityProvider's own feed
        // consumption; this path matters on nodes whose incident sync runs
        // before the next verification.
        if (record.targetId) this.identity?.revokeToken(record.targetId);
        return;
      default:
        this.authorization.applyIncidentRecord(record);
    }
  }

  status(): IncidentStatus {
    const health = this.channel.health();
    return {
      freezes: this.authorization.freezeState(),
      frozen: this.authorization.freezeState().length > 0,
      revokedCapabilities: this.authorization.revokedCapabilities().length,
      channelCursor: this.channel.cursor(),
      syncCursor: this.cursor,
      appliedRecords: this.appliedRecords,
      syncFailures: this.syncFailures,
      channelErrors: health.errors,
      ...(health.lastError !== undefined ? { channelLastError: health.lastError } : {}),
    };
  }

  /** Await queued channel writes (async backends) before a process exits. */
  async flush(): Promise<void> {
    await this.channel.flush();
  }

  /**
   * Page the ordinary authorized audit export (removing the silent 1000-event
   * cap for incident windows) and verify the caller's authority once up front.
   * `tenantId: '*'` is the global-incident view over `tenantId: ''` events.
   */
  private exportWindow(principal: Principal, tenantId: string, fromSeq: number, toSeq: number): readonly SecurityEvent[] {
    if (tenantId === GLOBAL_EVIDENCE_VIEW) {
      const probe = this.audit.query(principal, { tenantId: principal.tenantId, fromSeq, toSeq, limit: 1 });
      if (probe.decision.decision !== 'allow') {
        throw new IncidentEvidenceError(
          `incident export denied (${probe.decision.denyReason ?? 'denied'}) — audit.export authority is required`,
        );
      }
      const events = this.eventLog.forTenant('').filter((e) => e.seq >= fromSeq && e.seq <= toSeq);
      if (events.length === 0) {
        throw new IncidentEvidenceError(`no global incident events in the requested window (seq ${fromSeq}..${toSeq})`);
      }
      return events;
    }
    const probe = this.audit.query(principal, { tenantId, fromSeq, toSeq, limit: 1 });
    if (probe.decision.decision !== 'allow') {
      throw new IncidentEvidenceError(
        `incident export denied (${probe.decision.denyReason ?? 'denied'}) — audit.export authority is required`,
      );
    }
    const events: SecurityEvent[] = [];
    let cursor = fromSeq;
    for (;;) {
      const page = this.audit.exportFor(principal, { tenantId, fromSeq: cursor, toSeq, limit: PRESERVE_PAGE_SIZE });
      if (page.events.length === 0) break;
      events.push(...page.events);
      cursor = page.toSeq + 1;
      if (page.events.length < PRESERVE_PAGE_SIZE) break;
    }
    if (events.length === 0) {
      throw new IncidentEvidenceError(`no events in the requested window (seq ${fromSeq}..${toSeq})`);
    }
    return events;
  }

  /**
   * Preserve an incident window as a verifiable artifact. The event log gets
   * one `incident.preserve` record with digest + head + counts only — never
   * event content.
   */
  preserve(input: PreservationInput): PreservationResult {
    if (!input.tenantId || !input.outPath) throw new IncidentEvidenceError('preserve requires tenantId and outPath');
    if (!Number.isInteger(input.fromSeq) || !Number.isInteger(input.toSeq) || input.fromSeq < 0 || input.toSeq < input.fromSeq) {
      throw new IncidentEvidenceError(`invalid incident window: seq ${input.fromSeq}..${input.toSeq}`);
    }
    const events = this.exportWindow(input.principal, input.tenantId, input.fromSeq, input.toSeq);
    const exported: AuditExport = {
      tenantId: input.tenantId,
      generatedAt: this.clock(),
      fromSeq: events[0]!.seq,
      toSeq: events.at(-1)!.seq,
      events,
      head: events.at(-1)!.eventHash,
      previousHead: events[0]!.seq === 0 ? null : events[0]!.previousEventHash,
    };
    const publicKey = eventPublicKey();
    const chain = this.eventLog.verify({ publicKey });
    const anchor = this.eventLog.anchor();
    const anchorMatch = anchor !== '' && anchor.includes(`${exported.toSeq}:${exported.head}`);
    const contiguous = exported.events.every((e, i) => i === 0 || e.previousEventHash === exported.events[i - 1]!.eventHash);
    const bundle: IncidentBundle = {
      type: 'asl-incident-bundle',
      version: 1,
      tenantId: exported.tenantId,
      requestedFromSeq: input.fromSeq,
      requestedToSeq: input.toSeq,
      fromSeq: exported.fromSeq,
      toSeq: exported.toSeq,
      generatedAt: exported.generatedAt,
      events: exported.events,
      head: exported.head,
      previousHead: exported.previousHead,
      contiguous,
      chainValid: chain.valid,
      anchorMatch,
      digest: '',
    };
    const withDigest: IncidentBundle = { ...bundle, digest: bundleDigest(bundle) };
    const verification = verifyIncidentBundle(withDigest, {
      publicKey,
      ...(anchor !== '' ? { anchorContent: anchor } : {}),
    });
    if (!verification.valid) {
      // The common cross-process failure is a key mismatch, not corruption:
      // without EVENT_SIGNING_*_PEM each process signs with its own ephemeral
      // key (events.ts), and a verifier in another process cannot check them.
      const keyHint =
        chain.detail === 'signature mismatch' && !process.env.EVENT_SIGNING_PUBLIC_KEY_PEM
          ? ' (event-signing key mismatch: set EVENT_SIGNING_PRIVATE_KEY_PEM + EVENT_SIGNING_PUBLIC_KEY_PEM on the signing node and in this process, or preserve in the signing process)'
          : '';
      throw new IncidentEvidenceError(`incident bundle failed verification: ${verification.errors.join('; ')}${keyHint}`);
    }
    mkdirSync(dirname(input.outPath), { recursive: true });
    writeFileSync(input.outPath, `${JSON.stringify(withDigest, null, 2)}\n`, 'utf8');

    const event = this.eventLog.append({
      // The global view records its preservation under the preserving tenant:
      // the evidence is the artifact; the event must stay retrievable.
      tenantId: input.tenantId === GLOBAL_EVIDENCE_VIEW ? input.principal.tenantId : input.tenantId,
      principal: input.principal.id,
      actor: input.principal.id,
      actorKind: input.principal.kind,
      action: 'incident.preserve',
      resourceId: `${exported.fromSeq}..${exported.toSeq}`,
      decision: 'allow',
      result: 'success',
      metadata: {
        phase: 'incident-preservation',
        requestedFromSeq: input.fromSeq,
        requestedToSeq: input.toSeq,
        fromSeq: exported.fromSeq,
        toSeq: exported.toSeq,
        events: exported.events.length,
        head: exported.head,
        digest: withDigest.digest,
        chainValid: chain.valid,
        anchorMatch,
      },
    });
    return {
      path: input.outPath,
      digest: withDigest.digest,
      events: exported.events.length,
      fromSeq: exported.fromSeq,
      toSeq: exported.toSeq,
      head: exported.head,
      chainValid: chain.valid,
      anchorMatch,
      eventSeq: event.seq,
    };
  }

  /** Reconstruct what happened over an authorized, tenant-scoped window. */
  reconstruct(input: ReconstructionInput): IncidentReport {
    const events = this.exportWindow(input.principal, input.tenantId, input.fromSeq, input.toSeq);
    const denyReasons: Record<string, number> = {};
    const actions: Record<string, number> = {};
    const actors = new Set<string>();
    let allow = 0;
    let deny = 0;
    let revocations = 0;
    let freezes = 0;
    let lifts = 0;
    for (const event of events) {
      actions[event.action] = (actions[event.action] ?? 0) + 1;
      actors.add(event.actor);
      if (event.decision === 'allow') allow++;
      if (event.decision === 'deny') {
        deny++;
        if (event.denyReason) denyReasons[event.denyReason] = (denyReasons[event.denyReason] ?? 0) + 1;
      }
      if (event.action === 'capability.revoke') revocations++;
      if (event.action === 'incident.freeze' || event.action === 'incident.engage') freezes++;
      if (event.action === 'incident.lift') lifts++;
    }
    return {
      tenantId: input.tenantId,
      requestedFromSeq: input.fromSeq,
      requestedToSeq: input.toSeq,
      events: events.length,
      decisions: { allow, deny },
      denyReasons,
      actions,
      revocations,
      freezes,
      lifts,
      actors: [...actors],
      firstAt: events[0]?.timestamp ?? null,
      lastAt: events.at(-1)?.timestamp ?? null,
      chainValid: this.eventLog.verify({ publicKey: eventPublicKey() }).valid,
    };
  }

  close(): void {
    this.channel.close();
  }
}
