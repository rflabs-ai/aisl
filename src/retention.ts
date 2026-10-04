/**
 * H11 (ADR-031): evidence retention and legal holds.
 *
 * Retention is structural — the event store has no update or delete path at
 * any layer (API surface, SQLite triggers, Postgres triggers). A legal hold is
 * therefore not a lock on a delete operation; it is a *signed fact*: an
 * `evidence.hold` event in the append-only log marking a tenant/seq range that
 * must be kept. `RetentionLedger` replays those events (durable by
 * construction, restart-safe) and answers `isHeld()`. Any future
 * prune/archive-purge tool must consult this ledger; today no such tool
 * exists, and the structural tests are the enforcement.
 *
 * Trust boundary: the ledger writes operator events through the ordinary
 * store; a principal may only hold/release ranges in its OWN tenant (H8
 * posture — a cross-tenant hold is refused before any event append).
 */

import type { Principal } from './domain.ts';
import type { EventStore } from './events.ts';

export class RetentionError extends Error {}

export interface HoldInput {
  readonly tenantId: string;
  /** Inclusive first seq; defaults to 0 (whole chain). */
  readonly fromSeq?: number;
  /** Inclusive last seq; defaults to the whole chain. */
  readonly toSeq?: number;
  readonly reason: string;
}

export interface ReleaseInput {
  /** The `eventSeq` of the hold event being released. */
  readonly holdSeq: number;
  readonly reason: string;
}

export interface EvidenceHold {
  /** The event seq that recorded the hold (the ledger's stable id). */
  readonly eventSeq: number;
  readonly tenantId: string;
  readonly fromSeq: number;
  readonly toSeq: number;
  readonly reason: string;
  readonly actor: string;
  readonly at: number;
  /** Set once an `evidence.release` event lifted this hold. */
  readonly releasedBySeq?: number;
}

export interface RetentionStatus {
  readonly holds: number;
  readonly active: number;
  readonly tenants: readonly string[];
}

const WHOLE_CHAIN = Number.MAX_SAFE_INTEGER;

function requireSeq(value: number | undefined, field: string, fallback: number): number {
  if (value === undefined) return fallback;
  if (!Number.isSafeInteger(value) || value < 0) throw new RetentionError(`hold ${field} must be a non-negative integer`);
  return value;
}

export class RetentionLedger {
  private readonly store: EventStore;
  private readonly holds = new Map<number, EvidenceHold>();

  constructor(store: EventStore) {
    this.store = store;
    this.rehydrate();
  }

  /**
   * Record a legal hold. The event is signed and chained like any other
   * evidence; its `eventSeq` identifies the hold for release.
   */
  hold(principal: Principal, input: HoldInput): EvidenceHold {
    const tenantId = input.tenantId.trim();
    if (!tenantId) throw new RetentionError('hold requires a tenantId');
    if (principal.tenantId !== tenantId) {
      throw new RetentionError('a principal may only hold evidence in its own tenant');
    }
    const reason = input.reason.trim();
    if (!reason) throw new RetentionError('hold requires a reason');
    const fromSeq = requireSeq(input.fromSeq, 'fromSeq', 0);
    const toSeq = requireSeq(input.toSeq, 'toSeq', WHOLE_CHAIN);
    if (fromSeq > toSeq) throw new RetentionError(`hold range is empty (fromSeq ${fromSeq} > toSeq ${toSeq})`);

    const event = this.store.append({
      tenantId,
      principal: principal.id,
      actor: principal.id,
      actorKind: principal.kind,
      action: 'evidence.hold',
      resourceId: `audit-log:${tenantId}`,
      decision: 'allow',
      result: 'success',
      metadata: { phase: 'retention', fromSeq, toSeq, reason },
    });
    const hold: EvidenceHold = {
      eventSeq: event.seq,
      tenantId,
      fromSeq,
      toSeq,
      reason,
      actor: principal.id,
      at: event.timestamp,
    };
    this.holds.set(event.seq, hold);
    return hold;
  }

  /** Lift a hold by its event seq. A released or unknown hold is refused (fail closed). */
  release(principal: Principal, input: ReleaseInput): EvidenceHold {
    const hold = this.holds.get(input.holdSeq);
    if (!hold) throw new RetentionError(`unknown hold ${input.holdSeq}`);
    if (hold.releasedBySeq !== undefined) throw new RetentionError(`hold ${input.holdSeq} is not active (already released)`);
    if (principal.tenantId !== hold.tenantId) {
      throw new RetentionError('a principal may only release a hold in its own tenant');
    }
    const reason = input.reason.trim();
    if (!reason) throw new RetentionError('release requires a reason');

    const event = this.store.append({
      tenantId: hold.tenantId,
      principal: principal.id,
      actor: principal.id,
      actorKind: principal.kind,
      action: 'evidence.release',
      resourceId: `audit-log:${hold.tenantId}`,
      decision: 'allow',
      result: 'success',
      metadata: { phase: 'retention', holdSeq: hold.eventSeq, fromSeq: hold.fromSeq, toSeq: hold.toSeq, reason },
    });
    const updated: EvidenceHold = { ...hold, releasedBySeq: event.seq };
    this.holds.set(hold.eventSeq, updated);
    return updated;
  }

  activeHolds(tenantId?: string): readonly EvidenceHold[] {
    return [...this.holds.values()].filter(
      (hold) => hold.releasedBySeq === undefined && (tenantId === undefined || hold.tenantId === tenantId),
    );
  }

  /** True when any active hold covers `seq` for the tenant (range inclusive). */
  isHeld(tenantId: string, seq: number): boolean {
    return this.activeHolds(tenantId).some((hold) => seq >= hold.fromSeq && seq <= hold.toSeq);
  }

  status(): RetentionStatus {
    const active = this.activeHolds();
    return {
      holds: this.holds.size,
      active: active.length,
      tenants: [...new Set(active.map((hold) => hold.tenantId))].sort(),
    };
  }

  /**
   * Rebuild active holds from the event log. Release events are matched by the
   * hold event seq they name; an orphan release (no hold event) is ignored —
   * it stays in the log as evidence but changes nothing.
   */
  private rehydrate(): void {
    for (const event of this.store.all()) {
      if (event.action === 'evidence.hold') {
        const fromSeq = typeof event.metadata?.fromSeq === 'number' ? event.metadata.fromSeq : 0;
        const toSeq = typeof event.metadata?.toSeq === 'number' ? event.metadata.toSeq : WHOLE_CHAIN;
        const reason = typeof event.metadata?.reason === 'string' ? event.metadata.reason : '';
        this.holds.set(event.seq, {
          eventSeq: event.seq,
          tenantId: event.tenantId,
          fromSeq,
          toSeq,
          reason,
          actor: event.actor,
          at: event.timestamp,
        });
      } else if (event.action === 'evidence.release') {
        const holdSeq = event.metadata?.holdSeq;
        if (typeof holdSeq !== 'number') continue;
        const hold = this.holds.get(holdSeq);
        if (hold) this.holds.set(holdSeq, { ...hold, releasedBySeq: event.seq });
      }
    }
  }
}