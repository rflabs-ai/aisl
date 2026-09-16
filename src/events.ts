/**
 * Evidence plane: append-only, hash-chained, tamper-evident security events.
 *
 * Invariant 7: every decision (allow OR deny) produces an event.
 * Invariant 8: mutating, deleting, or reordering any event breaks `verify()`.
 */

import { createHash } from 'node:crypto';
import { DatabaseSync } from 'node:sqlite';
import {
  type Action,
  type Decision,
  type DenyReason,
  type PrincipalKind,
  canonicalJson,
} from './domain.ts';

export type EventResult = 'success' | 'denied' | 'error';

export interface SecurityEvent {
  readonly seq: number;
  readonly timestamp: number;
  readonly tenantId: string;
  readonly principal: string;
  readonly actor: string;
  readonly actorKind: PrincipalKind;
  readonly action: Action;
  readonly resourceId?: string;
  readonly decision?: Decision;
  readonly denyReason?: DenyReason;
  readonly policyId?: string;
  readonly capabilityId?: string;
  readonly result: EventResult;
  readonly metadata?: Readonly<Record<string, unknown>>;
  readonly previousEventHash: string;
  readonly eventHash: string;
}

export type EventInput = Omit<SecurityEvent, 'seq' | 'previousEventHash' | 'eventHash' | 'timestamp'> & {
  readonly timestamp?: number;
};

export const GENESIS_HASH = '0'.repeat(64);

export function eventHash(
  e: Omit<SecurityEvent, 'eventHash'>,
): string {
  const body = canonicalJson({
    seq: e.seq,
    timestamp: e.timestamp,
    tenantId: e.tenantId,
    principal: e.principal,
    actor: e.actor,
    actorKind: e.actorKind,
    action: e.action,
    resourceId: e.resourceId ?? null,
    decision: e.decision ?? null,
    denyReason: e.denyReason ?? null,
    policyId: e.policyId ?? null,
    capabilityId: e.capabilityId ?? null,
    result: e.result,
    metadata: e.metadata ?? null,
    previousEventHash: e.previousEventHash,
  });
  return createHash('sha256').update(body).digest('hex');
}

export interface ChainVerification {
  readonly valid: boolean;
  readonly count: number;
  readonly firstBrokenSeq?: number;
  readonly detail?: string;
}

export class EventLog {
  private readonly events: SecurityEvent[] = [];
  private readonly db?: DatabaseSync;
  private readonly insert?: ReturnType<DatabaseSync['prepare']>;

  constructor(sqlitePath?: string) {
    if (!sqlitePath) return;
    this.db = new DatabaseSync(sqlitePath);
    this.db.exec(`
      CREATE TABLE IF NOT EXISTS security_events (
        seq INTEGER PRIMARY KEY,
        tenant_id TEXT NOT NULL,
        timestamp INTEGER NOT NULL,
        event_hash TEXT NOT NULL,
        event TEXT NOT NULL
      );
    `);
    this.insert = this.db.prepare(
      'INSERT INTO security_events (seq, tenant_id, timestamp, event_hash, event) VALUES (?, ?, ?, ?, ?)',
    );
    this.resume();
  }

  /**
   * Rehydrate the chain so seq continues across restarts. A broken chain means
   * the store was edited or truncated mid-history: refuse to append rather than
   * extend something we can no longer vouch for.
   */
  private resume(): void {
    const rows = this.db!.prepare('SELECT event FROM security_events ORDER BY seq').all() as {
      event: string;
    }[];
    for (const row of rows) this.events.push(JSON.parse(row.event) as SecurityEvent);
    const check = this.verify();
    if (!check.valid) {
      this.db?.close();
      throw new Error(`evidence chain invalid at seq ${check.firstBrokenSeq} (${check.detail}): refusing to append`);
    }
  }

  append(input: EventInput): SecurityEvent {
    const previousEventHash = this.events.at(-1)?.eventHash ?? GENESIS_HASH;
    const partial = {
      ...input,
      seq: this.events.length,
      timestamp: input.timestamp ?? Date.now(), // ponytail: event timestamp at append time, not decision time. upgrade: pass decisionAt explicitly when events need sub-ms precision.
      previousEventHash,
    };
    const event: SecurityEvent = { ...partial, eventHash: eventHash(partial) };
    this.events.push(event);
    this.insert?.run(event.seq, event.tenantId, event.timestamp, event.eventHash, JSON.stringify(event));
    return event;
  }

  all(): readonly SecurityEvent[] {
    return [...this.events];
  }

  forTenant(tenantId: string): readonly SecurityEvent[] {
    return this.events.filter((e) => e.tenantId === tenantId);
  }

  verify(): ChainVerification {
    for (let i = 0; i < this.events.length; i++) {
      const e = this.events[i]!;
      const expectedPrev = i === 0 ? GENESIS_HASH : this.events[i - 1]!.eventHash;
      if (e.previousEventHash !== expectedPrev) {
        return { valid: false, count: this.events.length, firstBrokenSeq: e.seq, detail: 'previous hash mismatch' };
      }
      const { eventHash: _h, ...rest } = e;
      if (eventHash(rest) !== e.eventHash) {
        return { valid: false, count: this.events.length, firstBrokenSeq: e.seq, detail: 'event hash mismatch' };
      }
    }
    return { valid: true, count: this.events.length };
  }

  /** Portable evidence bundle for offline verification. */
  bundle(): string {
    return canonicalJson({
      algorithm: 'sha256-chain-v1',
      genesis: GENESIS_HASH,
      events: this.events,
      head: this.events.at(-1)?.eventHash ?? GENESIS_HASH,
    });
  }

  close(): void {
    this.db?.close();
  }
}
