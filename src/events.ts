/**
 * Evidence plane: append-only, hash-chained, tamper-evident security events.
 *
 * Invariant 7: every decision (allow OR deny) produces an event.
 * Invariant 8: mutating, deleting, or reordering any event breaks `verify()`.
 * M3: each event is also Ed25519-signed, and the head hash is anchored to an
 * external append-only file so an attacker with host access must rewrite both
 * consistently.
 */

import {
  createHash,
  generateKeyPairSync,
  sign as cryptoSign,
  verify as cryptoVerify,
  createPrivateKey,
  createPublicKey,
  type KeyObject,
} from 'node:crypto';
import { appendFileSync, existsSync, mkdirSync, readFileSync } from 'node:fs';
import { dirname } from 'node:path';
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
  readonly signature?: string;
}

export interface AuditFilters {
  readonly tenantId: string;          // required; tenant-scoped
  readonly fromSeq?: number;          // inclusive
  readonly toSeq?: number;            // inclusive
  readonly fromTime?: number;         // ms epoch, inclusive
  readonly toTime?: number;           // ms epoch, exclusive
  readonly actor?: string;            // exact match
  readonly action?: Action | '*';     // exact or '*'
  readonly decision?: 'allow' | 'deny';
  readonly resourceId?: string;       // exact match
  readonly limit?: number;            // default 100, max 1000
  readonly offset?: number;           // default 0
}

export interface AuditExport {
  readonly tenantId: string;
  readonly generatedAt: number;
  /** seq of the first event actually returned (a result bound, not the requested filter bound). */
  readonly fromSeq: number;
  /** seq of the last event actually returned (a result bound, not the requested filter bound). */
  readonly toSeq: number;
  readonly events: readonly SecurityEvent[];  // includes signature + eventHash
  readonly head: string;                        // eventHash of the last event in events
  readonly previousHead: string | null;         // eventHash of the event preceding the first returned event; null when the slice starts at seq 0
}

export type EventInput = Omit<SecurityEvent, 'seq' | 'previousEventHash' | 'eventHash' | 'timestamp' | 'signature'> & {
  readonly timestamp?: number;
};

export const GENESIS_HASH = '0'.repeat(64);

/**
 * H15 fail-closed signal: the event store cannot accept writes because it is
 * unreachable, unmigrated, or a prior write failed — the store is DOWN, not
 * merely slow. Thrown by PostgresEventLog.append; the PDP maps it to the
 * distinct `denyReason: 'store-unavailable'` so an outage is operator-
 * distinguishable from a policy denial or a generic write failure. EventLog
 * (SQLite/in-memory) never throws this class — its failures stay
 * `evidence-write-failure`.
 */
export class StoreUnavailableError extends Error {}

/**
 * The evidence-plane port (ADR-018): exactly the public surface of EventLog.
 * Two implementations: EventLog (SQLite + in-memory, the default for
 * single-node, on-prem, air-gapped, and every run without DATABASE_URL) and
 * PostgresEventLog (src/event-store-pg.ts). Consumers that only need the port
 * are typed against this interface, never the concrete class.
 */
export interface EventStore {
  append(input: EventInput): SecurityEvent;
  all(): readonly SecurityEvent[];
  forTenant(tenantId: string): readonly SecurityEvent[];
  query(filters: AuditFilters): readonly SecurityEvent[];
  exportFor(filters: AuditFilters): AuditExport;
  verify(options?: { publicKey?: KeyObject }): ChainVerification;
  bundle(): string;
  anchor(): string;
  close(): void;
}

/** Append one `<seq>:<eventHash>` line to the anchor file (M3 format). */
export function appendAnchorLine(anchorPath: string, event: SecurityEvent): void {
  const dir = dirname(anchorPath);
  if (dir && dir !== '.' && !existsSync(dir)) mkdirSync(dir, { recursive: true });
  appendFileSync(anchorPath, `${event.seq}:${event.eventHash}\n`, 'utf8');
}

/** Read the full anchor file content. Empty string when unconfigured or absent. */
export function readAnchor(anchorPath?: string): string {
  if (!anchorPath) return '';
  if (!existsSync(anchorPath)) return '';
  return readFileSync(anchorPath, 'utf8');
}

/**
 * In-memory filter semantics shared by both EventStore backends: tenant is
 * required, seq/time bounds are inclusive/exclusive as documented, and the
 * limit clamp (default 100, max 1000) matches the SQLite query path.
 */
export function filterEvents(
  events: readonly SecurityEvent[],
  filters: AuditFilters,
): readonly SecurityEvent[] {
  let matches = events.filter((e) => e.tenantId === filters.tenantId);
  if (filters.fromSeq !== undefined) matches = matches.filter((e) => e.seq >= filters.fromSeq!);
  if (filters.toSeq !== undefined) matches = matches.filter((e) => e.seq <= filters.toSeq!);
  if (filters.fromTime !== undefined) matches = matches.filter((e) => e.timestamp >= filters.fromTime!);
  if (filters.toTime !== undefined) matches = matches.filter((e) => e.timestamp < filters.toTime!);
  if (filters.actor !== undefined) matches = matches.filter((e) => e.actor === filters.actor);
  if (filters.action !== undefined && filters.action !== '*') matches = matches.filter((e) => e.action === filters.action);
  if (filters.decision !== undefined) matches = matches.filter((e) => e.decision === filters.decision);
  if (filters.resourceId !== undefined) matches = matches.filter((e) => e.resourceId === filters.resourceId);
  const limit = Math.min(filters.limit ?? 100, 1000);
  const offset = filters.offset ?? 0;
  return matches.slice(offset, offset + limit);
}

/** Build the portable export shape from a filtered event slice. */
export function exportFromEvents(
  events: readonly SecurityEvent[],
  filters: AuditFilters,
  generatedAt: number,
): AuditExport {
  if (events.length === 0) {
    return {
      tenantId: filters.tenantId,
      generatedAt,
      fromSeq: filters.fromSeq ?? 0,
      toSeq: filters.toSeq ?? 0,
      events: [],
      head: '',
      previousHead: null,
    };
  }
  const fromSeq = events[0]!.seq;
  const toSeq = events.at(-1)!.seq;
  const head = events.at(-1)!.eventHash;
  const previousHead = events[0]!.seq === 0 ? null : events[0]!.previousEventHash;
  return {
    tenantId: filters.tenantId,
    generatedAt,
    fromSeq,
    toSeq,
    events,
    head,
    previousHead,
  };
}

/** Recompute the whole hash chain (and signatures when a public key is given). */
export function verifyChain(
  events: readonly SecurityEvent[],
  options: { publicKey?: KeyObject } = {},
): ChainVerification {
  for (let i = 0; i < events.length; i++) {
    const e = events[i]!;
    const expectedPrev = i === 0 ? GENESIS_HASH : events[i - 1]!.eventHash;
    if (e.previousEventHash !== expectedPrev) {
      return { valid: false, count: events.length, firstBrokenSeq: e.seq, detail: 'previous hash mismatch' };
    }
    const body: Omit<SecurityEvent, 'eventHash' | 'signature'> = {
      seq: e.seq,
      timestamp: e.timestamp,
      tenantId: e.tenantId,
      principal: e.principal,
      actor: e.actor,
      actorKind: e.actorKind,
      action: e.action,
      resourceId: e.resourceId,
      decision: e.decision,
      denyReason: e.denyReason,
      policyId: e.policyId,
      capabilityId: e.capabilityId,
      result: e.result,
      metadata: e.metadata,
      previousEventHash: e.previousEventHash,
    };
    if (eventHash(body) !== e.eventHash) {
      return { valid: false, count: events.length, firstBrokenSeq: e.seq, detail: 'event hash mismatch' };
    }
    if (options.publicKey) {
      if (!e.signature) {
        return { valid: false, count: events.length, firstBrokenSeq: e.seq, detail: 'missing signature' };
      }
      if (!verifyEventSignature(e, options.publicKey)) {
        return { valid: false, count: events.length, firstBrokenSeq: e.seq, detail: 'signature mismatch' };
      }
    }
  }
  return { valid: true, count: events.length };
}

/** Portable evidence bundle for offline verification, from a full event list. */
export function bundleFromEvents(events: readonly SecurityEvent[]): string {
  return canonicalJson({
    algorithm: 'sha256-chain-ed25519-v1',
    genesis: GENESIS_HASH,
    events,
    head: events.at(-1)?.eventHash ?? GENESIS_HASH,
  });
}

/**
 * Canonical body used for hashing AND signing. Both must cover the same bytes
 * so a verifier can independently recompute both and detect any tamper.
 */
export function eventBody(e: Omit<SecurityEvent, 'eventHash' | 'signature'>): Record<string, unknown> {
  return {
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
  };
}

export function eventHash(
  e: Omit<SecurityEvent, 'eventHash' | 'signature'>,
): string {
  return createHash('sha256').update(canonicalJson(eventBody(e))).digest('hex');
}

function signatureBody(e: Omit<SecurityEvent, 'eventHash' | 'signature'>): Buffer {
  return Buffer.from(canonicalJson(eventBody(e)), 'utf8');
}

export interface ChainVerification {
  readonly valid: boolean;
  readonly count: number;
  readonly firstBrokenSeq?: number;
  readonly detail?: string;
}

export interface SigningKeyPair {
  readonly privateKey: KeyObject;
  readonly publicKey: KeyObject;
}

/**
 * Ed25519 signing key for events. Separate from the HMAC capability signing
 * key (ADR-002) so a leak of one does not break the other. Generated lazily
 * with a public-key fingerprint exposed for export.
 *
 * Production: supply `EVENT_SIGNING_PRIVATE_KEY_PEM` (PKCS8 PEM) plus
 * `EVENT_SIGNING_PUBLIC_KEY_PEM` for verification. Without it we generate an
 * ephemeral key per process — events are still signed, but the key is lost
 * across restarts (same caveat as capability signing, documented in ADR-002).
 *
 * ponytail: ephemeral-per-process key is fine for MVP. Cross-process
 * verification requires the operator to set the PEM env vars or wire HSM
 * custody (HARD stage).
 */
let cachedSigning: SigningKeyPair | undefined;
let cachedPublicKey: KeyObject | undefined;

export function eventSigningKeyPair(): SigningKeyPair {
  if (cachedSigning) return cachedSigning;
  const privPem = process.env.EVENT_SIGNING_PRIVATE_KEY_PEM;
  const pubPem = process.env.EVENT_SIGNING_PUBLIC_KEY_PEM;
  if (privPem && pubPem) {
    cachedSigning = {
      privateKey: createPrivateKey(privPem),
      publicKey: createPublicKey(pubPem),
    };
    return cachedSigning;
  }
  const generated = generateKeyPairSync('ed25519');
  cachedSigning = generated;
  process.emitWarning?.(
    'EVENT_SIGNING_*_PEM unset: using ephemeral Ed25519 event signing key (not durable across restarts)',
  );
  return generated;
}

export function eventPublicKey(): KeyObject {
  if (cachedPublicKey) return cachedPublicKey;
  cachedPublicKey = eventSigningKeyPair().publicKey;
  return cachedPublicKey;
}

export function signEventBody(
  e: Omit<SecurityEvent, 'eventHash' | 'signature'>,
): string {
  const sig = cryptoSign(null, signatureBody(e), eventSigningKeyPair().privateKey);
  return sig.toString('base64');
}

export function verifyEventSignature(
  e: Pick<SecurityEvent, 'seq' | 'timestamp' | 'tenantId' | 'principal' | 'actor' | 'actorKind' | 'action' | 'resourceId' | 'decision' | 'denyReason' | 'policyId' | 'capabilityId' | 'result' | 'metadata' | 'previousEventHash' | 'signature'>,
  publicKey: KeyObject,
): boolean {
  if (!e.signature) return false;
  const body: Omit<SecurityEvent, 'eventHash' | 'signature'> = {
    seq: e.seq,
    timestamp: e.timestamp,
    tenantId: e.tenantId,
    principal: e.principal,
    actor: e.actor,
    actorKind: e.actorKind,
    action: e.action,
    resourceId: e.resourceId,
    decision: e.decision,
    denyReason: e.denyReason,
    policyId: e.policyId,
    capabilityId: e.capabilityId,
    result: e.result,
    metadata: e.metadata,
    previousEventHash: e.previousEventHash,
  };
  let sigBuf: Buffer;
  try {
    sigBuf = Buffer.from(e.signature, 'base64');
  } catch {
    return false;
  }
  return cryptoVerify(null, signatureBody(body), publicKey, sigBuf);
}

export class EventLog implements EventStore {
  private readonly events: SecurityEvent[] = [];
  private readonly db?: DatabaseSync;
  private readonly insert?: ReturnType<DatabaseSync['prepare']>;
  private readonly anchorPath?: string;

  constructor(sqlitePath?: string, options: { anchorPath?: string } = {}) {
    if (options.anchorPath) this.anchorPath = options.anchorPath;
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
      CREATE INDEX IF NOT EXISTS idx_security_events_tenant_seq ON security_events (tenant_id, seq);
    `);
    // M3: append-only enforcement. Any UPDATE or DELETE on security_events
    // raises — including a direct sqlite3 exec from a script. The runtime
    // has no update() or delete() method by design.
    this.db.exec(`
      CREATE TRIGGER IF NOT EXISTS security_events_no_update
      BEFORE UPDATE ON security_events
      BEGIN
        SELECT RAISE(ABORT, 'security_events is append-only');
      END;
      CREATE TRIGGER IF NOT EXISTS security_events_no_delete
      BEFORE DELETE ON security_events
      BEGIN
        SELECT RAISE(ABORT, 'security_events is append-only');
      END;
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
    const partial: Omit<SecurityEvent, 'eventHash' | 'signature'> = {
      ...input,
      seq: this.events.length,
      timestamp: input.timestamp ?? Date.now(), // ponytail: event timestamp at append time, not decision time. upgrade: pass decisionAt explicitly when events need sub-ms precision.
      previousEventHash,
    };
    const signature = signEventBody(partial);
    const eventHashValue = eventHash(partial);
    const event: SecurityEvent = { ...partial, eventHash: eventHashValue, signature };
    this.events.push(event);
    this.insert?.run(event.seq, event.tenantId, event.timestamp, event.eventHash, JSON.stringify(event));
    if (this.anchorPath) this.appendAnchor(event);
    return event;
  }

  /**
   * Append one line to the anchor file. Format: `<seq>:<eventHash>\n`.
   * The file is a simple external witness — an attacker with host access can
   * rewrite both the SQLite store and this file, but doing so consistently
   * requires knowing the entire chain up to the truncation point.
   *
   * ponytail: per-append `appendFileSync` is fine at low write volume. If
   * throughput grows, batch writes (one flush every N appends or T ms) —
   * the worst case is losing the most recent un-flushed anchor line.
   */
  private appendAnchor(event: SecurityEvent): void {
    appendAnchorLine(this.anchorPath!, event);
  }

  all(): readonly SecurityEvent[] {
    return [...this.events];
  }

  forTenant(tenantId: string): readonly SecurityEvent[] {
    return this.events.filter((e) => e.tenantId === tenantId);
  }

  query(filters: AuditFilters): readonly SecurityEvent[] {
    if (!filters.tenantId || typeof filters.tenantId !== 'string' || filters.tenantId.trim() === '') {
      throw new Error('tenantId is required for audit query');
    }

    if (this.db) {
      const conditions: string[] = ['tenant_id = ?'];
      const params: (string | number)[] = [filters.tenantId];

      if (filters.fromSeq !== undefined) {
        conditions.push('seq >= ?');
        params.push(filters.fromSeq);
      }
      if (filters.toSeq !== undefined) {
        conditions.push('seq <= ?');
        params.push(filters.toSeq);
      }
      if (filters.fromTime !== undefined) {
        conditions.push('timestamp >= ?');
        params.push(filters.fromTime);
      }
      if (filters.toTime !== undefined) {
        conditions.push('timestamp < ?');
        params.push(filters.toTime);
      }
      if (filters.actor !== undefined) {
        conditions.push("json_extract(event, '$.actor') = ?");
        params.push(filters.actor);
      }
      if (filters.action !== undefined && filters.action !== '*') {
        conditions.push("json_extract(event, '$.action') = ?");
        params.push(filters.action);
      }
      if (filters.decision !== undefined) {
        conditions.push("json_extract(event, '$.decision') = ?");
        params.push(filters.decision);
      }
      if (filters.resourceId !== undefined) {
        conditions.push("json_extract(event, '$.resourceId') = ?");
        params.push(filters.resourceId);
      }

      const limit = Math.min(filters.limit ?? 100, 1000);
      const offset = filters.offset ?? 0;
      params.push(limit, offset);

      const sql = `SELECT event FROM security_events WHERE ${conditions.join(' AND ')} ORDER BY seq ASC LIMIT ? OFFSET ?`;
      const rows = this.db.prepare(sql).all(...params) as { event: string }[];
      return rows.map((r) => JSON.parse(r.event) as SecurityEvent);
    }

    return filterEvents(this.events, filters);
  }

  exportFor(filters: AuditFilters): AuditExport {
    return exportFromEvents(this.query(filters), filters, Date.now());
  }

  verify(options: { publicKey?: KeyObject } = {}): ChainVerification {
    return verifyChain(this.events, options);
  }

  /** Read the full anchor file content. Returns empty string if no anchor configured. */
  anchor(): string {
    return readAnchor(this.anchorPath);
  }

  /** Portable evidence bundle for offline verification. */
  bundle(): string {
    return bundleFromEvents(this.events);
  }

  close(): void {
    this.db?.close();
  }
}

export interface VerificationResult {
  readonly valid: boolean;
  readonly eventCount: number;
  readonly signatureValid: boolean;
  readonly anchorMatch: boolean;
  readonly errors: readonly string[];
}

/**
 * Offline verifier. Operates entirely on an exported bundle + optional anchor
 * content + optional public key. No database access.
 */
export function verifyBundle(
  bundleJson: string | AuditExport | readonly SecurityEvent[],
  options: { anchorContent?: string; publicKey?: KeyObject } = {},
): VerificationResult {
  const errors: string[] = [];
  let parsed: { algorithm?: string; genesis?: string; previousHead?: string | null; events?: SecurityEvent[]; head?: string };
  if (typeof bundleJson === 'string') {
    try {
      parsed = JSON.parse(bundleJson) as typeof parsed;
    } catch (e) {
      return { valid: false, eventCount: 0, signatureValid: false, anchorMatch: false, errors: [`bundle is not valid JSON: ${(e as Error).message}`] };
    }
  } else if (Array.isArray(bundleJson)) {
    parsed = {
      events: bundleJson as SecurityEvent[],
      genesis: bundleJson[0]?.previousEventHash ?? GENESIS_HASH,
      head: bundleJson.at(-1)?.eventHash,
    };
  } else {
    const exp = bundleJson as AuditExport;
    parsed = {
      events: exp.events as SecurityEvent[],
      genesis: exp.previousHead ?? GENESIS_HASH,
      head: exp.head,
    };
  }
  const events = parsed.events ?? [];
  if (events.length === 0) {
    return { valid: false, eventCount: 0, signatureValid: false, anchorMatch: false, errors: ['bundle contains no events'] };
  }

  let prev = parsed.genesis ?? (parsed.previousHead !== undefined && parsed.previousHead !== null ? parsed.previousHead : GENESIS_HASH);
  let signatureValid = true;
  let signatureChecked = options.publicKey !== undefined;
  for (const e of events) {
    if (e.previousEventHash !== prev) {
      errors.push(`seq ${e.seq}: previousEventHash does not match expected predecessor`);
      return { valid: false, eventCount: events.length, signatureValid: false, anchorMatch: false, errors };
    }
    const body: Omit<SecurityEvent, 'eventHash' | 'signature'> = {
      seq: e.seq,
      timestamp: e.timestamp,
      tenantId: e.tenantId,
      principal: e.principal,
      actor: e.actor,
      actorKind: e.actorKind,
      action: e.action,
      resourceId: e.resourceId,
      decision: e.decision,
      denyReason: e.denyReason,
      policyId: e.policyId,
      capabilityId: e.capabilityId,
      result: e.result,
      metadata: e.metadata,
      previousEventHash: e.previousEventHash,
    };
    const recomputed = eventHash(body);
    if (recomputed !== e.eventHash) {
      errors.push(`seq ${e.seq}: eventHash recomputation mismatch`);
      return { valid: false, eventCount: events.length, signatureValid: false, anchorMatch: false, errors };
    }
    if (options.publicKey) {
      if (!e.signature || !verifyEventSignature(e, options.publicKey)) {
        signatureValid = false;
        errors.push(`seq ${e.seq}: signature verification failed`);
      }
    }
    prev = e.eventHash;
  }

  const last = events.at(-1)!;
  if (parsed.head !== undefined && parsed.head !== last.eventHash) {
    errors.push(`bundle head ${parsed.head} does not match last event hash ${last.eventHash}: tail truncation suspected`);
    return { valid: false, eventCount: events.length, signatureValid: signatureChecked ? signatureValid : true, anchorMatch: false, errors };
  }

  let anchorMatch = true;
  if (options.anchorContent !== undefined) {
    if (!options.anchorContent.includes(`${last.seq}:${last.eventHash}`)) {
      anchorMatch = false;
      errors.push(`head hash ${last.seq}:${last.eventHash} not present in anchor content`);
    }
  }

  return {
    valid: errors.length === 0,
    eventCount: events.length,
    signatureValid: signatureChecked ? signatureValid : true,
    anchorMatch,
    errors,
  };
}
