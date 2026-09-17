/**
 * Postgres EventStore backend (ADR-018) — same public surface as EventLog.
 *
 * Raw SQL only, through the `postgres` driver: tagged templates are
 * parameterized by construction; migration DDL is static parameterless SQL
 * (no user input ever reaches SQL text). Migrations are forward-only,
 * versioned, and hash-recorded; a recorded id with a different hash is a
 * tamper signal and fails closed. Fail-closed (H15): a store that is not
 * open refuses to append — never a silent fallback to memory — and error
 * messages are redacted to the endpoint host, never the URL or credentials.
 */

import { createHash } from 'node:crypto';
import type { KeyObject } from 'node:crypto';
import postgres from 'postgres';
import {
  type AuditFilters,
  type AuditExport,
  type ChainVerification,
  type EventInput,
  type EventStore,
  type SecurityEvent,
  GENESIS_HASH,
  appendAnchorLine,
  bundleFromEvents,
  eventHash,
  exportFromEvents,
  filterEvents,
  readAnchor,
  signEventBody,
  verifyChain,
} from './events.ts';

type Sql = ReturnType<typeof postgres>;

export interface StoreMigration {
  readonly id: number;
  /** Exact SQL executed for this migration; sha256 of this text is recorded. */
  readonly sql: string;
}

/**
 * Ordered, forward-only migrations. New migrations append with a new id and
 * are never edited; a hash change on a recorded id is refused at connect.
 */
export const MIGRATIONS: readonly StoreMigration[] = [
  {
    id: 1,
    sql: `
      CREATE TABLE IF NOT EXISTS security_events(
        seq BIGINT PRIMARY KEY,
        tenant_id TEXT NOT NULL,
        timestamp BIGINT NOT NULL,
        event_hash TEXT NOT NULL,
        event TEXT NOT NULL
      );
      CREATE INDEX IF NOT EXISTS security_events_tenant_seq ON security_events (tenant_id, seq);
    `,
  },
];

interface AppliedMigration {
  readonly id: number;
  readonly hash: string;
}

export interface PostgresEventLogConfig {
  /** Runtime role connection (app_rw per ADR-018). Never logged, never stored. */
  readonly url: string;
  /** DDL-capable role connection (app_ddl). Omit when migrations are already applied. */
  readonly migrateUrl?: string;
  readonly anchorPath?: string;
}

function migrationHash(sql: string): string {
  return createHash('sha256').update(sql, 'utf8').digest('hex');
}

/** The URL is a secret: keep only the endpoint host for operator-visible errors. */
function endpointOf(url: string): string {
  try {
    return new URL(url).host;
  } catch {
    return 'unparsable-endpoint';
  }
}

function redactUrl(text: string): string {
  return text.replace(/postgres(?:ql)?:\/\/\S*/g, 'postgres://[redacted]');
}

/**
 * Explicit parse of a stored event row (trust boundary: the database is
 * adversarial data). Structural validation here; tamper detection comes from
 * the hash-chain verification that runs over the parsed objects.
 */
function parseStoredEvent(raw: string): SecurityEvent {
  let parsed: unknown;
  try {
    parsed = JSON.parse(raw);
  } catch {
    throw new Error('stored event is not valid JSON: refusing to load');
  }
  if (typeof parsed !== 'object' || parsed === null || Array.isArray(parsed)) {
    throw new Error('stored event is not an object: refusing to load');
  }
  const e = parsed as {
    seq?: unknown;
    timestamp?: unknown;
    tenantId?: unknown;
    principal?: unknown;
    actor?: unknown;
    actorKind?: unknown;
    action?: unknown;
    result?: unknown;
    previousEventHash?: unknown;
    eventHash?: unknown;
  };
  const shapeOk =
    typeof e.seq === 'number' &&
    typeof e.timestamp === 'number' &&
    typeof e.tenantId === 'string' &&
    typeof e.principal === 'string' &&
    typeof e.actor === 'string' &&
    typeof e.actorKind === 'string' &&
    typeof e.action === 'string' &&
    typeof e.result === 'string' &&
    typeof e.previousEventHash === 'string' &&
    typeof e.eventHash === 'string';
  if (!shapeOk) {
    throw new Error('stored event is malformed: refusing to load');
  }
  return e as SecurityEvent;
}

export class PostgresEventLog implements EventStore {
  private readonly events: SecurityEvent[] = [];
  private readonly sql: Sql;
  private readonly anchorPath?: string;
  /** Endpoint host only — the full URL is a secret and is never retained. */
  private readonly endpoint: string;
  private tail: Promise<void>;
  private isOpen = false;
  private failure = 'postgres event store is not open';

  constructor(config: PostgresEventLogConfig) {
    this.anchorPath = config.anchorPath;
    this.endpoint = endpointOf(config.url);
    this.sql = postgres(config.url);
    this.tail = this.connect(config);
    // The rejection is observed by consumers of whenReady(); keep an unobserved
    // tail from crashing the process on top of the controlled failure.
    this.tail.catch(() => {});
  }

  /** Resolves once migrations are verified/applied and the chain loads and verifies; rejects on any failure. */
  whenReady(): Promise<void> {
    return this.tail;
  }

  private async connect(config: PostgresEventLogConfig): Promise<void> {
    try {
      const applied = config.migrateUrl
        ? await this.runMigrations(postgres(config.migrateUrl))
        : await this.assertMigrationsApplied();
      await this.loadAndVerifyChain();
      this.isOpen = true;
      this.failure = 'postgres event store is not open';
      if (applied.length > 0) this.recordMigrationEvent(applied);
    } catch (error) {
      this.isOpen = false;
      const detail = redactUrl(error instanceof Error ? error.message : String(error));
      this.failure = `postgres event store unavailable (endpoint ${this.endpoint}): ${detail}`;
      await this.sql.end({ timeout: 1_000 }).catch(() => {});
      throw new Error(this.failure);
    }
  }

  /**
   * Forward-only migrations through the DDL-capable connection. An already
   * recorded id with the same hash is skipped; a different hash is tamper and
   * throws. No destructive step exists in this framework, ever.
   */
  private async runMigrations(ddl: Sql): Promise<readonly AppliedMigration[]> {
    try {
      await ddl`CREATE TABLE IF NOT EXISTS migrations(
        id INTEGER PRIMARY KEY,
        hash TEXT NOT NULL,
        applied_at TIMESTAMPTZ NOT NULL
      )`;
      const applied: AppliedMigration[] = [];
      for (const migration of MIGRATIONS) {
        const hash = migrationHash(migration.sql);
        const recorded = await ddl`SELECT hash FROM migrations WHERE id = ${migration.id}`;
        const existing = recorded[0]?.hash;
        if (existing !== undefined) {
          if (existing !== hash) {
            throw new Error(`migration ${migration.id} hash mismatch: recorded migration was modified (fail closed)`);
          }
          continue; // already applied, same hash
        }
        // Static DDL text, no parameters: parameterless query -> simple
        // protocol, which supports the multi-statement migration batch.
        await ddl.unsafe(migration.sql);
        await ddl`INSERT INTO migrations (id, hash, applied_at) VALUES (${migration.id}, ${hash}, now())`;
        applied.push({ id: migration.id, hash });
      }
      return applied;
    } finally {
      await ddl.end({ timeout: 1_000 }).catch(() => {});
    }
  }

  /** No migration role configured: the recorded schema must already match, or fail closed. */
  private async assertMigrationsApplied(): Promise<readonly AppliedMigration[]> {
    const recorded = await this.sql`SELECT id, hash FROM migrations`;
    const hashes = new Map<number, string>(recorded.map((r) => [r.id, r.hash]));
    for (const migration of MIGRATIONS) {
      const hash = hashes.get(migration.id);
      if (hash === undefined) {
        throw new Error(`migration ${migration.id} has not been applied: refusing to open (provide migrateUrl with a DDL-capable role)`);
      }
      if (hash !== migrationHash(migration.sql)) {
        throw new Error(`migration ${migration.id} hash mismatch: recorded migration was modified (fail closed)`);
      }
    }
    return [];
  }

  /** Mirror of EventLog.resume(): rehydrate, verify, refuse a broken chain. */
  private async loadAndVerifyChain(): Promise<void> {
    const rows = await this.sql`SELECT event FROM security_events ORDER BY seq`;
    const loaded: SecurityEvent[] = [];
    for (const row of rows) loaded.push(parseStoredEvent(row.event));
    const check = verifyChain(loaded);
    if (!check.valid) {
      throw new Error(`evidence chain invalid at seq ${check.firstBrokenSeq} (${check.detail}): refusing to append`);
    }
    this.events.push(...loaded);
  }

  private recordMigrationEvent(applied: readonly AppliedMigration[]): void {
    this.append({
      tenantId: '', // store-level event: not tenant-scoped
      principal: 'service:store-migrate',
      actor: 'service:store-migrate',
      actorKind: 'service',
      action: 'store.migrate',
      result: 'success',
      metadata: { phase: 'store-migrate', applied: applied.map((a) => ({ id: a.id, hash: a.hash })) },
    });
  }

  append(input: EventInput): SecurityEvent {
    if (!this.isOpen) throw new Error(`${this.failure}: refusing to append (fail closed)`);
    const previousEventHash = this.events.at(-1)?.eventHash ?? GENESIS_HASH;
    const partial: Omit<SecurityEvent, 'eventHash' | 'signature'> = {
      ...input,
      seq: this.events.length,
      timestamp: input.timestamp ?? Date.now(), // ponytail: event timestamp at append time, not decision time. upgrade: pass decisionAt explicitly when events need sub-ms precision.
      previousEventHash,
    };
    const event: SecurityEvent = {
      ...partial,
      eventHash: eventHash(partial),
      signature: signEventBody(partial),
    };
    this.events.push(event);
    if (this.anchorPath) appendAnchorLine(this.anchorPath, event);
    const next = this.tail.then(() => this.persist(event));
    next.catch((error) => {
      // A write that did not reach the database closes the store for further
      // appends: the next append (and every decision) fails closed.
      this.isOpen = false;
      const detail = redactUrl(error instanceof Error ? error.message : String(error));
      this.failure = `postgres event store write failed (endpoint ${this.endpoint}): ${detail}`;
    });
    this.tail = next;
    return event;
  }

  private async persist(event: SecurityEvent): Promise<void> {
    await this.sql`INSERT INTO security_events (seq, tenant_id, timestamp, event_hash, event) VALUES (${event.seq}, ${event.tenantId}, ${event.timestamp}, ${event.eventHash}, ${JSON.stringify(event)})`;
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
    // ponytail: reads serve from the rehydrated mirror — the EventStore port is
    // synchronous (EventLog's surface), so SQL-side filtering ((event::jsonb)
    // ->>'actor', LIMIT/OFFSET) needs an async port first. Upgrade: move reads
    // into SQL when chains outgrow memory or the reader role (Phase 2 RLS)
    // needs tenant-scoped server-side filtering.
    return filterEvents(this.events, filters);
  }

  exportFor(filters: AuditFilters): AuditExport {
    return exportFromEvents(this.query(filters), filters, Date.now());
  }

  verify(options: { publicKey?: KeyObject } = {}): ChainVerification {
    return verifyChain(this.events, options);
  }

  anchor(): string {
    return readAnchor(this.anchorPath);
  }

  bundle(): string {
    return bundleFromEvents(this.events);
  }

  close(): void {
    this.sql.end({ timeout: 5_000 }).catch(() => {});
  }
}
