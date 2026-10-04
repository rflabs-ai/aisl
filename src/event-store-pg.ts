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
import { RLS_MIGRATION } from './tenant-rls.ts';
import { PERSISTENCE_MIGRATION } from './persistence.ts';
import { INCIDENT_MIGRATION } from './incident-store-pg.ts';
import {
  type AuditFilters,
  type AuditExport,
  type ChainVerification,
  type EventInput,
  type EventStore,
  type SecurityEvent,
  GENESIS_HASH,
  StoreUnavailableError,
  appendAnchorLine,
  bundleFromEvents,
  eventHash,
  exportFromEvents,
  filterEvents,
  readAnchor,
  signEventBody,
  verifyChain,
} from './events.ts';
// Type-only: sink port implemented in src/anchors.ts (H11, ADR-031).
import type { AnchorPoint, AnchorSink } from './anchors.ts';

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
  // ADR-018 phase 2: database-enforced tenant isolation on the evidence
  // table (deny-by-default per-role policies, append-only triggers), wired
  // from src/tenant-rls.ts so RLS owns its own DDL.
  RLS_MIGRATION,
  // ADR-018 phase 2: control-plane state tables (persistence + their RLS),
  // wired from src/persistence.ts.
  PERSISTENCE_MIGRATION,
  // ADR-026 (H13): the multi-writer revocation channel, wired from
  // src/incident-store-pg.ts.
  INCIDENT_MIGRATION,
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
  /** H11: external anchor sinks (HTTP witnesses, extra file witnesses). */
  readonly sinks?: readonly AnchorSink[];
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
  private readonly anchorSinks: readonly AnchorSink[];
  /** Endpoint host only — the full URL is a secret and is never retained. */
  private readonly endpoint: string;
  private tail: Promise<void>;
  private state: 'connecting' | 'open' | 'failed' = 'connecting';
  private failure = 'postgres event store is not open';

  constructor(config: PostgresEventLogConfig) {
    this.anchorPath = config.anchorPath;
    this.anchorSinks = config.sinks ?? [];
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
      this.state = 'open';
      this.failure = 'postgres event store is not open';
      // Await the migrate event's own persist before connect resolves, so
      // whenReady() means "migrations recorded AND their event persisted".
      if (applied.length > 0) await this.recordMigrationEvent(applied);
    } catch (error) {
      this.state = 'failed';
      const detail = redactUrl(error instanceof Error ? error.message : String(error));
      this.failure = `postgres event store unavailable (endpoint ${this.endpoint}): ${detail}`;
      await this.sql.end({ timeout: 1_000 }).catch(() => {});
      // Typed so the PDP maps this to denyReason 'store-unavailable' (H15).
      throw new StoreUnavailableError(this.failure);
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
      // Idempotent bootstrap for the ADR-018 roles (cluster-level, like the
      // migrations bookkeeping table): NOLOGIN roles, no passwords in DDL —
      // operator provisioning of LOGIN/passwords is out-of-band (DEPLOYMENT).
      // Tests use superuser + SET LOCAL ROLE to exercise RLS contexts.
      await ddl.unsafe(`
        DO $$ BEGIN
          IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname = 'app_rw') THEN
            CREATE ROLE app_rw NOLOGIN;
          END IF;
          IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname = 'app_reader') THEN
            CREATE ROLE app_reader NOLOGIN;
          END IF;
        END $$;
      `);
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

  /**
   * Build the signed event, mirror it, anchor it — the shared body of both
   * write paths. Callers decide whether the persist goes through the
   * append queue (append) or is awaited directly (the migrate event, which
   * connect() must have persisted before whenReady() resolves).
   */
  private buildAndMirror(input: EventInput): SecurityEvent {
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
    if (this.anchorSinks.length > 0) {
      const point: AnchorPoint = {
        seq: event.seq,
        headHash: event.eventHash,
        eventCount: event.seq + 1,
        at: event.timestamp,
      };
      for (const sink of this.anchorSinks) {
        try {
          sink.publish(point);
        } catch {
          process.emitWarning?.(`anchor sink '${sink.name}' threw on publish (evidence append unaffected)`);
        }
      }
    }
    return event;
  }

  /** H11: drain external witness delivery (HTTP sinks may be async). */
  async flushAnchors(): Promise<void> {
    await Promise.all(this.anchorSinks.map((sink) => sink.flush()));
  }

  /** Store-level migrate event: mirrored synchronously, persisted directly (not queued). */
  private async recordMigrationEvent(applied: readonly AppliedMigration[]): Promise<void> {
    const event = this.buildAndMirror({
      tenantId: '', // store-level event: not tenant-scoped
      principal: 'service:store-migrate',
      actor: 'service:store-migrate',
      actorKind: 'service',
      action: 'store.migrate',
      result: 'success',
      metadata: { phase: 'store-migrate', applied: applied.map((a) => ({ id: a.id, hash: a.hash })) },
    });
    await this.persist(event);
  }

  append(input: EventInput): SecurityEvent {
    // Typed for the PDP: appends before the store is open (or after a failed
    // connect/write) are a typed refusal — the PDP maps this to
    // 'store-unavailable' (H15), not the generic evidence-write-failure.
    // Runtime callers reach readiness through buildWorldAsync (scenario.ts)
    // BEFORE any decision, so this fires only on genuine outages/misuse.
    if (this.state !== 'open') throw new StoreUnavailableError(`${this.failure}: refusing to append (fail closed)`);
    const event = this.buildAndMirror(input);
    const next = this.tail.then(() => this.persist(event));
    next.catch((error) => {
      // A write that did not reach the database closes the store for further
      // appends: the next append (and every decision) fails closed.
      this.state = 'failed';
      const detail = redactUrl(error instanceof Error ? error.message : String(error));
      this.failure = `postgres event store write failed (endpoint ${this.endpoint}): ${detail}`;
      // Loud, once per failure (H15): the next append denies, and this warning
      // is the operator-visible health signal the evidence path cannot give.
      process.emitWarning?.(`evidence store unavailable: ${this.failure}`);
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
    // End the pool AFTER every queued write: appends persist asynchronously
    // (queued on this.tail), so an immediate end loses them (CONNECTION_ENDED).
    // The tail is drained before the pool ends; post-close appends then fail
    // closed through the driver error path.
    const tail = this.tail;
    const end = (): void => {
      this.sql.end({ timeout: 5_000 }).catch(() => {});
    };
    tail.then(end, end).catch(() => {});
  }
}
