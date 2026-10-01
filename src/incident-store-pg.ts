/**
 * H13 (ADR-026): Postgres revocation channel.
 *
 * The event log is single-writer by construction; revocation coordination is a
 * separate, multi-writer, append-only table (migration id 4). The runtime
 * connects with the ordinary app_rw role; there is no UPDATE/DELETE grant, so
 * the channel is append-only by privilege. This is control-plane data: no
 * secrets and no claim content may be published (reason text is operator
 * typed and treated as non-secret).
 *
 * The channel is a local mirror + async refresh, the PostgresEventLog pattern:
 * the decision path cannot await a database, so `since` reads the mirror and
 * `refresh` (fired by IncidentService.sync) pulls new rows. Errors surface
 * through `health()`; they never silently become "propagated".
 */

import postgres from 'postgres';
// Full `import type` — an inline `{ type X }` specifier would keep a runtime
// load edge back to event-store-pg.ts and close a cycle (TDZ crash when this
// module is imported first).
import type { StoreMigration } from './event-store-pg.ts';
import {
  type ChannelHealth,
  type RevocationAction,
  type RevocationChannel,
  type RevocationInput,
  type RevocationRecord,
} from './incident.ts';

const REVOCATION_ACTIONS: readonly RevocationAction[] = [
  'freeze',
  'unfreeze',
  'revoke-caps',
  'revoke-sessions',
  'revoke-cap',
  'revoke-session',
];

export const INCIDENT_MIGRATION: StoreMigration = {
  id: 4,
  sql: `
    -- H13 incident response: multi-writer revocation channel. Deliberately NOT
    -- RLS-scoped: it coordinates nodes and tenants (scope/tenant columns carry
    -- the routing), carries no claim content, and every row is control-plane
    -- coordination data. Append-only by privilege: app_rw has SELECT/INSERT
    -- and no UPDATE/DELETE grant exists.
    CREATE TABLE IF NOT EXISTS revocation_channel(
      seq BIGSERIAL PRIMARY KEY,
      action TEXT NOT NULL,
      scope TEXT NOT NULL CHECK (scope IN ('tenant', 'global')),
      tenant_id TEXT,
      target_id TEXT,
      reason TEXT NOT NULL,
      at BIGINT NOT NULL
    );
    REVOKE UPDATE, DELETE ON revocation_channel FROM PUBLIC;
    GRANT USAGE ON SCHEMA public TO app_rw;
    GRANT SELECT, INSERT ON revocation_channel TO app_rw;
    GRANT USAGE, SELECT ON SEQUENCE revocation_channel_seq TO app_rw;
  `,
};

type Sql = ReturnType<typeof postgres>;

interface ChannelRow {
  readonly seq: string | number;
  readonly action: string;
  readonly scope: string;
  readonly tenant_id: string | null;
  readonly target_id: string | null;
  readonly reason: string;
  readonly at: string | number;
}

function redactUrl(text: string): string {
  return text.replace(/postgres(?:ql)?:\/\/\S*/g, 'postgres://[redacted]');
}

function endpointOf(url: string): string {
  try {
    return new URL(url).host;
  } catch {
    return 'unparsable-endpoint';
  }
}

/** Trust boundary: the database row is adversarial data — validate, never cast. */
function parseChannelRow(row: ChannelRow): RevocationRecord {
  const seq = Number(row.seq);
  const at = Number(row.at);
  if (!Number.isInteger(seq) || seq < 0 || !Number.isInteger(at)) {
    throw new Error('revocation channel row is malformed: refusing to apply');
  }
  if (!REVOCATION_ACTIONS.includes(row.action as RevocationAction)) {
    throw new Error('revocation channel row has an unknown action: refusing to apply');
  }
  if (row.scope !== 'tenant' && row.scope !== 'global') {
    throw new Error('revocation channel row has an unknown scope: refusing to apply');
  }
  if (typeof row.reason !== 'string' || row.reason.trim() === '') {
    throw new Error('revocation channel row has no reason: refusing to apply');
  }
  return {
    seq,
    action: row.action as RevocationAction,
    scope: row.scope,
    ...(row.tenant_id !== null ? { tenantId: row.tenant_id } : {}),
    ...(row.target_id !== null ? { targetId: row.target_id } : {}),
    reason: row.reason,
    at,
  };
}

export interface PostgresRevocationChannelConfig {
  /** Runtime role connection (app_rw per ADR-018). Never logged, never stored. */
  readonly url: string;
}

export class PostgresRevocationChannel implements RevocationChannel {
  private readonly sql: Sql;
  private readonly mirror: RevocationRecord[] = [];
  private readonly endpoint: string;
  private maxSeq = -1;
  private refreshInFlight = false;
  private errorCount = 0;
  private lastError?: string;

  constructor(config: PostgresRevocationChannelConfig) {
    this.endpoint = endpointOf(config.url);
    this.sql = postgres(config.url);
    this.refresh();
  }

  /**
   * Fire-and-forget append: a kill switch must not block on a remote write,
   * and a failure is surfaced through `health()` (and `broadcastOk` on the
   * engaging node) rather than silently treated as propagated.
   */
  publish(input: RevocationInput): void {
    void this.sql`
      INSERT INTO revocation_channel (action, scope, tenant_id, target_id, reason, at)
      VALUES (${input.action}, ${input.scope}, ${input.tenantId ?? null}, ${input.targetId ?? null}, ${input.reason}, ${input.at})
    `.catch((error: unknown) => this.recordError(error));
  }

  refresh(): void {
    if (this.refreshInFlight) return;
    this.refreshInFlight = true;
    void this.load()
      .catch((error: unknown) => this.recordError(error))
      .finally(() => {
        this.refreshInFlight = false;
      });
  }

  private async load(): Promise<void> {
    const rows = (await this.sql`
      SELECT seq, action, scope, tenant_id, target_id, reason, at
      FROM revocation_channel
      WHERE seq > ${this.maxSeq}
      ORDER BY seq ASC
    `) as unknown as ChannelRow[];
    for (const row of rows) {
      let record: RevocationRecord;
      try {
        record = parseChannelRow(row);
      } catch (error) {
        // A rejected row must not stall the cursor: record it loudly and keep
        // advancing. The table is append-only, so the row cannot be removed
        // in-band — without this skip, one hostile (or future-version) row
        // halts all revocation propagation on this node forever.
        this.recordError(error, 'row rejected');
        const seq = Number(row.seq);
        if (Number.isInteger(seq) && seq >= 0) this.maxSeq = Math.max(this.maxSeq, seq);
        continue;
      }
      this.mirror.push(record);
      this.maxSeq = record.seq;
    }
  }

  private recordError(error: unknown, kind = 'unavailable'): void {
    this.errorCount++;
    const detail = redactUrl(error instanceof Error ? error.message : String(error));
    this.lastError = `postgres revocation channel ${kind} (endpoint ${this.endpoint}): ${detail}`;
  }

  since(cursor: number): readonly RevocationRecord[] {
    return this.mirror.filter((r) => r.seq > cursor);
  }

  cursor(): number {
    return this.maxSeq;
  }

  /** Await every queued query (inserts included) — used before process exit. */
  async flush(): Promise<void> {
    await this.sql`SELECT 1`.catch((error: unknown) => this.recordError(error));
  }

  health(): ChannelHealth {
    return { errors: this.errorCount, ...(this.lastError !== undefined ? { lastError: this.lastError } : {}) };
  }

  close(): void {
    void this.sql.end({ timeout: 1_000 }).catch(() => {});
  }
}
