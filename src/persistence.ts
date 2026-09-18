/**
 * Stage-0 control-plane persistence (ADR-018): projects, tasks, and agent
 * session state over Postgres — the application state store ADR-010 separates
 * from the evidence plane (the EventStore port keeps the evidence role).
 *
 * Raw SQL through the `postgres` driver: tagged templates bind every value as
 * a parameter by construction; migration DDL below is static parameterless
 * text — no user input, no secrets, ever. Every query binds the tenant
 * explicitly (ADR-007 defense in depth) and runs inside a transaction as the
 * app_rw role with the RLS tenant context set, so a query that skips the
 * tenant context reads zero rows — the database denies, not app code.
 *
 * Error messages are redacted to the endpoint host; the URL and its
 * credentials are never retained or logged (same pattern as
 * src/event-store-pg.ts).
 */

import postgres, { type TransactionSql } from 'postgres';
import { type StoreMigration } from './event-store-pg.ts';

type Sql = ReturnType<typeof postgres>;

/** JSON-serializable value: writable state is validated by construction. */
type JsonValue = string | number | boolean | null | readonly JsonValue[] | { readonly [key: string]: undefined | JsonValue };
type JsonObject = { readonly [key: string]: undefined | JsonValue };

export interface PersistenceConfig {
  /** Runtime role connection URL. Never logged, never stored. */
  readonly url: string;
}

export interface ProjectRow {
  readonly id: string;
  readonly tenantId: string;
  readonly name: string;
  readonly createdAt: Date;
}

export interface TaskRow {
  readonly id: string;
  readonly tenantId: string;
  readonly projectId: string;
  readonly status: string;
  readonly payload: Readonly<Record<string, unknown>>;
  readonly createdAt: Date;
  readonly updatedAt: Date;
}

export interface SessionRow {
  readonly id: string;
  readonly tenantId: string;
  readonly taskId: string;
  readonly principal: string;
  readonly state: Readonly<Record<string, unknown>>;
  readonly createdAt: Date;
  readonly updatedAt: Date;
}

/**
 * Migration id 3 (ADR-018 schema block, verbatim columns/types): the M4
 * capability-request flow table plus the Stage-0 project/task/session state
 * tables. Roles app_rw/app_reader are bootstrapped by the migration runner
 * (src/event-store-pg.ts) before any migration applies, so the policies and
 * grants below can reference app_rw. RLS is deny-by-default: a session that
 * never sets app.tenant_id reads zero rows. app_rw keeps SELECT/INSERT/UPDATE
 * here — these are state tables, not the append-only security_events.
 */
export const PERSISTENCE_MIGRATION: StoreMigration = {
  id: 3,
  sql: `
    -- IF NOT EXISTS keeps re-application after a partial batch failure
    -- converging (forward-only runner posture, matching migration id 1).
    CREATE TABLE IF NOT EXISTS capability_requests(
      id TEXT PRIMARY KEY,
      tenant_id TEXT NOT NULL,
      principal TEXT NOT NULL,
      status TEXT NOT NULL,        -- pending|approved|denied|expired
      requested JSONB NOT NULL,
      created_at TIMESTAMPTZ NOT NULL,
      expires_at TIMESTAMPTZ NOT NULL,
      decided_at TIMESTAMPTZ,
      decided_by TEXT
    );
    CREATE TABLE IF NOT EXISTS projects(
      id TEXT PRIMARY KEY,
      tenant_id TEXT NOT NULL,
      name TEXT NOT NULL,
      created_at TIMESTAMPTZ NOT NULL
    );
    CREATE TABLE IF NOT EXISTS tasks(
      id TEXT PRIMARY KEY,
      tenant_id TEXT NOT NULL,
      project_id TEXT NOT NULL REFERENCES projects(id),
      status TEXT NOT NULL,
      payload JSONB NOT NULL,
      created_at TIMESTAMPTZ NOT NULL,
      updated_at TIMESTAMPTZ NOT NULL
    );
    CREATE TABLE IF NOT EXISTS agent_sessions(
      id TEXT PRIMARY KEY,
      tenant_id TEXT NOT NULL,
      task_id TEXT NOT NULL REFERENCES tasks(id),
      principal TEXT NOT NULL,
      state JSONB NOT NULL,        -- everything needed to resume
      created_at TIMESTAMPTZ NOT NULL,
      updated_at TIMESTAMPTZ NOT NULL
    );

    ALTER TABLE capability_requests ENABLE ROW LEVEL SECURITY;
    ALTER TABLE capability_requests FORCE ROW LEVEL SECURITY;
    DROP POLICY IF EXISTS tenant_isolation ON capability_requests;
    CREATE POLICY tenant_isolation ON capability_requests
      USING      (tenant_id = current_setting('app.tenant_id', true))
      WITH CHECK (tenant_id = current_setting('app.tenant_id', true));

    ALTER TABLE projects ENABLE ROW LEVEL SECURITY;
    ALTER TABLE projects FORCE ROW LEVEL SECURITY;
    DROP POLICY IF EXISTS tenant_isolation ON projects;
    CREATE POLICY tenant_isolation ON projects
      USING      (tenant_id = current_setting('app.tenant_id', true))
      WITH CHECK (tenant_id = current_setting('app.tenant_id', true));

    ALTER TABLE tasks ENABLE ROW LEVEL SECURITY;
    ALTER TABLE tasks FORCE ROW LEVEL SECURITY;
    DROP POLICY IF EXISTS tenant_isolation ON tasks;
    CREATE POLICY tenant_isolation ON tasks
      USING      (tenant_id = current_setting('app.tenant_id', true))
      WITH CHECK (tenant_id = current_setting('app.tenant_id', true));

    ALTER TABLE agent_sessions ENABLE ROW LEVEL SECURITY;
    ALTER TABLE agent_sessions FORCE ROW LEVEL SECURITY;
    DROP POLICY IF EXISTS tenant_isolation ON agent_sessions;
    CREATE POLICY tenant_isolation ON agent_sessions
      USING      (tenant_id = current_setting('app.tenant_id', true))
      WITH CHECK (tenant_id = current_setting('app.tenant_id', true));

    GRANT USAGE ON SCHEMA public TO app_rw;
    GRANT SELECT, INSERT, UPDATE ON capability_requests, projects, tasks, agent_sessions TO app_rw;
  `,
};

/** The URL is a secret: keep only the endpoint host for operator-visible errors. */
function endpointOf(url: string): string {
  try {
    return new URL(url).host;
  } catch {
    return 'unparsable-endpoint';
  }
}

/** Mirrors src/event-store-pg.ts: no postgres:// URL or credentials in error text. */
function redactUrl(text: string): string {
  return text.replace(/postgres(?:ql)?:\/\/\S*/g, 'postgres://[redacted]');
}

/** Trust boundary: the database is adversarial data. Column values are checked, never cast. */
function requireString(value: unknown, column: string): string {
  if (typeof value !== 'string') throw new Error(`column ${column} is not text: refusing to load`);
  return value;
}

function requireDate(value: unknown, column: string): Date {
  if (!(value instanceof Date)) throw new Error(`column ${column} is not a timestamp: refusing to load`);
  return value;
}

/** JSONB state must be a plain object — garbage throws, nothing is cast silently. */
function requireObject(value: unknown, column: string): Readonly<Record<string, unknown>> {
  if (typeof value !== 'object' || value === null || Array.isArray(value)) {
    throw new Error(`column ${column} is not a JSON object: refusing to load`);
  }
  return value as Record<string, unknown>;
}

type Row = Record<string, unknown>;

function toProject(row: Row): ProjectRow {
  return {
    id: requireString(row.id, 'projects.id'),
    tenantId: requireString(row.tenant_id, 'projects.tenant_id'),
    name: requireString(row.name, 'projects.name'),
    createdAt: requireDate(row.created_at, 'projects.created_at'),
  };
}

function toTask(row: Row): TaskRow {
  return {
    id: requireString(row.id, 'tasks.id'),
    tenantId: requireString(row.tenant_id, 'tasks.tenant_id'),
    projectId: requireString(row.project_id, 'tasks.project_id'),
    status: requireString(row.status, 'tasks.status'),
    payload: requireObject(row.payload, 'tasks.payload'),
    createdAt: requireDate(row.created_at, 'tasks.created_at'),
    updatedAt: requireDate(row.updated_at, 'tasks.updated_at'),
  };
}

function toSession(row: Row): SessionRow {
  return {
    id: requireString(row.id, 'agent_sessions.id'),
    tenantId: requireString(row.tenant_id, 'agent_sessions.tenant_id'),
    taskId: requireString(row.task_id, 'agent_sessions.task_id'),
    principal: requireString(row.principal, 'agent_sessions.principal'),
    state: requireObject(row.state, 'agent_sessions.state'),
    createdAt: requireDate(row.created_at, 'agent_sessions.created_at'),
    updatedAt: requireDate(row.updated_at, 'agent_sessions.updated_at'),
  };
}

export class PersistenceStore {
  private readonly sql: Sql;
  /** Endpoint host only — the full URL is a secret and is never retained. */
  private readonly endpoint: string;

  constructor(config: PersistenceConfig) {
    this.endpoint = endpointOf(config.url);
    this.sql = postgres(config.url);
  }

  close(): void {
    this.sql.end({ timeout: 5_000 }).catch(() => {});
  }

  /**
   * One transaction per operation, as the app_rw runtime role (ADR-018) with
   * the RLS tenant context set per transaction. set_config's is_local=true
   * reverts at commit; the SET LOCAL ROLE reverts with the transaction.
   */
  private async run<T>(tenantId: string, work: (tx: TransactionSql) => Promise<T>): Promise<T> {
    try {
      return await this.sql.begin<Promise<T>>(async (tx) => {
        await tx.unsafe('SET LOCAL ROLE app_rw');
        await tx`SELECT set_config('app.tenant_id', ${tenantId}, true)`;
        return work(tx);
      });
    } catch (error) {
      const detail = redactUrl(error instanceof Error ? error.message : String(error));
      throw new Error(`persistence operation failed (endpoint ${this.endpoint}): ${detail}`, { cause: error });
    }
  }

  async createProject(tenantId: string, id: string, name: string): Promise<ProjectRow> {
    return this.run(tenantId, async (tx) => {
      const rows = await tx`
        INSERT INTO projects (id, tenant_id, name, created_at)
        VALUES (${id}, ${tenantId}, ${name}, now())
        RETURNING id, tenant_id, name, created_at`;
      return toProject(rows[0]!);
    });
  }

  async getProject(tenantId: string, id: string): Promise<ProjectRow | undefined> {
    return this.run(tenantId, async (tx) => {
      const rows = await tx`
        SELECT id, tenant_id, name, created_at FROM projects
        WHERE tenant_id = ${tenantId} AND id = ${id}`;
      return rows.length === 0 ? undefined : toProject(rows[0]!);
    });
  }

  async listProjects(tenantId: string): Promise<ProjectRow[]> {
    return this.run(tenantId, async (tx) => {
      const rows = await tx`
        SELECT id, tenant_id, name, created_at FROM projects
        WHERE tenant_id = ${tenantId} ORDER BY created_at, id`;
      return rows.map(toProject);
    });
  }

  async createTask(
    tenantId: string,
    id: string,
    projectId: string,
    payload: JsonObject,
  ): Promise<TaskRow> {
    return this.run(tenantId, async (tx) => {
      // ADR-007 defense in depth: the FK constraint alone would accept a
      // cross-tenant project_id; the app check refuses it first.
      const owner = await tx`SELECT id FROM projects WHERE tenant_id = ${tenantId} AND id = ${projectId}`;
      if (owner.length === 0) {
        throw new Error(`project ${projectId} not found in tenant: refusing to create task`);
      }
      const rows = await tx`
        INSERT INTO tasks (id, tenant_id, project_id, status, payload, created_at, updated_at)
        VALUES (${id}, ${tenantId}, ${projectId}, 'pending', ${tx.json(payload)}, now(), now())
        RETURNING id, tenant_id, project_id, status, payload, created_at, updated_at`;
      return toTask(rows[0]!);
    });
  }

  async getTask(tenantId: string, id: string): Promise<TaskRow | undefined> {
    return this.run(tenantId, async (tx) => {
      const rows = await tx`
        SELECT id, tenant_id, project_id, status, payload, created_at, updated_at FROM tasks
        WHERE tenant_id = ${tenantId} AND id = ${id}`;
      return rows.length === 0 ? undefined : toTask(rows[0]!);
    });
  }

  async updateTaskStatus(tenantId: string, id: string, status: string): Promise<TaskRow | undefined> {
    return this.run(tenantId, async (tx) => {
      const rows = await tx`
        UPDATE tasks SET status = ${status}, updated_at = now()
        WHERE tenant_id = ${tenantId} AND id = ${id}
        RETURNING id, tenant_id, project_id, status, payload, created_at, updated_at`;
      return rows.length === 0 ? undefined : toTask(rows[0]!);
    });
  }

  async listTasksForProject(tenantId: string, projectId: string): Promise<TaskRow[]> {
    return this.run(tenantId, async (tx) => {
      const rows = await tx`
        SELECT id, tenant_id, project_id, status, payload, created_at, updated_at FROM tasks
        WHERE tenant_id = ${tenantId} AND project_id = ${projectId} ORDER BY created_at, id`;
      return rows.map(toTask);
    });
  }

  /**
   * Upsert of one agent session's resumable state. A cross-tenant id
   * collision (the id already exists under another tenant) affects zero rows
   * and throws instead of silently saving.
   */
  async saveSession(
    tenantId: string,
    id: string,
    taskId: string,
    principal: string,
    state: JsonObject,
  ): Promise<SessionRow> {
    return this.run(tenantId, async (tx) => {
      // ADR-007 defense in depth: the FK alone would accept a cross-tenant task_id.
      const owner = await tx`SELECT id FROM tasks WHERE tenant_id = ${tenantId} AND id = ${taskId}`;
      if (owner.length === 0) {
        throw new Error(`task ${taskId} not found in tenant: refusing to save session`);
      }
      const rows = await tx`
        INSERT INTO agent_sessions (id, tenant_id, task_id, principal, state, created_at, updated_at)
        VALUES (${id}, ${tenantId}, ${taskId}, ${principal}, ${tx.json(state)}, now(), now())
        ON CONFLICT (id) DO UPDATE
        SET task_id = EXCLUDED.task_id, principal = EXCLUDED.principal,
            state = EXCLUDED.state, updated_at = now()
        WHERE agent_sessions.tenant_id = ${tenantId}
        RETURNING id, tenant_id, task_id, principal, state, created_at, updated_at`;
      if (rows.length === 0) {
        throw new Error(`session ${id} belongs to another tenant: refusing to save`);
      }
      return toSession(rows[0]!);
    });
  }

  async getSession(tenantId: string, id: string): Promise<SessionRow | undefined> {
    return this.run(tenantId, async (tx) => {
      const rows = await tx`
        SELECT id, tenant_id, task_id, principal, state, created_at, updated_at FROM agent_sessions
        WHERE tenant_id = ${tenantId} AND id = ${id}`;
      return rows.length === 0 ? undefined : toSession(rows[0]!);
    });
  }

  async listSessionsForTask(tenantId: string, taskId: string): Promise<SessionRow[]> {
    return this.run(tenantId, async (tx) => {
      const rows = await tx`
        SELECT id, tenant_id, task_id, principal, state, created_at, updated_at FROM agent_sessions
        WHERE tenant_id = ${tenantId} AND task_id = ${taskId} ORDER BY created_at, id`;
      return rows.map(toSession);
    });
  }
}
