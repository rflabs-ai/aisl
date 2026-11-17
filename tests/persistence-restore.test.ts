/**
 * M12 Phase 2 — persistence API + backup/restore rehearsal (ADR-018).
 *
 * DATABASE_URL must point at a DISPOSABLE scratch database: the persistence
 * suite drops and recreates its tables around every test. The restore
 * rehearsal additionally needs RESTORE_DATABASE_URL (a second disposable
 * scratch database that the test drops and recreates via the admin client)
 * and a pg_dump/psql pair — either on PATH or inside the fallback Docker
 * container (PG_CONTAINER, default sec-layer-pg). Tests skip cleanly with
 * the reason when any of these is unavailable.
 */

import { after, beforeEach, describe, test } from 'node:test';
import assert from 'node:assert/strict';
import { rmSync } from 'node:fs';
import { spawnSync } from 'node:child_process';
import postgres from 'postgres';
import { eventPublicKey, verifyBundle } from '../src/events.ts';
import { PostgresEventLog } from '../src/event-store-pg.ts';
import { PERSISTENCE_MIGRATION, PersistenceStore } from '../src/persistence.ts';

const DATABASE_URL = process.env.DATABASE_URL;
const RESTORE_DATABASE_URL = process.env.RESTORE_DATABASE_URL;
const PG_SKIP = !DATABASE_URL && 'DATABASE_URL is not set (ADR-018: Postgres tests skip cleanly)';

function tmp(name: string): string {
  return `${process.env.TEMP ?? '.'}\\ai-security-layer-m12-${name}-${Date.now()}-${Math.random().toString(36).slice(2)}`;
}

/** Inline identifier guard: admin DDL cannot take bind parameters. */
function databaseNameOf(databaseUrl: string): string {
  const name = decodeURIComponent(new URL(databaseUrl).pathname.slice(1));
  if (!/^[A-Za-z0-9_-]+$/.test(name)) {
    throw new Error('database name must match [A-Za-z0-9_-]+ (it is inlined into admin DDL)');
  }
  return name;
}

function redact(text: string): string {
  return text.replace(/postgres(?:ql)?:\/\/\S*/g, 'postgres://[redacted]');
}

const pgAdmin: ReturnType<typeof postgres> | undefined = DATABASE_URL ? postgres(DATABASE_URL) : undefined;

after(async () => {
  if (pgAdmin) await pgAdmin.end({ timeout: 1_000 });
});

// DATABASE_URL points at a disposable scratch database: reset the whole
// schema before every test so each test starts fresh (roles are
// cluster-level and survive; grants are re-created by the migrations).
beforeEach(async () => {
  if (!pgAdmin) return;
  await pgAdmin`DROP SCHEMA public CASCADE`;
  await pgAdmin`CREATE SCHEMA public`;
});

interface PgTools {
  dump(databaseUrl: string, outFile: string): void;
  restore(databaseUrl: string, dumpFile: string): void;
}

let tools: PgTools | undefined;
let toolsReason = 'DATABASE_URL and RESTORE_DATABASE_URL are not both set (restore rehearsal skips)';

if (DATABASE_URL && RESTORE_DATABASE_URL) {
  const hostPgDump = spawnSync('pg_dump', ['--version'], { stdio: 'ignore' }).status === 0;
  const hostPsql = spawnSync('psql', ['--version'], { stdio: 'ignore' }).status === 0;
  if (hostPgDump && hostPsql) {
    const conn = (url: string): string[] => {
      const u = new URL(url);
      const args = ['-h', u.hostname];
      if (u.port) args.push('-p', u.port);
      args.push('-U', u.username || 'postgres');
      return args;
    };
    const envFor = (url: string): NodeJS.ProcessEnv => ({
      ...process.env,
      PGPASSWORD: new URL(url).password ? decodeURIComponent(new URL(url).password) : '',
    });
    tools = {
      dump(url, outFile) {
        const r = spawnSync('pg_dump', [...conn(url), '-d', databaseNameOf(url), '-f', outFile], {
          stdio: ['ignore', 'ignore', 'pipe'],
          env: envFor(url),
        });
        if (r.status !== 0) throw new Error(redact(r.stderr?.toString() ?? 'pg_dump failed'));
      },
      restore(url, dumpFile) {
        const r = spawnSync('psql', [...conn(url), '-d', databaseNameOf(url), '-v', 'ON_ERROR_STOP=1', '-f', dumpFile], {
          stdio: ['ignore', 'ignore', 'pipe'],
          env: envFor(url),
        });
        if (r.status !== 0) throw new Error(redact(r.stderr?.toString() ?? 'psql restore failed'));
      },
    };
  } else {
    const container = process.env.PG_CONTAINER ?? 'sec-layer-pg';
    const probe = spawnSync('docker', ['exec', container, 'pg_dump', '--version'], { stdio: 'ignore' });
    if (probe.status === 0) {
      const viaContainer = (args: readonly string[]): void => {
        const r = spawnSync('docker', args, { stdio: ['ignore', 'ignore', 'pipe'] });
        if (r.status !== 0) throw new Error(redact(r.stderr?.toString() ?? `docker ${args[0]} failed`));
      };
      tools = {
        dump(url, outFile) {
          const remote = `/tmp/sec-layer-dump-${Date.now()}.sql`;
          try {
            viaContainer(['exec', container, 'sh', '-c', `pg_dump -U postgres -d ${databaseNameOf(url)} > ${remote}`]);
            viaContainer(['cp', `${container}:${remote}`, outFile]);
          } finally {
            spawnSync('docker', ['exec', container, 'rm', '-f', remote], { stdio: 'ignore' });
          }
        },
        restore(url, dumpFile) {
          const remote = `/tmp/sec-layer-dump-${Date.now()}.sql`;
          try {
            viaContainer(['cp', dumpFile, `${container}:${remote}`]);
            viaContainer(['exec', container, 'psql', '-U', 'postgres', '-d', databaseNameOf(url), '-v', 'ON_ERROR_STOP=1', '-f', remote]);
          } finally {
            spawnSync('docker', ['exec', container, 'rm', '-f', remote], { stdio: 'ignore' });
          }
        },
      };
    } else {
      toolsReason = 'pg_dump/psql are neither on PATH nor inside the fallback Docker container; backup/restore rehearsal skips';
    }
  }
}

const TOOLS_SKIP = tools ? false : toolsReason;

/**
 * Roles (app_rw) are bootstrapped by the migration runner's idempotent DO
 * block when a PostgresEventLog connects, so each test opens one briefly to
 * ensure the cluster roles exist before applying the persistence migration.
 */
async function seededPersistenceStore(url: string): Promise<PersistenceStore> {
  const bootstrapper = new PostgresEventLog({ url, migrateUrl: url });
  await bootstrapper.whenReady();
  bootstrapper.close();
  await pgAdmin!.unsafe(PERSISTENCE_MIGRATION.sql);
  return new PersistenceStore({ url });
}

describe('M12 persistence API over Postgres (ADR-018 Stage-0 state store)', () => {
  test('projects: create/get/list round trip, tenant-scoped', { skip: PG_SKIP }, async () => {
    const store = await seededPersistenceStore(DATABASE_URL!);
    try {
      const created = await store.createProject('t1', 'proj-1', 'Acme platform');
      assert.equal(created.id, 'proj-1');
      assert.equal(created.tenantId, 't1');
      await store.createProject('t1', 'proj-2', 'Second');
      await store.createProject('t2', 'proj-2-foreign', 'Foreign');

      assert.deepEqual((await store.listProjects('t1')).map((p) => p.id), ['proj-1', 'proj-2']);
      assert.deepEqual((await store.listProjects('t2')).map((p) => p.id), ['proj-2-foreign']);
      assert.equal(await store.getProject('t2', 'proj-1'), undefined, 'cross-tenant read denied');
      assert.equal(await store.getProject('t1', 'proj-unknown'), undefined);
    } finally {
      store.close();
    }
  });

  /**
   * Ticket 09 contract: `createProject` is an idempotent create keyed on the
   * project id. The first call inserts; a repeat in the same tenant returns
   * the existing row (created_at preserved, name refreshed) instead of a raw
   * `projects_pkey` violation. A repeat under another tenant affects zero
   * rows and refuses loudly: the id is global, the row is tenant-scoped.
   */
  test('projects: creating the same id twice is idempotent and tenant-scoped (ticket 09)', { skip: PG_SKIP }, async () => {
    const store = await seededPersistenceStore(DATABASE_URL!);
    try {
      const first = await store.createProject('t1', 'proj-1', 'Acme platform');
      const second = await store.createProject('t1', 'proj-1', 'Acme platform (renamed)');

      assert.equal(second.id, 'proj-1');
      assert.equal(second.tenantId, 't1');
      assert.equal(second.createdAt.getTime(), first.createdAt.getTime(), 'repeat create keeps created_at');
      assert.equal(second.name, 'Acme platform (renamed)', 'repeat create refreshes name');
      assert.deepEqual((await store.listProjects('t1')).map((p) => p.id), ['proj-1'], 'one row, not two');

      await assert.rejects(
        store.createProject('t2', 'proj-1', 'Hostile takeover'),
        /belongs to another tenant: refusing to create/,
      );
      assert.deepEqual(await store.getProject('t1', 'proj-1'), second, 'cross-tenant create changed nothing');
      assert.deepEqual(await store.listProjects('t2'), [], 'cross-tenant create wrote no row');
    } finally {
      store.close();
    }
  });

  test('tasks: FK-scoped creation, status updates, per-project listing', { skip: PG_SKIP }, async () => {
    const store = await seededPersistenceStore(DATABASE_URL!);
    try {
      await store.createProject('t1', 'proj-1', 'Acme platform');
      const created = await store.createTask('t1', 'task-1', 'proj-1', { input: 'summarize' });
      assert.equal(created.status, 'pending');
      assert.deepEqual(created.payload, { input: 'summarize' });

      // A project of another tenant is invisible: the task is refused.
      await assert.rejects(
        store.createTask('t1', 'task-2', 'proj-foreign', {}),
        /not found in tenant|foreign key/,
      );

      const updated = await store.updateTaskStatus('t1', 'task-1', 'running');
      assert.equal(updated?.status, 'running');
      assert.equal(await store.updateTaskStatus('t1', 'task-ghost', 'done'), undefined);
      assert.equal(await store.updateTaskStatus('t2', 'task-1', 'done'), undefined, 'cross-tenant update denied');

      assert.deepEqual((await store.listTasksForProject('t1', 'proj-1')).map((t) => t.id), ['task-1']);
      assert.deepEqual((await store.listTasksForProject('t2', 'proj-1')), []);
      assert.deepEqual((await store.getTask('t1', 'task-1'))?.payload, { input: 'summarize' });
    } finally {
      store.close();
    }
  });

  test('sessions: upsert state, resume readback, per-task listing', { skip: PG_SKIP }, async () => {
    const store = await seededPersistenceStore(DATABASE_URL!);
    try {
      await store.createProject('t1', 'proj-1', 'Acme platform');
      await store.createTask('t1', 'task-1', 'proj-1', {});

      const first = await store.saveSession('t1', 'sess-1', 'task-1', 'agent:1', { step: 1, history: ['x'] });
      assert.deepEqual(first.state, { step: 1, history: ['x'] });
      const second = await store.saveSession('t1', 'sess-1', 'task-1', 'agent:1', { step: 2, history: ['x', 'y'] });
      assert.deepEqual(second.state, { step: 2, history: ['x', 'y'] });
      assert.equal(second.createdAt.getTime(), first.createdAt.getTime(), 'upsert keeps created_at');
      assert.ok(second.updatedAt.getTime() >= second.createdAt.getTime());

      assert.deepEqual((await store.listSessionsForTask('t1', 'task-1')).map((s) => s.id), ['sess-1']);
      assert.equal(await store.getSession('t2', 'sess-1'), undefined, 'cross-tenant read denied');

      // A session id that already exists under another tenant refuses loudly
      // instead of silently affecting zero rows (and so does a cross-tenant
      // task reference — the FK is global, the app check is not).
      await assert.rejects(
        store.saveSession('t2', 'sess-1', 'task-1', 'agent:2', { step: 9 }),
        /another tenant|not found in tenant/,
      );
    } finally {
      store.close();
    }
  });

  test('RLS is the deny-by-default boundary: no tenant context reads zero rows', { skip: PG_SKIP }, async () => {
    const store = await seededPersistenceStore(DATABASE_URL!);
    try {
      await store.createProject('t1', 'proj-1', 'Acme platform');
      const bare = postgres(DATABASE_URL!);
      try {
        const visible = await bare.begin(async (tx) => {
          await tx.unsafe('SET LOCAL ROLE app_rw');
          return (await tx`SELECT id FROM projects WHERE id = ${'proj-1'}`).length;
        });
        assert.equal(visible, 0, 'rows exist, but app.tenant_id was never set: the database denies');
        await assert.rejects(
          bare.begin(async (tx) => {
            await tx.unsafe('SET LOCAL ROLE app_rw');
            await tx.unsafe("INSERT INTO projects (id, tenant_id, name, created_at) VALUES ('proj-x', 't1', 'x', now())");
          }),
          /persistence|row-level|policy/i,
        );
      } finally {
        await bare.end({ timeout: 1_000 });
      }
    } finally {
      store.close();
    }
  });
});

describe('M12 backup + restore rehearsal (ADR-018: restore is rehearsed, not assumed)', () => {
  test('pg_dump round trip: restored chain verifies, persistence rows match, bundle verifies', { skip: TOOLS_SKIP }, async () => {
    assert.ok(tools, 'pg_dump/psql tooling must be detected when the restore rehearsal runs');
    const dumpFile = `${tmp('restore-dump')}.sql`;
    let source: PostgresEventLog | undefined;
    let sourceStore: PersistenceStore | undefined;
    try {
      source = new PostgresEventLog({ url: DATABASE_URL!, migrateUrl: DATABASE_URL! });
      await source.whenReady();
      await pgAdmin!.unsafe(PERSISTENCE_MIGRATION.sql);

      sourceStore = new PersistenceStore({ url: DATABASE_URL! });
      const project = await sourceStore.createProject('t-restore', 'proj-1', 'Restore rehearsal');
      await sourceStore.createProject('t-other', 'proj-foreign', 'Other tenant');
      const task = await sourceStore.createTask('t-restore', 'task-1', 'proj-1', { objective: 'resume me' });
      const session = await sourceStore.saveSession('t-restore', 'sess-1', 'task-1', 'agent:t-restore-1', {
        step: 2,
        transcript: ['a', 'b'],
      });
      source.append({
        tenantId: 't-restore',
        principal: 'p1',
        actor: 'agent:t-restore-1',
        actorKind: 'agent',
        action: 'read',
        resourceId: 'r1',
        decision: 'allow',
        result: 'success',
      });
      await source.whenReady(); // drain pending writes before the dump
      source.close();
      source = undefined;

      tools.dump(DATABASE_URL!, dumpFile);
      // Recreate the target scratch database, then restore the dump into it.
      const targetDb = databaseNameOf(RESTORE_DATABASE_URL!);
      const admin = postgres(RESTORE_DATABASE_URL!, { database: 'postgres' });
      try {
        await admin.unsafe(`DROP DATABASE IF EXISTS "${targetDb}" WITH (FORCE)`);
        await admin.unsafe(`CREATE DATABASE "${targetDb}"`);
      } finally {
        await admin.end({ timeout: 1_000 });
      }
      tools.restore(RESTORE_DATABASE_URL!, dumpFile);

      const restored = new PostgresEventLog({ url: RESTORE_DATABASE_URL!, migrateUrl: RESTORE_DATABASE_URL! });
      const restoredStore = new PersistenceStore({ url: RESTORE_DATABASE_URL! });
      try {
        await restored.whenReady(); // loads and verifies the restored chain (refuses a broken one)
        assert.equal(restored.verify({ publicKey: eventPublicKey() }).valid, true);
        assert.equal(restored.all().length, 2, 'one store.migrate event + one seeded event survived the dump');

        const exp = restored.exportFor({ tenantId: 't-restore' });
        assert.equal(verifyBundle(exp, { publicKey: eventPublicKey() }).valid, true);

        assert.deepEqual(await restoredStore.getProject('t-restore', 'proj-1'), project);
        assert.deepEqual(await restoredStore.getTask('t-restore', 'task-1'), task);
        assert.deepEqual(await restoredStore.getSession('t-restore', 'sess-1'), session);
        assert.equal(
          await restoredStore.getProject('t-restore', 'proj-foreign'),
          undefined,
          'the other tenant is still isolated after the restore',
        );
      } finally {
        restoredStore.close();
        restored.close();
      }
    } finally {
      rmSync(dumpFile, { force: true });
      sourceStore?.close();
      source?.close();
    }
  });
});
