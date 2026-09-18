/**
 * M12 Phase 1 — EventStore port + Postgres backend (ADR-018).
 *
 * The core evidence behaviors run against every backend in the parity loop:
 * in-memory EventLog, SQLite EventLog (temp file), and PostgresEventLog when
 * DATABASE_URL is set. Postgres tests skip cleanly when DATABASE_URL is unset,
 * mirroring the container-sandbox fallback pattern.
 *
 * DATABASE_URL must point at a DISPOSABLE scratch database: the Postgres
 * suites drop and recreate their tables around every test.
 */

import { after, beforeEach, describe, test } from 'node:test';
import assert from 'node:assert/strict';
import { rmSync } from 'node:fs';
import { createHash } from 'node:crypto';
import { DatabaseSync } from 'node:sqlite';
import postgres from 'postgres';
import {
  EventLog,
  eventPublicKey,
  verifyBundle,
  type EventStore,
  type SecurityEvent,
} from '../src/events.ts';
import { MIGRATIONS, PostgresEventLog } from '../src/event-store-pg.ts';
import { ResourceRegistry, defineResource } from '../src/registry.ts';
import { AuthorizationService } from '../src/pdp.ts';
import { createPolicyEngine } from '../src/policy.ts';
import { mockAuth } from '../src/testing.ts';
import { type Principal } from '../src/domain.ts';

const DATABASE_URL = process.env.DATABASE_URL;
const UNREACHABLE_URL = 'postgres://postgres:fake-password-for-redaction-test@127.0.0.1:1/none';
const PG_SKIP = !DATABASE_URL && 'DATABASE_URL is not set (ADR-018: Postgres tests skip cleanly)';

function tmp(name: string): string {
  return `${process.env.TEMP ?? '.'}\\ai-security-layer-m12-${name}-${Date.now()}-${Math.random().toString(36).slice(2)}`;
}

function sha256(text: string): string {
  return createHash('sha256').update(text, 'utf8').digest('hex');
}

const pgAdmin: ReturnType<typeof postgres> | undefined = DATABASE_URL ? postgres(DATABASE_URL) : undefined;

after(async () => {
  if (pgAdmin) await pgAdmin.end({ timeout: 1_000 });
});

// DATABASE_URL points at a disposable scratch database: wipe before every test
// so each test starts from a fresh (or absent) schema.
beforeEach(async () => {
  if (!pgAdmin) return;
  await pgAdmin`DROP TABLE IF EXISTS security_events`;
  await pgAdmin`DROP TABLE IF EXISTS migrations`;
});

function seed(store: EventStore): SecurityEvent[] {
  return [
    store.append({ tenantId: 't1', principal: 'p1', actor: 'agent:1', actorKind: 'agent', action: 'read', resourceId: 'r1', decision: 'allow', result: 'success' }),
    store.append({ tenantId: 't1', principal: 'p2', actor: 'agent:2', actorKind: 'agent', action: 'write', resourceId: 'r2', decision: 'deny', denyReason: 'no-capability', result: 'denied' }),
    store.append({ tenantId: 't2', principal: 'p3', actor: 'agent:3', actorKind: 'agent', action: 'read', resourceId: 'r3', decision: 'allow', result: 'success' }),
  ];
}

interface Opened {
  readonly store: EventStore;
  ready(): Promise<void>;
  cleanup(): void;
}

interface BackendDef {
  readonly name: string;
  open(options?: { anchorPath?: string }): Opened;
}

const backends: BackendDef[] = [
  {
    name: 'memory',
    open: (options = {}) => {
      const store = new EventLog(undefined, options);
      return { store, ready: async () => {}, cleanup: () => {} };
    },
  },
  {
    name: 'sqlite',
    open: (options = {}) => {
      const path = `${tmp('parity')}.db`;
      const store = new EventLog(path, options);
      return { store, ready: async () => {}, cleanup: () => { store.close(); rmSync(path, { force: true }); } };
    },
  },
  ...(DATABASE_URL
    ? [{
        name: 'postgres',
        open: (options: { anchorPath?: string } = {}) => {
          const store = new PostgresEventLog({ url: DATABASE_URL!, migrateUrl: DATABASE_URL!, anchorPath: options.anchorPath });
          return { store, ready: () => store.whenReady(), cleanup: () => store.close() };
        },
      }]
    : []),
];

describe('M12 EventStore parity across backends', () => {
  for (const backend of backends) {
    describe(`backend: ${backend.name}`, () => {
      test('append is recorded, verifies, and bundles offline', async () => {
        const { store, ready, cleanup } = backend.open();
        try {
          await ready();
          const base = store.all().length; // postgres records one store.migrate event at startup
          const seeded = seed(store);
          await ready(); // drain pending postgres writes
          assert.equal(store.all().length, base + seeded.length);
          assert.equal(store.verify().valid, true);
          assert.equal(store.verify({ publicKey: eventPublicKey() }).valid, true);
          const bundle = store.bundle();
          assert.equal((JSON.parse(bundle) as { events: unknown[] }).events.length, base + seeded.length);
          assert.equal(verifyBundle(bundle, { publicKey: eventPublicKey() }).valid, true);
        } finally {
          cleanup();
        }
      });

      test('forTenant returns only that tenant', async () => {
        const { store, ready, cleanup } = backend.open();
        try {
          await ready();
          seed(store);
          await ready();
          assert.equal(store.forTenant('t1').length, 2);
          assert.equal(store.forTenant('t2').length, 1);
          assert.equal(store.forTenant('no-such-tenant').length, 0);
        } finally {
          cleanup();
        }
      });

      test('query filters: tenant, actor, action, decision, resourceId, seq/time bounds, limit/offset', async () => {
        const { store, ready, cleanup } = backend.open();
        try {
          await ready();
          const seeded = seed(store);
          await ready();
          const t1 = seeded.filter((e) => e.tenantId === 't1');
          assert.equal(store.query({ tenantId: 't1' }).length, 2);
          assert.equal(store.query({ tenantId: 't1', actor: 'agent:1' }).length, 1);
          assert.equal(store.query({ tenantId: 't1', action: '*' }).length, 2);
          assert.equal(store.query({ tenantId: 't1', action: 'read' }).length, 1);
          assert.equal(store.query({ tenantId: 't1', decision: 'deny' }).length, 1);
          assert.equal(store.query({ tenantId: 't1', resourceId: 'r2' }).length, 1);
          assert.equal(store.query({ tenantId: 't1', limit: 1 }).length, 1);
          assert.equal(store.query({ tenantId: 't1', limit: 1, offset: 1 })[0]!.seq, t1[1]!.seq);
          assert.equal(store.query({ tenantId: 't1', fromSeq: t1[0]!.seq, toSeq: t1[0]!.seq }).length, 1);
          assert.equal(store.query({ tenantId: 't1', fromTime: Date.now() + 1_000_000 }).length, 0);
          assert.equal(store.query({ tenantId: 't2' }).length, 1);
          assert.throws(() => store.query({ tenantId: '   ' }), /tenantId is required/);
        } finally {
          cleanup();
        }
      });

      test('exportFor shape: fromSeq/toSeq/head/previousHead', async () => {
        const { store, ready, cleanup } = backend.open();
        try {
          await ready();
          seed(store);
          await ready();
          const t1 = store.query({ tenantId: 't1' });
          const exp = store.exportFor({ tenantId: 't1' });
          assert.equal(exp.tenantId, 't1');
          assert.equal(exp.events.length, t1.length);
          assert.equal(exp.fromSeq, t1[0]!.seq);
          assert.equal(exp.toSeq, t1.at(-1)!.seq);
          assert.equal(exp.head, t1.at(-1)!.eventHash);
          assert.equal(exp.previousHead, t1[0]!.seq === 0 ? null : t1[0]!.previousEventHash);

          const empty = store.exportFor({ tenantId: 'no-such-tenant' });
          assert.equal(empty.events.length, 0);
          assert.equal(empty.head, '');
          assert.equal(empty.previousHead, null);
        } finally {
          cleanup();
        }
      });

      test('anchor file receives one line per append', async () => {
        const anchorPath = `${tmp('anchor')}.anchor`;
        const { store, ready, cleanup } = backend.open({ anchorPath });
        try {
          await ready();
          seed(store);
          await ready();
          const lines = store.anchor().trim().split('\n');
          assert.equal(lines.length, store.all().length);
          for (const line of lines) assert.match(line!, /^\d+:[0-9a-f]{64}$/);
          const last = store.all().at(-1)!;
          assert.equal(lines.at(-1), `${last.seq}:${last.eventHash}`);
        } finally {
          cleanup();
          rmSync(anchorPath, { force: true });
        }
      });

      test('mutating a loaded event breaks verify', async () => {
        const { store, ready, cleanup } = backend.open();
        try {
          await ready();
          seed(store);
          await ready();
          const mutable = store.all()[0] as { action: string };
          mutable.action = 'delete';
          const result = store.verify({ publicKey: eventPublicKey() });
          assert.equal(result.valid, false);
          assert.match(result.detail ?? '', /hash|signature/);
        } finally {
          cleanup();
        }
      });
    });
  }
});

describe('M12 EventStore persistence parity: sqlite', () => {
  test('second instance resumes across restart and continues the seq', () => {
    const path = `${tmp('restart')}.db`;
    try {
      const a = new EventLog(path);
      seed(a);
      a.close();
      const b = new EventLog(path);
      assert.equal(b.all().length, 3);
      const next = b.append({ tenantId: 't1', principal: 'p', actor: 'a', actorKind: 'agent', action: 'read', result: 'success' });
      assert.equal(next.seq, 3);
      assert.equal(b.verify({ publicKey: eventPublicKey() }).valid, true);
      b.close();
    } finally {
      rmSync(path, { force: true });
    }
  });

  test('a tampered store refuses to be extended', () => {
    const path = `${tmp('tamper')}.db`;
    try {
      const a = new EventLog(path);
      a.append({ tenantId: 't1', principal: 'p', actor: 'a', actorKind: 'agent', action: 'read', result: 'success' });
      a.close();
      // An attacker with file access can drop the belt-and-braces trigger and
      // edit a row; the chain check at resume must refuse the store.
      const db = new DatabaseSync(path);
      db.exec('DROP TRIGGER IF EXISTS security_events_no_update');
      db.exec(`UPDATE security_events SET event = replace(event, '"result":"success"', '"result":"error"') WHERE seq = 0`);
      db.close();
      assert.throws(() => new EventLog(path), /refusing to append/);
    } finally {
      rmSync(path, { force: true });
    }
  });
});

describe('M12 EventStore persistence parity: postgres', () => {
  test('second instance resumes across restart and continues the seq', { skip: PG_SKIP }, async () => {
    const a = new PostgresEventLog({ url: DATABASE_URL!, migrateUrl: DATABASE_URL! });
    await a.whenReady();
    const base = a.all().length;
    seed(a);
    await a.whenReady(); // drain pending inserts
    a.close();

    // Second instance without a migration role: migrations must already be applied.
    const b = new PostgresEventLog({ url: DATABASE_URL! });
    await b.whenReady();
    assert.equal(b.all().length, base + 3);
    const next = b.append({ tenantId: 't1', principal: 'p', actor: 'a', actorKind: 'agent', action: 'read', result: 'success' });
    await b.whenReady();
    assert.equal(next.seq, base + 3);
    assert.equal(b.verify({ publicKey: eventPublicKey() }).valid, true);
    b.close();
  });

  test('a tampered store refuses to be extended', { skip: PG_SKIP }, async () => {
    const a = new PostgresEventLog({ url: DATABASE_URL!, migrateUrl: DATABASE_URL! });
    await a.whenReady();
    a.append({ tenantId: 't1', principal: 'p', actor: 'a', actorKind: 'agent', action: 'read', result: 'success' });
    await a.whenReady();
    a.close();

    // Privileged direct-SQL tamper: the append-only guard (migration id 2)
    // must be disarmed by the same privileged actor that tampers, exactly
    // like the SQLite file-level tamper this test mirrors — the resume
    // chain check must then refuse the store.
    await pgAdmin!`DROP TRIGGER IF EXISTS security_events_no_update ON security_events`;
    await pgAdmin!`UPDATE security_events SET event = replace(event, '"result":"success"', '"result":"error"')`;

    const b = new PostgresEventLog({ url: DATABASE_URL! });
    await assert.rejects(b.whenReady(), /refusing to append|chain invalid/);
    assert.equal(b.all().length, 0, 'a broken chain must not be loaded');
    assert.throws(() => b.append({ tenantId: 't1', principal: 'p', actor: 'a', actorKind: 'agent', action: 'read', result: 'success' }), /refus|unavailable|failed/);
    b.close();
  });
});

describe('M12 postgres migrations', () => {
  test('fresh database: migrations apply, are recorded with sha256 hashes, and emit one store.migrate event', { skip: PG_SKIP }, async () => {
    const store = new PostgresEventLog({ url: DATABASE_URL!, migrateUrl: DATABASE_URL! });
    try {
      await store.whenReady();
      const rows = await pgAdmin!`SELECT id, hash FROM migrations ORDER BY id`;
      assert.equal(rows.length, MIGRATIONS.length);
      rows.forEach((row, i) => {
        assert.equal(row.id, MIGRATIONS[i]!.id);
        assert.equal(row.hash, sha256(MIGRATIONS[i]!.sql));
      });
      const migrateEvents = store.all().filter((e) => e.action === 'store.migrate');
      assert.equal(migrateEvents.length, 1);
      const migrateEvent = migrateEvents[0]!;
      assert.equal(migrateEvent.actorKind, 'service');
      assert.equal(migrateEvent.result, 'success');
      const meta = migrateEvent.metadata as { applied: { id: number; hash: string }[] };
      assert.deepEqual(
        meta.applied.map((a) => a.id),
        MIGRATIONS.map((m) => m.id),
      );
      assert.equal(store.verify({ publicKey: eventPublicKey() }).valid, true);
    } finally {
      store.close();
    }
  });

  test('re-running migrations applies nothing new and emits no second store.migrate event', { skip: PG_SKIP }, async () => {
    const a = new PostgresEventLog({ url: DATABASE_URL!, migrateUrl: DATABASE_URL! });
    await a.whenReady();
    a.close();
    const recorded = await pgAdmin!`SELECT id FROM migrations`;
    assert.equal(recorded.length, MIGRATIONS.length);

    const b = new PostgresEventLog({ url: DATABASE_URL!, migrateUrl: DATABASE_URL! });
    try {
      await b.whenReady();
      assert.equal((await pgAdmin!`SELECT id FROM migrations`).length, recorded.length, 'nothing new applied');
      assert.equal(b.all().filter((e) => e.action === 'store.migrate').length, 1, 'no second migrate event for an already-applied batch');
    } finally {
      b.close();
    }
  });

  test('a recorded migration with a changed hash throws (tamper refusal)', { skip: PG_SKIP }, async () => {
    const a = new PostgresEventLog({ url: DATABASE_URL!, migrateUrl: DATABASE_URL! });
    await a.whenReady();
    a.close();
    await pgAdmin!`UPDATE migrations SET hash = ${'f'.repeat(64)} WHERE id = ${MIGRATIONS[0]!.id}`;

    const b = new PostgresEventLog({ url: DATABASE_URL!, migrateUrl: DATABASE_URL! });
    await assert.rejects(b.whenReady(), /hash mismatch/);
    b.close();
  });

  test('without a migration role, unapplied migrations fail the connect (fail closed)', { skip: PG_SKIP }, async () => {
    const store = new PostgresEventLog({ url: DATABASE_URL! });
    await assert.rejects(store.whenReady(), /migration|not been applied/);
    assert.throws(() => store.append({ tenantId: 't1', principal: 'p', actor: 'a', actorKind: 'agent', action: 'read', result: 'success' }), /refus|unavailable|failed/);
    assert.equal(store.all().length, 0);
    store.close();
  });
});

describe('M12 postgres fail-closed (H15)', () => {
  test('an unreachable database fails loudly: no fallback, no appends', { skip: PG_SKIP }, async () => {
    const store = new PostgresEventLog({ url: UNREACHABLE_URL });
    await assert.rejects(store.whenReady(), /unavailable|failed/i);
    assert.throws(() => store.append({ tenantId: 't1', principal: 'p', actor: 'a', actorKind: 'agent', action: 'read', result: 'success' }), /refus|unavailable|failed/i);
    assert.equal(store.all().length, 0, 'the in-memory chain reflects the refusal: nothing was appended');
    store.close();
  });

  test('an unavailable store denies with the distinct store-unavailable reason (H15, no DB needed)', async () => {
    // No DATABASE_URL and no server: after the connect fails, every append is
    // a typed refusal — the PDP must surface that as store-unavailable, not
    // the generic evidence-write-failure. (During 'connecting', appends queue
    // for the startup race and must NOT deny — false denials are a regression
    // of the M10 false-denial budget.)
    const broken = new PostgresEventLog({ url: UNREACHABLE_URL });
    await assert.rejects(broken.whenReady(), /unavailable/i);
    const registry = new ResourceRegistry();
    registry.add(defineResource({ id: 'r1', type: 'document', tenantId: 'acme', classification: 'internal' }));
    const principal: Principal = { id: 'agent:x', kind: 'agent', tenantId: 'acme', roles: [], attributes: {}, auth: mockAuth({ subject: 'agent:x' }) };
    const authz = new AuthorizationService(
      registry,
      createPolicyEngine([{ id: 'allow-read', effect: 'allow', principals: {}, actions: ['read'], resources: {} }]),
      broken,
      () => 1,
    );
    const decision = authz.authorize({ principal, action: 'read', resourceId: 'r1' });
    assert.equal(decision.decision, 'deny');
    assert.equal(decision.denyReason, 'store-unavailable');
    broken.close();
  });

  test('error messages never carry the URL or its credentials (structural secret test)', { skip: PG_SKIP }, async () => {
    const store = new PostgresEventLog({ url: UNREACHABLE_URL });
    let connectError = '';
    try {
      await store.whenReady();
    } catch (e) {
      connectError = (e as Error).message;
    }
    assert.ok(connectError.length > 0);
    assert.equal(connectError.includes(UNREACHABLE_URL), false);
    assert.equal(connectError.includes('fake-password-for-redaction-test'), false);

    let appendError = '';
    try {
      store.append({ tenantId: 't1', principal: 'p', actor: 'a', actorKind: 'agent', action: 'read', result: 'success' });
    } catch (e) {
      appendError = (e as Error).message;
    }
    assert.ok(appendError.length > 0);
    assert.equal(appendError.includes('fake-password-for-redaction-test'), false);
    store.close();
  });
});
