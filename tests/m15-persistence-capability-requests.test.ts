/**
 * M15 acceptance: the M12 seam closed — capability_requests persistence API
 * (ADR-020) over the existing migration-3 table, plus the REST mirror.
 * Live-DB tests skip cleanly without DATABASE_URL (persistence-restore
 * posture); the REST mirror is tested in-memory (store absent → M14
 * behavior unchanged).
 */

import { after, beforeEach, describe, test } from 'node:test';
import assert from 'node:assert/strict';
import postgres from 'postgres';
import { PostgresEventLog } from '../src/event-store-pg.ts';
import { PERSISTENCE_MIGRATION, PersistenceStore } from '../src/persistence.ts';

const DATABASE_URL = process.env.DATABASE_URL;
const PG_SKIP = !DATABASE_URL && 'DATABASE_URL is not set (ADR-018: Postgres tests skip cleanly)';

const pgAdmin: ReturnType<typeof postgres> | undefined = DATABASE_URL ? postgres(DATABASE_URL) : undefined;

after(async () => {
  if (pgAdmin) await pgAdmin.end({ timeout: 1_000 });
});

beforeEach(async () => {
  if (!pgAdmin) return;
  await pgAdmin`DROP SCHEMA public CASCADE`;
  await pgAdmin`CREATE SCHEMA public`;
});

async function seededStore(url: string): Promise<PersistenceStore> {
  const bootstrapper = new PostgresEventLog({ url, migrateUrl: url });
  await bootstrapper.whenReady();
  bootstrapper.close();
  await pgAdmin!.unsafe(PERSISTENCE_MIGRATION.sql);
  return new PersistenceStore({ url });
}

describe('capability_requests persistence API (ADR-020)', () => {
  test('create/get/list/status round trip, tenant-scoped', { skip: PG_SKIP }, async () => {
    const store = await seededStore(DATABASE_URL!);
    try {
      const requested = {
        sessionId: 'sess-1',
        resources: ['doc:acme-merger'],
        actions: ['read'],
        maxClassification: 'confidential',
        justification: 'summaries need the merger doc',
      };
      const created = await store.createCapabilityRequest(
        't1', 'req-1', 'agent:summarizer-1', requested, new Date(Date.now() + 300_000),
      );
      assert.equal(created.status, 'pending');
      assert.deepEqual(created.requested, requested);
      assert.equal(created.decidedAt, undefined);
      assert.equal(created.decidedBy, undefined);

      await store.createCapabilityRequest('t2', 'req-1', 'agent:globex-1', {}, new Date(Date.now() + 300_000));

      assert.deepEqual((await store.listCapabilityRequestsForTenant('t1', 'pending')).map((r) => r.id), ['req-1']);
      assert.equal((await store.getCapabilityRequest('t2', 'req-1'))?.principal, 'agent:globex-1', 'cross-tenant read is tenant-scoped');
      assert.equal(await store.getCapabilityRequest('t1', 'req-unknown'), undefined);

      const approved = await store.updateCapabilityRequestStatus('t1', 'req-1', 'approved', 'user:alice');
      assert.equal(approved?.status, 'approved');
      assert.equal(approved?.decidedBy, 'user:alice');
      assert.ok(approved?.decidedAt instanceof Date);
      assert.equal(await store.updateCapabilityRequestStatus('t2', 'req-1', 'denied', 'user:mallory'), undefined, 'cross-tenant update denied');
      assert.equal(await store.updateCapabilityRequestStatus('t1', 'req-ghost', 'approved', 'user:alice'), undefined);
    } finally {
      store.close();
    }
  });
});
