/**
 * H13 (ADR-026): Postgres revocation channel — migration 4 static invariants
 * plus live scratch-DB tests.
 *
 * DATABASE_URL must point at a DISPOSABLE scratch database. Live tests skip
 * cleanly when it is unset, mirroring tests/event-store-pg.test.ts and
 * tests/tenant-rls.test.ts.
 */

import { after, beforeEach, describe, test } from 'node:test';
import assert from 'node:assert/strict';
import postgres from 'postgres';
import { MIGRATIONS, PostgresEventLog } from '../src/event-store-pg.ts';
import { INCIDENT_MIGRATION, PostgresRevocationChannel } from '../src/incident-store-pg.ts';

const DATABASE_URL = process.env.DATABASE_URL;
const PG_SKIP = !DATABASE_URL && 'DATABASE_URL is not set (ADR-026: Postgres tests skip cleanly)';

const pgAdmin: ReturnType<typeof postgres> | undefined = DATABASE_URL ? postgres(DATABASE_URL) : undefined;

after(async () => {
  if (pgAdmin) await pgAdmin.end({ timeout: 1_000 });
});

describe('H13: revocation channel migration (static DDL invariants)', () => {
  test('migration id 4 is wired into MIGRATIONS and carries no secrets', () => {
    assert.equal(INCIDENT_MIGRATION.id, 4);
    assert.ok(MIGRATIONS.some((m) => m.id === 4), 'MIGRATIONS must include the incident migration');
    assert.equal(/PRIVATE KEY/.test(INCIDENT_MIGRATION.sql), false);
    assert.equal(/password|PEM|secret/i.test(INCIDENT_MIGRATION.sql), false);
  });

  test('append-only by privilege: app_rw gets SELECT + INSERT only, no RLS, scope is constrained', () => {
    const sql = INCIDENT_MIGRATION.sql;
    assert.match(sql, /GRANT SELECT, INSERT ON revocation_channel TO app_rw/);
    // The live run proved the sequence name: BIGSERIAL on column `seq`.
    assert.match(sql, /GRANT USAGE, SELECT ON SEQUENCE revocation_channel_seq_seq TO app_rw/);
    assert.doesNotMatch(sql, /GRANT[^;]*UPDATE/i);
    assert.doesNotMatch(sql, /GRANT[^;]*DELETE/i);
    assert.doesNotMatch(sql, /ENABLE ROW LEVEL SECURITY/i);
    assert.match(sql, /CHECK \(scope IN \('tenant', 'global'\)\)/);
    assert.match(sql, /REVOKE UPDATE, DELETE ON revocation_channel FROM PUBLIC/);
  });
});

describe('H13: Postgres revocation channel error redaction', () => {
  test('an unreachable endpoint is surfaced through health() with the URL redacted', async () => {
    const channel = new PostgresRevocationChannel({
      url: 'postgres://postgres:fake-password-for-redaction-test@127.0.0.1:1/none',
    });
    await new Promise((resolve) => setTimeout(resolve, 300));
    const health = channel.health();
    assert.ok(health.errors >= 1, 'an unreachable channel must report an error, never silently succeed');
    assert.equal(health.lastError?.includes('fake-password-for-redaction-test'), false);
    assert.equal(health.lastError?.includes('postgres://postgres'), false, health.lastError);
    assert.ok(health.lastError?.includes('endpoint 127.0.0.1:1') === true, health.lastError);
    channel.close();
    await new Promise((resolve) => setTimeout(resolve, 50));
  });
});

describe('H13: Postgres revocation channel (live, ADR-026)', () => {
  beforeEach(async () => {
    if (!pgAdmin) return;
    await pgAdmin`DROP TABLE IF EXISTS revocation_channel`;
    await pgAdmin`DROP TABLE IF EXISTS security_events`;
    await pgAdmin`DROP TABLE IF EXISTS migrations`;
  });

  async function applyMigrations(): Promise<void> {
    const store = new PostgresEventLog({ url: DATABASE_URL!, migrateUrl: DATABASE_URL! });
    await store.whenReady();
    store.close();
  }

  test('two channel instances propagate via the shared table (multi-node broadcast)', { skip: PG_SKIP }, async () => {
    await applyMigrations();
    const nodeA = new PostgresRevocationChannel({ url: DATABASE_URL! });
    const nodeB = new PostgresRevocationChannel({ url: DATABASE_URL! });
    try {
      nodeA.publish({ action: 'freeze', scope: 'tenant', tenantId: 'acme', reason: 'live broadcast', at: 1 });
      await nodeA.flush();
      nodeB.refresh();
      await nodeB.flush();
      const seen = nodeB.since(-1);
      assert.equal(seen.length, 1);
      assert.equal(seen[0]?.action, 'freeze');
      assert.equal(seen[0]?.tenantId, 'acme');
      assert.equal(nodeB.cursor(), seen[0]?.seq);
    } finally {
      nodeA.close();
      nodeB.close();
    }
  });

  test('app_rw cannot update or delete channel rows (append-only privilege)', { skip: PG_SKIP }, async () => {
    await applyMigrations();
    const node = new PostgresRevocationChannel({ url: DATABASE_URL! });
    node.publish({ action: 'unfreeze', scope: 'global', reason: 'live append-only probe', at: 2 });
    await node.flush();
    node.close();
    await assert.rejects(
      pgAdmin!.begin(async (tx) => {
        await tx.unsafe('SET LOCAL ROLE app_rw');
        await tx.unsafe("UPDATE revocation_channel SET reason = 'edited'");
      }),
      /permission denied/i,
    );
    await assert.rejects(
      pgAdmin!.begin(async (tx) => {
        await tx.unsafe('SET LOCAL ROLE app_rw');
        await tx.unsafe('DELETE FROM revocation_channel');
      }),
      /permission denied/i,
    );
  });

  test('a malformed channel row (hostile database) is refused, not applied', { skip: PG_SKIP }, async () => {
    await applyMigrations();
    await pgAdmin!`INSERT INTO revocation_channel (action, scope, tenant_id, target_id, reason, at)
      VALUES (${'exfiltrate-everything'}, ${'global'}, ${null}, ${null}, ${'hostile row'}, ${3})`;
    const node = new PostgresRevocationChannel({ url: DATABASE_URL! });
    try {
      node.refresh();
      await node.flush();
      assert.ok(node.health().errors >= 1, 'an unknown action must be a refusal');
      assert.equal(node.since(-1).some((r) => (r.action as string) === 'exfiltrate-everything'), false);
    } finally {
      node.close();
    }
  });

  test('a malformed row does not stall later rows (audit 01: skip-and-count)', { skip: PG_SKIP }, async () => {
    await applyMigrations();
    await pgAdmin!`INSERT INTO revocation_channel (action, scope, tenant_id, target_id, reason, at)
      VALUES (${'exfiltrate-everything'}, ${'global'}, ${null}, ${null}, ${'hostile row'}, ${1})`;
    await pgAdmin!`INSERT INTO revocation_channel (action, scope, tenant_id, target_id, reason, at)
      VALUES (${'unfreeze'}, ${'global'}, ${null}, ${null}, ${'good row'}, ${2})`;
    const node = new PostgresRevocationChannel({ url: DATABASE_URL! });
    try {
      node.refresh();
      await node.flush();
      assert.ok(node.health().errors >= 1, 'the bad row must be loud');
      assert.deepEqual(
        node.since(-1).map((r) => r.action),
        ['unfreeze'],
        'the good row after the bad row must apply',
      );
      assert.equal(node.cursor(), 2, 'the cursor advances past the rejected row');
    } finally {
      node.close();
    }
  });
});
