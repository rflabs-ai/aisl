/**
 * M12 Phase 2 — RLS on `security_events` (ADR-018 migration id 2) and
 * per-tenant evidence keys (ADR-018 extension of ADR-013).
 *
 * Postgres tests skip cleanly when DATABASE_URL is unset, mirroring
 * tests/event-store-pg.test.ts. DATABASE_URL must point at a DISPOSABLE
 * scratch database: this suite applies migration id 1 + the RLS migration
 * around every test.
 */

import { after, beforeEach, describe, test } from 'node:test';
import assert from 'node:assert/strict';
import {
  createCipheriv,
  createDecipheriv,
  hkdfSync,
  randomBytes,
} from 'node:crypto';
import postgres from 'postgres';
import { MIGRATIONS } from '../src/event-store-pg.ts';
import { RLS_MIGRATION } from '../src/tenant-rls.ts';
import {
  classificationFromKeyId,
  keyIdFor,
  keyIdForTenant,
  open,
  openFor,
  seal,
  sealFor,
  type Sealed,
} from '../src/seal.ts';

const DATABASE_URL = process.env.DATABASE_URL;
const PG_SKIP = !DATABASE_URL && 'DATABASE_URL is not set (ADR-018: Postgres tests skip cleanly)';

// Fixed master key so the hand-derived HKDF contract tests are deterministic.
process.env.EVIDENCE_SEALING_KEY = 'tenant-rls-test-master-key';
const MASTER = Buffer.from('tenant-rls-test-master-key', 'utf8');
const SALT = Buffer.from('ai-security-layer/evidence/v1');

/** Independent re-derivation of the documented HKDF contract (key = HKDF(info)). */
function deriveKey(info: string): Buffer {
  return Buffer.from(hkdfSync('sha256', MASTER, SALT, Buffer.from(info), 32));
}

/** Seal with an explicitly supplied key, independent of src/seal.ts internals. */
function handSeal(keyId: string, key: Buffer, plaintext: string): Sealed {
  const iv = randomBytes(12);
  const cipher = createCipheriv('aes-256-gcm', key, iv);
  const ciphertext = Buffer.concat([cipher.update(plaintext, 'utf8'), cipher.final()]);
  return {
    keyId,
    iv: iv.toString('base64'),
    tag: cipher.getAuthTag().toString('base64'),
    ciphertext: ciphertext.toString('base64'),
  };
}

describe('M12 Phase 2: tenant-bound evidence keys (extends ADR-013)', () => {
  test('sealFor/openFor roundtrip for the owning tenant', () => {
    const sealed = sealFor('tenant-a', 'tenant-a-content', 'confidential');
    assert.equal(openFor('tenant-a', sealed), 'tenant-a-content');
    assert.equal(open(sealed), 'tenant-a-content');
  });

  test('another tenant cannot open the seal — wrong key fails the GCM tag', () => {
    const sealed = sealFor('tenant-a', 'tenant-a-content', 'internal');
    assert.equal(openFor('tenant-b', sealed), undefined);
    const resealed = handSeal(sealed.keyId, deriveKey('evidence:tenant-b:internal'), 'forged');
    assert.equal(openFor('tenant-b', resealed), 'forged');
    assert.equal(openFor('tenant-a', resealed), undefined, 'a forged keyId does not cross tenants');
  });

  test('keyIds carry the v2 shape, tenant, and classification; legacy keyId is unchanged', () => {
    assert.equal(keyIdForTenant('tenant-a', 'confidential'), 'evidence-key:v2:tenant-a:confidential');
    assert.equal(keyIdFor('internal'), 'evidence-key:internal');
    assert.equal(classificationFromKeyId(keyIdForTenant('tenant-x', 'pii')), 'pii');
    assert.equal(classificationFromKeyId('evidence-key:internal'), 'internal');
    assert.equal(classificationFromKeyId('garbage'), 'x-unknown');
  });

  test('legacy sealed records still open under the legacy derivation — no silent re-encryption', () => {
    // The pre-ADR-018 formula, verbatim: HKDF info `evidence:<classification>`.
    const legacy = handSeal('evidence-key:internal', deriveKey('evidence:internal'), 'old-record');
    assert.equal(open(legacy), 'old-record');
    assert.equal(openFor('tenant-a', legacy), 'old-record', 'legacy seals ignore the tenant argument');
    assert.equal(openFor('tenant-b', legacy), 'old-record');
    assert.equal(seal('old-record', 'internal').keyId, 'evidence-key:internal');
  });

  test('the v2 HKDF info is exactly evidence:<tenantId>:<classification> (hand-derived contract)', () => {
    const sealed = sealFor('tenant-a', 'contract', 'confidential');
    const key = deriveKey('evidence:tenant-a:confidential');
    const decipher = createDecipheriv('aes-256-gcm', key, Buffer.from(sealed.iv, 'base64'));
    decipher.setAuthTag(Buffer.from(sealed.tag, 'base64'));
    assert.equal(
      Buffer.concat([decipher.update(Buffer.from(sealed.ciphertext, 'base64')), decipher.final()]).toString('utf8'),
      'contract',
    );
    // The legacy info string must NOT decrypt a tenant-bound seal.
    assert.equal(open({ ...sealed, keyId: keyIdFor('confidential') }), undefined);
  });

  test('dispatch is on keyId shape: legacy ciphertext under a v2 keyId does not open', () => {
    const forged: Sealed = handSeal(
      keyIdForTenant('tenant-a', 'internal'),
      deriveKey('evidence:internal'),
      'forged',
    );
    assert.equal(open(forged), undefined, 'a v2 keyId must use the tenant derivation, not the legacy one');
    assert.equal(openFor('tenant-a', forged), undefined);
  });

  test('invalid tenants and unknown keyId shapes fail closed (undefined, no throw)', () => {
    const sealed = sealFor('tenant-a', 'x', 'internal');
    assert.throws(() => sealFor('a:b', 'x', 'internal'));
    assert.throws(() => sealFor('', 'x', 'internal'));
    assert.throws(() => sealFor('a b', 'x', 'internal'));
    assert.throws(() => keyIdForTenant('a:b', 'internal'));
    assert.equal(openFor('a:b', sealed), undefined);
    assert.equal(openFor('', sealed), undefined);
    assert.equal(open({ keyId: 'evidence-key:v2:notenant', iv: sealed.iv, tag: sealed.tag, ciphertext: sealed.ciphertext }), undefined);
    assert.equal(open({ keyId: 'other-shape', iv: sealed.iv, tag: sealed.tag, ciphertext: sealed.ciphertext }), undefined);
    const tampered = { ...sealed, tag: Buffer.from('tampered-tampered-tampered-ta').toString('base64') };
    assert.equal(openFor('tenant-a', tampered), undefined);
  });

  test('structural: a sealed object carries no plaintext content and the keyId is tenant + level only', () => {
    const sealed = sealFor('tenant-a', 'tenant-a-content', 'confidential');
    assert.deepEqual(Object.keys(sealed).sort(), ['ciphertext', 'iv', 'keyId', 'tag']);
    assert.equal(JSON.stringify(sealed).includes('tenant-a-content'), false);
    assert.equal(sealed.keyId, 'evidence-key:v2:tenant-a:confidential');
  });
});

describe('M12 Phase 2 RLS: migration id 2 DDL invariants', () => {
  test('static deny-by-default DDL: per-role policies, revokes, triggers, no secrets', () => {
    assert.equal(RLS_MIGRATION.id, 2);
    const sql = RLS_MIGRATION.sql;
    assert.ok(sql.includes('ALTER TABLE security_events ENABLE ROW LEVEL SECURITY'));
    assert.ok(sql.includes('ALTER TABLE security_events FORCE ROW LEVEL SECURITY'));
    assert.ok(sql.includes('FOR SELECT TO app_rw'));
    assert.ok(sql.includes('USING (true)'));
    assert.ok(sql.includes('FOR INSERT TO app_rw'));
    assert.ok(sql.includes('WITH CHECK (true)'));
    assert.ok(sql.includes("FOR SELECT TO app_reader"));
    assert.ok(sql.includes("USING (tenant_id = current_setting('app.tenant_id', true))"));
    assert.ok(sql.includes('REVOKE UPDATE, DELETE ON security_events FROM app_rw'));
    assert.ok(sql.includes('REVOKE UPDATE, DELETE ON security_events FROM PUBLIC'));
    assert.ok(sql.includes('GRANT USAGE ON SCHEMA public TO app_rw'));
    assert.ok(sql.includes('GRANT SELECT, INSERT ON security_events TO app_rw'));
    assert.ok(sql.includes('GRANT USAGE ON SCHEMA public TO app_reader'));
    assert.ok(sql.includes('GRANT SELECT ON security_events TO app_reader'));
    assert.ok(sql.includes('BEFORE UPDATE ON security_events'));
    assert.ok(sql.includes('BEFORE DELETE ON security_events'));
    // Role bootstrap is the runner's cluster-level job, not a table migration;
    // no credentials or dynamic SQL ever appear in migration text.
    assert.doesNotMatch(sql, /create\s+role|password|login\s|identified|grant\s+on\s+all/i);
  });
});

const pgAdmin: ReturnType<typeof postgres> | undefined = DATABASE_URL ? postgres(DATABASE_URL) : undefined;

after(async () => {
  if (pgAdmin) await pgAdmin.end({ timeout: 1_000 });
});

beforeEach(async () => {
  if (!pgAdmin) return;
  await pgAdmin`DROP TABLE IF EXISTS security_events`;
  await pgAdmin`DROP TABLE IF EXISTS migrations`;
});

/** Mirror of the runner's bootstrap + migrations id 1 and 2, applied directly. */
async function applySchema(): Promise<void> {
  await pgAdmin!.unsafe(`
    DO $$ BEGIN
      IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname = 'app_rw') THEN
        CREATE ROLE app_rw NOLOGIN;
      END IF;
      IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname = 'app_reader') THEN
        CREATE ROLE app_reader NOLOGIN;
      END IF;
    END $$;
  `);
  await pgAdmin!.unsafe(MIGRATIONS[0]!.sql);
  await pgAdmin!.unsafe(RLS_MIGRATION.sql);
}

/** Seed t1 x2 and t2 x1 directly via SQL (superuser bypasses RLS). */
async function seedRows(): Promise<void> {
  for (const row of [
    { seq: 0, tenantId: 't1' },
    { seq: 1, tenantId: 't1' },
    { seq: 2, tenantId: 't2' },
  ]) {
    await pgAdmin!`INSERT INTO security_events (seq, tenant_id, timestamp, event_hash, event) VALUES (${row.seq}, ${row.tenantId}, ${0}, ${'h'.repeat(64)}, ${'{}'})`;
  }
}

/**
 * `SELECT set_config('app.tenant_id', ..., true)` is the parameterized
 * equivalent of `SET LOCAL app.tenant_id` (SET takes no bound parameters on
 * the wire) — both are transaction-local, which is what the policy reads.
 */
async function readUnder(role: 'app_reader' | 'app_rw', tenantId: string | null): Promise<string[]> {
  return pgAdmin!.begin(async (tx) => {
    await tx.unsafe(`SET LOCAL ROLE ${role}`);
    if (tenantId !== null) await tx`SELECT set_config('app.tenant_id', ${tenantId}, true)`;
    const rows = await tx`SELECT tenant_id FROM security_events ORDER BY seq` as { tenant_id: string }[];
    return rows.map((r) => r.tenant_id);
  });
}

describe('M12 Phase 2 RLS: cross-tenant proof on Postgres (ADR-018)', { skip: PG_SKIP }, () => {
  test('a hostile reader with NO tenant context reads zero rows (fail closed)', async () => {
    await applySchema();
    await seedRows();
    assert.deepEqual(await readUnder('app_reader', null), []);
  });

  test('a hostile reader with a wrong tenant context reads zero rows', async () => {
    await applySchema();
    await seedRows();
    assert.deepEqual(await readUnder('app_reader', 'no-such-tenant'), []);
  });

  test('the honest reader sees only its own tenant, never the other tenant', async () => {
    await applySchema();
    await seedRows();
    assert.deepEqual(await readUnder('app_reader', 't1'), ['t1', 't1']);
    assert.deepEqual(await readUnder('app_reader', 't2'), ['t2']);
  });

  test('app_reader cannot insert even with tenant context set', async () => {
    await applySchema();
    await seedRows();
    await assert.rejects(
      pgAdmin!.begin(async (tx) => {
        await tx.unsafe('SET LOCAL ROLE app_reader');
        await tx`SELECT set_config('app.tenant_id', ${'t1'}, true)`;
        await tx`INSERT INTO security_events (seq, tenant_id, timestamp, event_hash, event) VALUES (${99}, ${'t1'}, ${0}, ${'h'.repeat(64)}, ${'{}'})`;
      }),
      /permission denied|row-level/i,
    );
    assert.equal((await pgAdmin!`SELECT seq FROM security_events WHERE seq = 99`).length, 0);
  });

  test('app_rw cannot update or delete: privileges revoked, trigger as braces', async () => {
    await applySchema();
    await seedRows();
    await assert.rejects(
      pgAdmin!.begin(async (tx) => {
        await tx.unsafe('SET LOCAL ROLE app_rw');
        await tx.unsafe('UPDATE security_events SET timestamp = timestamp + 1');
      }),
      /permission denied|append-only/i,
    );
    await assert.rejects(
      pgAdmin!.begin(async (tx) => {
        await tx.unsafe('SET LOCAL ROLE app_rw');
        await tx.unsafe('DELETE FROM security_events');
      }),
      /permission denied|append-only/i,
    );
  });

  test('append-only triggers raise even for a superuser (belt and braces)', async () => {
    await applySchema();
    await seedRows();
    await assert.rejects(pgAdmin!`UPDATE security_events SET timestamp = timestamp + 1`, /append-only/i);
    await assert.rejects(pgAdmin!`DELETE FROM security_events`, /append-only/i);
    assert.equal((await pgAdmin!`SELECT seq FROM security_events ORDER BY seq` as { seq: number }[]).length, 3);
  });

  test('app_rw reads the whole global chain across tenants and appends', async () => {
    await applySchema();
    await seedRows();
    assert.deepEqual(await readUnder('app_rw', null), ['t1', 't1', 't2'], 'app_rw is the chain verifier: unfiltered reads');
    await pgAdmin!.begin(async (tx) => {
      await tx.unsafe('SET LOCAL ROLE app_rw');
      await tx`INSERT INTO security_events (seq, tenant_id, timestamp, event_hash, event) VALUES (${99}, ${'t3'}, ${0}, ${'h'.repeat(64)}, ${'{}'})`;
    });
    assert.deepEqual(await readUnder('app_reader', 't3'), ['t3']);
  });

  test('the RLS migration is idempotent: re-applying changes nothing and does not throw', async () => {
    await applySchema();
    await seedRows();
    await pgAdmin!.unsafe(RLS_MIGRATION.sql);
    assert.deepEqual(await readUnder('app_reader', 't1'), ['t1', 't1']);
  });
});
