/**
 * M6: Audit Query + Export API tests.
 *
 * Verifies that the audit plane can be queried and exported:
 * 1. Authorized (capability AND policy, fail-closed).
 * 2. Tenant-scoped (no cross-tenant reads).
 * 3. Events return with Ed25519 signatures intact for offline verifyBundle().
 * 4. Synthetic audit-log resource model gates access.
 * 5. Sealing remains intact (no plaintext leaks).
 */

import { test, describe } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import {
  AuditQueryService,
  AuditFilterError,
  type AuditFilters,
  type AuditExport,
} from '../src/audit-query.ts';
import { EventLog, verifyBundle, eventPublicKey, type SecurityEvent } from '../src/events.ts';
import { AuthorizationService } from '../src/pdp.ts';
import { createPolicyEngine, type PolicyRule } from '../src/policy.ts';
import { ResourceRegistry } from '../src/registry.ts';
import { testWorld, mockAuth, unauthPrincipal, testUser } from '../src/testing.ts';
import { TENANT_A, TENANT_B, buildWorld } from '../src/scenario.ts';
import { type Principal } from '../src/domain.ts';

const AUDIT_POLICY_RULE: PolicyRule = {
  id: 'allow-user-audit',
  description: 'Users may query and export the audit log for their tenant with capability.',
  effect: 'allow',
  principals: { kinds: ['user'] },
  actions: ['query.audit', 'audit.export'],
  resources: { types: ['audit-log'] },
};

function issueAuditCap(
  world: ReturnType<typeof testWorld>,
  subject: string,
  actions: readonly ('query.audit' | 'audit.export')[] = ['query.audit', 'audit.export'],
  tenantId = TENANT_A,
) {
  return world.authorization.issue(world.root, {
    subject,
    tenantId,
    resourceIds: [`audit-log:${tenantId}`],
    actions: actions as any,
    maxClassification: 'internal',
    expiresAt: world.clock.now() + 3_600_000,
    provenance: { source: 'policy-grant', note: 'audit capability' },
  });
}

function setupAuditTestWorld(customPolicies: readonly PolicyRule[] = [AUDIT_POLICY_RULE]) {
  const world = testWorld({ policies: customPolicies });
  const service = new AuditQueryService(world.authorization, world.eventLog, world.clock.now);
  return { world, service };
}

describe('M6: Audit query authorization and tenant scoping', () => {
  test('Authorization: an unauthenticated principal is denied (unauthenticated-principal)', () => {
    const { world, service } = setupAuditTestWorld();
    const unauth = unauthPrincipal('user:anon', 'user', TENANT_A);

    // Issue capability to the unauth principal id
    issueAuditCap(world, unauth.id, ['query.audit']);

    const result = service.query(unauth, { tenantId: TENANT_A });
    assert.equal(result.decision.decision, 'deny');
    assert.equal(result.decision.denyReason, 'unauthenticated-principal');
    assert.equal(result.length, 0);
  });

  test('Tenant scope: tenant A query against tenant B synthetic id is denied (tenant-mismatch)', () => {
    const { world, service } = setupAuditTestWorld();
    const userA = world.user; // tenant A

    // Query for tenant B
    const result = service.query(userA, { tenantId: TENANT_B });
    assert.equal(result.decision.decision, 'deny');
    assert.equal(result.decision.denyReason, 'tenant-mismatch');
    assert.equal(result.length, 0);
  });

  test('Tenant isolation invariant: tenant A query MUST NEVER return tenant B events', () => {
    const { world, service } = setupAuditTestWorld();
    const userA = world.user;

    // Grant user A query.audit for tenant A
    issueAuditCap(world, userA.id, ['query.audit']);

    // Populate events for tenant A and tenant B
    world.eventLog.append({
      tenantId: TENANT_A,
      principal: userA.id,
      actor: userA.id,
      actorKind: 'user',
      action: 'read',
      resourceId: 'repo:acme/repo-a',
      decision: 'allow',
      result: 'success',
    });
    world.eventLog.append({
      tenantId: TENANT_B,
      principal: 'user:bob',
      actor: 'user:bob',
      actorKind: 'user',
      action: 'read',
      resourceId: 'doc:globex-strategy',
      decision: 'allow',
      result: 'success',
    });

    const resA = service.query(userA, { tenantId: TENANT_A });
    assert.equal(resA.decision.decision, 'allow');
    assert.ok(resA.length > 0);
    for (const event of resA) {
      assert.equal(event.tenantId, TENANT_A, 'returned event must belong to tenant A');
      assert.notEqual(event.tenantId, TENANT_B, 'tenant B event must never appear in tenant A query');
    }
  });

  test('Capability required: a principal with no capability is denied (no-capability)', () => {
    const { world, service } = setupAuditTestWorld();
    const userA = world.user;

    const result = service.query(userA, { tenantId: TENANT_A });
    assert.equal(result.decision.decision, 'deny');
    assert.equal(result.decision.denyReason, 'no-capability');
    assert.equal(result.length, 0);
  });

  test('Capability required: capability for tenant A but no policy rule match is denied (policy-deny)', () => {
    // Empty policies: no allow rule for audit-log
    const world = testWorld({ policies: [] });
    const service = new AuditQueryService(world.authorization, world.eventLog, world.clock.now);
    const userA = world.user;

    issueAuditCap(world, userA.id, ['query.audit']);

    const result = service.query(userA, { tenantId: TENANT_A });
    assert.equal(result.decision.decision, 'deny');
    assert.equal(result.decision.denyReason, 'policy-deny');
    assert.equal(result.length, 0);
  });

  test('Default deny: empty policy set denies (no matching allow rule)', () => {
    const world = testWorld({ policies: [] });
    const service = new AuditQueryService(world.authorization, world.eventLog, world.clock.now);
    const userA = world.user;

    const result = service.query(userA, { tenantId: TENANT_A });
    assert.equal(result.decision.decision, 'deny');
  });

  test('Happy path: principal with capability + matching allow rule gets results', () => {
    const { world, service } = setupAuditTestWorld();
    const userA = world.user;

    issueAuditCap(world, userA.id, ['query.audit', 'audit.export']);

    world.eventLog.append({
      tenantId: TENANT_A,
      principal: 'agent:summarizer-1',
      actor: 'agent:summarizer-1',
      actorKind: 'agent',
      action: 'read',
      resourceId: 'repo:acme/repo-a',
      decision: 'allow',
      result: 'success',
    });

    const result = service.query(userA, { tenantId: TENANT_A, action: 'read' });
    assert.equal(result.decision.decision, 'allow');
    assert.ok(result.length >= 1);
    assert.equal(result[0]!.action, 'read');
    assert.equal(result[0]!.resourceId, 'repo:acme/repo-a');
  });
});

describe('M6: Audit filters and pagination', () => {
  test('Filter: time range (fromTime/toTime)', () => {
    const { world, service } = setupAuditTestWorld();
    const userA = world.user;

    issueAuditCap(world, userA.id, ['query.audit']);

    const t1 = 1_000_000;
    const t2 = 1_005_000;
    const t3 = 1_010_000;

    world.eventLog.append({
      tenantId: TENANT_A,
      principal: userA.id,
      actor: userA.id,
      actorKind: 'user',
      action: 'read',
      result: 'success',
      timestamp: t1,
    });
    world.eventLog.append({
      tenantId: TENANT_A,
      principal: userA.id,
      actor: userA.id,
      actorKind: 'user',
      action: 'write',
      result: 'success',
      timestamp: t2,
    });
    world.eventLog.append({
      tenantId: TENANT_A,
      principal: userA.id,
      actor: userA.id,
      actorKind: 'user',
      action: 'delete',
      result: 'success',
      timestamp: t3,
    });

    // Inclusive fromTime, exclusive toTime: covers t2 only
    const res = service.query(userA, { tenantId: TENANT_A, fromTime: t2, toTime: t3 });
    assert.equal(res.decision.decision, 'allow');
    assert.equal(res.length, 1);
    assert.equal(res[0]!.action, 'write');
  });

  test('Filter: actor', () => {
    const { world, service } = setupAuditTestWorld();
    const userA = world.user;

    issueAuditCap(world, userA.id, ['query.audit']);

    world.eventLog.append({
      tenantId: TENANT_A,
      principal: 'agent:1',
      actor: 'agent:1',
      actorKind: 'agent',
      action: 'read',
      result: 'success',
    });
    world.eventLog.append({
      tenantId: TENANT_A,
      principal: 'agent:2',
      actor: 'agent:2',
      actorKind: 'agent',
      action: 'read',
      result: 'success',
    });

    const res = service.query(userA, { tenantId: TENANT_A, actor: 'agent:2' });
    assert.equal(res.decision.decision, 'allow');
    assert.equal(res.length, 1);
    assert.equal(res[0]!.actor, 'agent:2');
  });

  test('Filter: action', () => {
    const { world, service } = setupAuditTestWorld();
    const userA = world.user;

    issueAuditCap(world, userA.id, ['query.audit']);

    world.eventLog.append({
      tenantId: TENANT_A,
      principal: userA.id,
      actor: userA.id,
      actorKind: 'user',
      action: 'write',
      result: 'success',
    });
    world.eventLog.append({
      tenantId: TENANT_A,
      principal: userA.id,
      actor: userA.id,
      actorKind: 'user',
      action: 'export',
      result: 'success',
    });

    const res = service.query(userA, { tenantId: TENANT_A, action: 'export' });
    assert.equal(res.decision.decision, 'allow');
    assert.equal(res.length, 1);
    assert.equal(res[0]!.action, 'export');
  });

  test('Filter: decision', () => {
    const { world, service } = setupAuditTestWorld();
    const userA = world.user;

    issueAuditCap(world, userA.id, ['query.audit']);

    world.eventLog.append({
      tenantId: TENANT_A,
      principal: userA.id,
      actor: userA.id,
      actorKind: 'user',
      action: 'read',
      decision: 'allow',
      result: 'success',
    });
    world.eventLog.append({
      tenantId: TENANT_A,
      principal: userA.id,
      actor: userA.id,
      actorKind: 'user',
      action: 'read',
      decision: 'deny',
      denyReason: 'no-capability',
      result: 'denied',
    });

    const allows = service.query(userA, { tenantId: TENANT_A, decision: 'allow' });
    const denies = service.query(userA, { tenantId: TENANT_A, decision: 'deny' });
    assert.ok(allows.every((e: SecurityEvent) => e.decision === 'allow'));
    assert.ok(denies.every((e: SecurityEvent) => e.decision === 'deny'));
    assert.equal(denies.length, 1);
  });

  test('Filter: resourceId', () => {
    const { world, service } = setupAuditTestWorld();
    const userA = world.user;

    issueAuditCap(world, userA.id, ['query.audit']);

    world.eventLog.append({
      tenantId: TENANT_A,
      principal: userA.id,
      actor: userA.id,
      actorKind: 'user',
      action: 'read',
      resourceId: 'repo:acme/repo-a',
      result: 'success',
    });
    world.eventLog.append({
      tenantId: TENANT_A,
      principal: userA.id,
      actor: userA.id,
      actorKind: 'user',
      action: 'read',
      resourceId: 'doc:acme-onboarding',
      result: 'success',
    });

    const res = service.query(userA, { tenantId: TENANT_A, resourceId: 'doc:acme-onboarding' });
    assert.equal(res.decision.decision, 'allow');
    assert.equal(res.length, 1);
    assert.equal(res[0]!.resourceId, 'doc:acme-onboarding');
  });

  test('Filter: limit + offset pagination returns right slice in seq order', () => {
    const { world, service } = setupAuditTestWorld();
    const userA = world.user;

    issueAuditCap(world, userA.id, ['query.audit']);

    for (let i = 0; i < 10; i++) {
      world.eventLog.append({
        tenantId: TENANT_A,
        principal: userA.id,
        actor: userA.id,
        actorKind: 'user',
        action: 'read',
        resourceId: `res:${i}`,
        result: 'success',
      });
    }

    const page1 = service.query(userA, { tenantId: TENANT_A, resourceId: 'res:0', limit: 5, offset: 0 });
    const page2 = service.query(userA, { tenantId: TENANT_A, limit: 3, offset: 2 });
    assert.equal(page2.length, 3);
    assert.ok(page2[0]!.seq < page2[1]!.seq);
    assert.ok(page2[1]!.seq < page2[2]!.seq);
  });

  test('Empty result: filters that match nothing return [] (no error)', () => {
    const { world, service } = setupAuditTestWorld();
    const userA = world.user;

    issueAuditCap(world, userA.id, ['query.audit']);

    const res = service.query(userA, { tenantId: TENANT_A, actor: 'nonexistent-actor' });
    assert.equal(res.decision.decision, 'allow');
    assert.equal(res.length, 0);
  });

  test('Bad filter: limit: 5000, limit: 0, fromTime > toTime, time range > 90 days throw AuditFilterError', () => {
    const { world, service } = setupAuditTestWorld();
    const userA = world.user;

    assert.throws(() => service.query(userA, { tenantId: TENANT_A, limit: 5000 }), AuditFilterError);
    assert.throws(() => service.query(userA, { tenantId: TENANT_A, limit: 0 }), AuditFilterError);
    assert.throws(() => service.query(userA, { tenantId: TENANT_A, limit: -5 }), AuditFilterError);
    assert.throws(() => service.query(userA, { tenantId: TENANT_A, offset: -1 }), AuditFilterError);
    assert.throws(() => service.query(userA, { tenantId: TENANT_A, fromTime: 200, toTime: 100 }), AuditFilterError);
    assert.throws(
      () => service.query(userA, { tenantId: TENANT_A, fromTime: 0, toTime: 91 * 86_400_000 }),
      AuditFilterError,
    );
  });
});

describe('M6: Audit export and verification', () => {
  test('Export shape and verification: exportFor returns valid bundle slice', () => {
    const { world, service } = setupAuditTestWorld();
    const userA = world.user;

    issueAuditCap(world, userA.id, ['query.audit', 'audit.export']);

    for (let i = 0; i < 5; i++) {
      world.eventLog.append({
        tenantId: TENANT_A,
        principal: userA.id,
        actor: userA.id,
        actorKind: 'user',
        action: 'read',
        result: 'success',
      });
    }

    const exported = service.exportFor(userA, { tenantId: TENANT_A, fromSeq: 0, toSeq: 4 });
    assert.equal(exported.tenantId, TENANT_A);
    assert.ok(typeof exported.generatedAt === 'number');
    assert.equal(exported.fromSeq, 0);
    assert.equal(exported.toSeq, 4);
    assert.equal(exported.events.length, 5);
    assert.equal(exported.head, exported.events.at(-1)!.eventHash);
    assert.equal(exported.previousHead, null);

    // Offline verify against public key
    const verification = verifyBundle(JSON.stringify(exported), { publicKey: eventPublicKey() });
    assert.equal(verification.valid, true);
    assert.equal(verification.signatureValid, true);
    assert.equal(verification.eventCount, 5);
  });

  test('Chain slice: slice from seq 5 to seq 9 verifies with previousHead', () => {
    const { world, service } = setupAuditTestWorld();
    const userA = world.user;

    issueAuditCap(world, userA.id, ['query.audit', 'audit.export']);

    for (let i = 0; i < 10; i++) {
      world.eventLog.append({
        tenantId: TENANT_A,
        principal: userA.id,
        actor: userA.id,
        actorKind: 'user',
        action: 'read',
        result: 'success',
      });
    }

    const allEvents = world.eventLog.all();
    const startSeq = allEvents[5]!.seq;
    const endSeq = allEvents[9]!.seq;
    const sliceExport = service.exportFor(userA, { tenantId: TENANT_A, fromSeq: startSeq, toSeq: endSeq });
    assert.equal(sliceExport.fromSeq, startSeq);
    assert.equal(sliceExport.toSeq, endSeq);
    assert.equal(sliceExport.previousHead, allEvents[4]!.eventHash);
    assert.equal(sliceExport.head, allEvents[9]!.eventHash);

    const verification = verifyBundle(JSON.stringify(sliceExport), { publicKey: eventPublicKey() });
    assert.equal(verification.valid, true);
    assert.equal(verification.signatureValid, true);
    assert.equal(verification.eventCount, 5);
  });

  test('Decision audit completeness (Claim 7): every query.audit call appends exactly one event', () => {
    const { world, service } = setupAuditTestWorld();
    const userA = world.user;

    issueAuditCap(world, userA.id, ['query.audit']);

    const countBefore = world.eventLog.all().length;
    service.query(userA, { tenantId: TENANT_A, action: 'read' });
    const countAfter = world.eventLog.all().length;

    assert.equal(countAfter, countBefore + 1, 'query.audit call must append exactly one event');
    const lastEvent = world.eventLog.all().at(-1)!;
    assert.equal(lastEvent.action, 'query.audit');
    assert.equal(lastEvent.decision, 'allow');
  });

  test('SQLite-backed EventLog query execution parity', () => {
    const tmp = mkdtempSync(join(tmpdir(), 'asl-m6-sqlite-'));
    const dbPath = join(tmp, 'events.db');

    try {
      const log = new EventLog(dbPath);
      log.append({
        tenantId: TENANT_A,
        principal: 'user:alice',
        actor: 'user:alice',
        actorKind: 'user',
        action: 'read',
        resourceId: 'repo:acme/repo-a',
        decision: 'allow',
        result: 'success',
      });
      log.append({
        tenantId: TENANT_A,
        principal: 'user:alice',
        actor: 'user:alice',
        actorKind: 'user',
        action: 'write',
        resourceId: 'repo:acme/repo-a',
        decision: 'deny',
        denyReason: 'policy-deny',
        result: 'denied',
      });
      log.append({
        tenantId: TENANT_B,
        principal: 'user:bob',
        actor: 'user:bob',
        actorKind: 'user',
        action: 'read',
        result: 'success',
      });

      const rowsA = log.query({ tenantId: TENANT_A });
      assert.equal(rowsA.length, 2);
      assert.equal(rowsA[0]!.action, 'read');
      assert.equal(rowsA[1]!.action, 'write');

      const denies = log.query({ tenantId: TENANT_A, decision: 'deny' });
      assert.equal(denies.length, 1);
      assert.equal(denies[0]!.denyReason, 'policy-deny');

      const exported = log.exportFor({ tenantId: TENANT_A, fromSeq: 0, toSeq: 1 });
      assert.equal(exported.events.length, 2);
      assert.equal(exported.head, exported.events[1]!.eventHash);

      log.close();
    } finally {
      rmSync(tmp, { recursive: true, force: true });
    }
  });

  test('Sealed content stays sealed in query result (Claim 13 invariant)', () => {
    const { world, service } = setupAuditTestWorld();
    const userA = world.user;

    issueAuditCap(world, userA.id, ['query.audit']);

    world.eventLog.append({
      tenantId: TENANT_A,
      principal: 'agent:1',
      actor: 'agent:1',
      actorKind: 'agent',
      action: 'read',
      result: 'success',
      metadata: {
        sealed: {
          keyId: 'evidence-key:confidential',
          iv: 'fake-iv',
          tag: 'fake-tag',
          ciphertext: 'secret-ciphertext',
        },
      },
    });

    const res = service.query(userA, { tenantId: TENANT_A, action: 'read' });
    assert.equal(res.decision.decision, 'allow');
    const matched = res.find((e: SecurityEvent) => (e.metadata as any)?.sealed !== undefined);
    assert.ok(matched);
    assert.equal((matched.metadata as any).sealed.ciphertext, 'secret-ciphertext');
    assert.equal((matched.metadata as any).sealed.keyId, 'evidence-key:confidential');
  });
});
