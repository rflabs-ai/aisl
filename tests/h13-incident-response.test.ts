/**
 * H13 acceptance: incident response (ADR-026).
 *
 * The kill switch freezes issuance and revokes authority in one operator
 * action, denials carry the distinct `incident-frozen` reason, and the switch
 * propagates across nodes through the revocation channel within the poll
 * interval (target ≤ 5 s). Preservation pages past M6's 1000-event export cap
 * into an independently verifiable incident bundle. Each refusal has a
 * distinct reason; no channel record, incident event, or artifact carries key
 * material or secret canaries.
 *
 * These tests were written BEFORE src/incident.ts existed (red-confirmed)
 * per the H13 kickoff contract.
 */

import { describe, test } from 'node:test';
import assert from 'node:assert/strict';
import { existsSync, mkdtempSync, readFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { SessionManager } from '../src/session-manager.ts';
import { eventPublicKey } from '../src/events.ts';
import { RestApi } from '../src/rest-api.ts';
import { createMockIdP, testWorld, mockAuth, testUser } from '../src/testing.ts';
import { TENANT_A, TENANT_B, type World } from '../src/scenario.ts';
import {
  InMemoryRevocationChannel,
  IncidentService,
  IncidentEvidenceError,
  IncidentInputError,
  bundleDigest,
  verifyIncidentBundle,
  type ChannelHealth,
  type IncidentBundle,
  type RevocationChannel,
  type RevocationInput,
  type RevocationRecord,
} from '../src/incident.ts';
import type { Principal } from '../src/domain.ts';

const T0 = Date.UTC(2026, 0, 1);

function issueAuditCapability(world: World): void {
  world.authorization.issue(world.root, {
    subject: world.user.id,
    tenantId: TENANT_A,
    resourceIds: [`audit-log:${TENANT_A}`],
    actions: ['query.audit', 'audit.export'],
    maxClassification: 'internal',
    expiresAt: world.clock.now() + 3_600_000,
    provenance: { source: 'policy-grant', note: 'h13 test audit authority' },
  });
}

function tempDir(prefix: string): { dir: string; cleanup: () => void } {
  const dir = mkdtempSync(join(tmpdir(), prefix));
  return { dir, cleanup: () => rmSync(dir, { recursive: true, force: true }) };
}

/** A channel whose publish always fails — channel-outage behavior. */
class BrokenChannel implements RevocationChannel {
  publish(_input: RevocationInput): void {
    throw new Error('channel down');
  }
  since(_cursor: number): readonly RevocationRecord[] {
    throw new Error('channel down');
  }
  cursor(): number {
    return 0;
  }
  refresh(): void {}
  flush(): Promise<void> {
    return Promise.resolve();
  }
  health(): ChannelHealth {
    return { errors: 1, lastError: 'channel down' };
  }
  close(): void {}
}

describe('H13: kill switch (freeze)', () => {
  test('engage denies the next authorize with the distinct incident-frozen reason, and the decision is recorded', () => {
    const world = testWorld();
    const allowed = world.authorization.authorize({
      principal: world.agent,
      action: 'read',
      resourceId: world.resources.repoA!,
    });
    assert.equal(allowed.decision, 'allow');

    const result = world.incident.engage({ scope: 'tenant', tenantId: TENANT_A, reason: 'hostile agent', actor: 'user:oncall' });
    assert.equal(result.frozen, true);
    assert.equal(result.broadcastOk, true);

    const denied = world.authorization.authorize({
      principal: world.agent,
      action: 'read',
      resourceId: world.resources.repoA!,
    });
    assert.equal(denied.decision, 'deny');
    assert.equal(denied.denyReason, 'incident-frozen');

    const event = world.eventLog.all().at(-1);
    assert.equal(event?.decision, 'deny');
    assert.equal(event?.denyReason, 'incident-frozen');
  });

  test('engage blocks issuance with an audited capability.issue refusal', () => {
    const world = testWorld();
    world.incident.engage({ scope: 'global', reason: 'worm', actor: 'user:oncall' });

    assert.throws(
      () =>
        world.authorization.issue(world.root, {
          subject: world.agent.id,
          tenantId: TENANT_A,
          resourceIds: [world.resources.internalDoc!],
          actions: ['read'],
          maxClassification: 'internal',
          expiresAt: world.clock.now() + 60_000,
          provenance: { source: 'policy-grant' },
        }),
      /incident-frozen/,
    );
    const refusal = world.eventLog.all().filter(
      (e) => e.action === 'capability.issue' && e.decision === 'deny' && e.denyReason === 'incident-frozen',
    );
    assert.equal(refusal.length, 1);
  });

  test('lift restores authorization but never restores revoked capabilities', () => {
    const world = testWorld();
    world.incident.engage({ scope: 'tenant', tenantId: TENANT_A, reason: 'triage', actor: 'user:oncall' });
    world.incident.lift({ scope: 'tenant', tenantId: TENANT_A, reason: 'contained', actor: 'user:oncall' });
    assert.equal(world.authorization.isFrozen(TENANT_A), false);

    const decision = world.authorization.authorize({
      principal: world.agent,
      action: 'read',
      resourceId: world.resources.repoA!,
    });
    // The bootstrap capability was revoked by the kill switch and stays revoked.
    assert.equal(decision.decision, 'deny');
    assert.equal(decision.denyReason, 'capability-revoked');
  });

  test('freeze is scoped: a tenant freeze leaves other tenants working; global freezes everyone', () => {
    const world = testWorld();
    world.incident.engage({ scope: 'tenant', tenantId: TENANT_A, reason: 'tenant incident', actor: 'user:oncall' });

    const acme = world.authorization.authorize({ principal: world.agent, action: 'read', resourceId: world.resources.repoA! });
    assert.equal(acme.denyReason, 'incident-frozen');

    // globex's bootstrap: create a capability under globex via the root of A? The
    // scenario issues none for the foreign agent, so its deny is no-capability —
    // the point is it is NOT incident-frozen.
    const globex = world.authorization.authorize({ principal: world.foreignAgent, action: 'read', resourceId: world.resources.foreignDoc! });
    assert.notEqual(globex.denyReason, 'incident-frozen');

    world.incident.engage({ scope: 'global', reason: 'everything', actor: 'user:oncall' });
    const globexAfter = world.authorization.authorize({ principal: world.foreignAgent, action: 'read', resourceId: world.resources.foreignDoc! });
    assert.equal(globexAfter.denyReason, 'incident-frozen');
  });

  test('revokeAll is tenant-scoped and audited once per revoked capability', () => {
    const world = testWorld();
    const acmeCaps = world.authorization.capabilitiesFor(world.agent.id);
    assert.ok(acmeCaps.length >= 2);
    const before = world.eventLog.all().filter((e) => e.action === 'capability.revoke').length;

    const count = world.authorization.revokeAll('tenant', TENANT_A, 'bulk incident revoke');
    assert.equal(count, acmeCaps.length);
    for (const cap of acmeCaps) assert.equal(world.authorization.isRevoked(cap.id), true);
    assert.equal(world.authorization.isRevoked('cap-not-ours'), false);

    const after = world.eventLog.all().filter((e) => e.action === 'capability.revoke').length;
    assert.equal(after - before, acmeCaps.length);
  });

  test('kill-switch latency is immediate in-process (no clock advance)', () => {
    const world = testWorld();
    world.clock.set(T0);
    const t0 = world.clock.now();
    world.incident.engage({ scope: 'tenant', tenantId: TENANT_A, reason: 'measured drill', actor: 'user:oncall' });
    const denied = world.authorization.authorize({ principal: world.agent, action: 'read', resourceId: world.resources.repoA! });
    assert.equal(denied.denyReason, 'incident-frozen');
    assert.equal(world.clock.now() - t0, 0);
  });

  test('engage validates input: tenant scope requires a tenant, reason must be non-empty', () => {
    const world = testWorld();
    assert.throws(() => world.incident.engage({ scope: 'tenant', reason: 'x', actor: 'a' }), IncidentInputError);
    assert.throws(() => world.incident.engage({ scope: 'global', reason: '  ', actor: 'a' }), IncidentInputError);
    assert.throws(() => world.incident.engage({ scope: 'global', reason: 'x', actor: '' }), IncidentInputError);
  });
});

describe('H13: session bulk revocation', () => {
  test('revokeAllForTenant revokes only that tenant; revokeAll revokes everything', () => {
    const sessions = new SessionManager();
    const auth = mockAuth({ subject: 'user:s', amr: ['pwd', 'mfa'] });
    const a = { id: 'user:a', kind: 'user' as const, tenantId: TENANT_A, roles: [], attributes: {}, auth };
    const b = { id: 'user:b', kind: 'user' as const, tenantId: TENANT_B, roles: [], attributes: {}, auth };
    const sa = sessions.create(a, auth);
    const sb = sessions.create(b, auth);

    assert.equal(sessions.revokeAllForTenant(TENANT_A), 1);
    assert.equal(sessions.isValid(sa.id), false);
    assert.equal(sessions.isValid(sb.id), true);
    assert.equal(sessions.revokeAll(), 1);
    assert.equal(sessions.isValid(sb.id), false);
  });

  test('engage revokes sessions in scope', () => {
    const world = testWorld();
    const auth = mockAuth({ subject: 'user:sess', amr: ['pwd', 'mfa'] });
    const sessions = new SessionManager();
    const principal = { id: 'user:sess', kind: 'user' as const, tenantId: TENANT_A, roles: [], attributes: {}, auth };
    const session = sessions.create(principal, auth);
    const incident = new IncidentService({
      authorization: world.authorization,
      sessions,
      audit: world.audit,
      eventLog: world.eventLog,
      channel: new InMemoryRevocationChannel(),
      clock: world.clock.now,
    });
    const result = incident.engage({ scope: 'tenant', tenantId: TENANT_A, reason: 'session sweep', actor: 'user:oncall' });
    assert.equal(result.sessionsRevoked, 1);
    assert.equal(sessions.isValid(session.id), false);
  });
});

describe('H13: revocation channel broadcast', () => {
  test('two nodes sharing a channel: the remote node denies incident-frozen after one sync interval (≤ 5 s bound)', () => {
    const channel = new InMemoryRevocationChannel();
    const nodeA = testWorld({ channel });
    const nodeB = testWorld({ channel });
    nodeA.clock.set(T0);
    nodeB.clock.set(T0);
    // Give B's incident service a 1 s poll interval (inside the ROADMAP 5 s target).
    const incidentB = new IncidentService({
      authorization: nodeB.authorization,
      sessions: new SessionManager(),
      audit: nodeB.audit,
      eventLog: nodeB.eventLog,
      channel,
      clock: nodeB.clock.now,
      syncIntervalMs: 1000,
    });
    nodeB.authorization.setBroadcastSync((force) => incidentB.sync(force));

    // B syncs once at t0 (fresh: cursor 0 → nothing to apply), starting its throttle window.
    incidentB.sync(true);
    const before = nodeB.authorization.authorize({ principal: nodeB.agent, action: 'read', resourceId: nodeB.resources.repoA! });
    assert.equal(before.decision, 'allow');

    nodeA.incident.engage({ scope: 'tenant', tenantId: TENANT_A, reason: 'node A kill switch', actor: 'user:oncall' });

    // 999 ms later the throttle still holds: the incident was published at t0 and B last synced at t0.
    nodeB.clock.advance(999);
    const throttled = nodeB.authorization.authorize({ principal: nodeB.agent, action: 'read', resourceId: nodeB.resources.repoA! });
    assert.equal(throttled.decision, 'allow');

    // At one full interval B pulls the records and the freeze applies.
    nodeB.clock.advance(1);
    const propagated = nodeB.authorization.authorize({ principal: nodeB.agent, action: 'read', resourceId: nodeB.resources.repoA! });
    assert.equal(propagated.denyReason, 'incident-frozen');
  });

  test('issuance force-syncs: a post-freeze mint on a remote node cannot slip through the throttle', () => {
    const channel = new InMemoryRevocationChannel();
    const nodeA = testWorld({ channel });
    const nodeB = testWorld({ channel });
    nodeB.clock.set(T0);
    nodeA.clock.set(T0);
    const incidentB = new IncidentService({
      authorization: nodeB.authorization,
      sessions: new SessionManager(),
      audit: nodeB.audit,
      eventLog: nodeB.eventLog,
      channel,
      clock: nodeB.clock.now,
      syncIntervalMs: 60_000,
    });
    nodeB.authorization.setBroadcastSync((force) => incidentB.sync(force));

    nodeA.incident.engage({ scope: 'tenant', tenantId: TENANT_A, reason: 'stop issuance', actor: 'user:oncall' });

    nodeB.clock.advance(1); // far inside the 60 s throttle window
    assert.throws(
      () =>
        nodeB.authorization.issue(nodeB.root, {
          subject: nodeB.agent.id,
          tenantId: TENANT_A,
          resourceIds: [nodeB.resources.internalDoc!],
          actions: ['read'],
          maxClassification: 'internal',
          expiresAt: nodeB.clock.now() + 60_000,
          provenance: { source: 'policy-grant' },
        }),
      /incident-frozen/,
    );
  });

  test('a fresh node replays the channel from cursor 0 and reconstructs freeze state', () => {
    const channel = new InMemoryRevocationChannel();
    const nodeA = testWorld({ channel });
    nodeA.incident.engage({ scope: 'tenant', tenantId: TENANT_A, reason: 'replayed incident', actor: 'user:oncall' });

    const nodeC = testWorld({ channel });
    assert.equal(nodeC.authorization.isFrozen(TENANT_A), false, 'unsynced node knows nothing yet');
    nodeC.incident.sync(true);
    assert.equal(nodeC.authorization.isFrozen(TENANT_A), true);
    const denied = nodeC.authorization.authorize({ principal: nodeC.agent, action: 'read', resourceId: nodeC.resources.repoA! });
    assert.equal(denied.denyReason, 'incident-frozen');
  });

  test('single-target revoke-cap and revoke-session records apply cross-node', () => {
    const channel = new InMemoryRevocationChannel();
    const nodeA = testWorld({ channel });
    const nodeB = testWorld({ channel });
    const capId = nodeB.authorization.capabilitiesFor(nodeB.agent.id)[0]!.id;

    nodeA.incident.revokeCapability(capId, TENANT_A, 'stolen capability');
    nodeB.incident.sync(true);
    assert.equal(nodeB.authorization.isRevoked(capId), true);

    const auth = mockAuth({ subject: 'user:sess2', amr: ['pwd', 'mfa'] });
    const sessions = new SessionManager();
    const principal = { id: 'user:sess2', kind: 'user' as const, tenantId: TENANT_A, roles: [], attributes: {}, auth };
    const session = sessions.create(principal, auth);
    const incidentB = new IncidentService({
      authorization: nodeB.authorization,
      sessions,
      audit: nodeB.audit,
      eventLog: nodeB.eventLog,
      channel,
      clock: nodeB.clock.now,
      syncIntervalMs: 0,
    });
    nodeA.incident.revokeSession(session.id, TENANT_A, 'compromised session');
    incidentB.sync(true);
    assert.equal(sessions.isValid(session.id), false);

    // Audit 05: the single-target revocation is evidence in the signed log,
    // not just a channel row.
    const revokeEvent = nodeA.eventLog.all().filter((e) => e.action === 'incident.revoke').at(-1);
    assert.equal((revokeEvent?.metadata as { sessionId?: string } | undefined)?.sessionId, session.id);
    assert.equal(revokeEvent?.resourceId, session.id);
  });

  test('channel sequence is monotonic and since(cursor) returns only later records', () => {
    const channel = new InMemoryRevocationChannel();
    channel.publish({ action: 'freeze', scope: 'tenant', tenantId: TENANT_A, reason: 'r1', at: 1 });
    channel.publish({ action: 'unfreeze', scope: 'tenant', tenantId: TENANT_A, reason: 'r2', at: 2 });
    const records = channel.since(-1);
    assert.deepEqual(records.map((r) => r.seq), [0, 1]);
    assert.ok(records[1]!.seq > records[0]!.seq);
    assert.deepEqual(channel.since(records[0]!.seq).map((r) => r.seq), [records[1]!.seq]);
    assert.equal(channel.cursor(), records[1]!.seq);
  });

  test('a channel outage still engages locally and reports broadcastOk=false', () => {
    const world = testWorld({ channel: new BrokenChannel() });
    const result = world.incident.engage({ scope: 'tenant', tenantId: TENANT_A, reason: 'channel down', actor: 'user:oncall' });
    assert.equal(result.broadcastOk, false);
    assert.equal(world.authorization.isFrozen(TENANT_A), true);
    const engageEvent = world.eventLog.all().filter((e) => e.action === 'incident.engage').at(-1);
    assert.equal((engageEvent?.metadata as { broadcastOk?: boolean } | undefined)?.broadcastOk, false);
  });

  test('the REST server pulls the channel once per authorized request', async () => {
    const world = testWorld();
    const mockIdp = await createMockIdP();
    const idp = await mockIdp.createIdP();
    let syncs = 0;
    const api = new RestApi({
      authorization: world.authorization,
      idp,
      eventLog: world.eventLog,
      resolvePrincipal: (auth) => (auth.subject === world.user.id ? world.user : undefined),
      incidentSync: () => {
        syncs++;
      },
    });
    const port = await api.start();
    try {
      const token = await mockIdp.signJWT({ sub: world.user.id });
      const response = await fetch(`http://127.0.0.1:${port}/v1/authorize`, {
        method: 'POST',
        headers: { authorization: `Bearer ${token}`, 'content-type': 'application/json' },
        body: JSON.stringify({ action: 'read', resourceId: world.resources.repoA! }),
      });
      assert.ok(response.status === 200 || response.status === 403, `unexpected status ${response.status}`);
      assert.equal(syncs, 1, 'one sync per authorized request');
    } finally {
      api.stop();
    }
  });
});

describe('H13: evidence preservation and reconstruction', () => {
  test('preserve writes a verifiable incident bundle and records digest + head only', () => {
    const world = testWorld();
    issueAuditCapability(world);
    const { dir, cleanup } = tempDir('h13-preserve-');
    try {
      const outPath = join(dir, 'incident-bundle.json');
      const lastSeq = world.eventLog.all().at(-1)!.seq;
      const lastHash = world.eventLog.all().at(-1)!.eventHash;
      const result = world.incident.preserve({
        principal: world.user,
        tenantId: TENANT_A,
        fromSeq: 0,
        toSeq: lastSeq,
        outPath,
      });

      assert.equal(existsSync(outPath), true);
      const bytes = readFileSync(outPath, 'utf8');
      const parsed = JSON.parse(bytes) as IncidentBundle;
      assert.equal(parsed.type, 'asl-incident-bundle');
      assert.equal(parsed.digest, bundleDigest(parsed));
      // The bundle covers the chain as of preservation; the preserve event itself is appended after.
      assert.equal(parsed.head, lastHash);
      assert.equal(parsed.toSeq, lastSeq);
      assert.equal(world.eventLog.all().at(-1)!.action, 'incident.preserve');

      const verified = verifyIncidentBundle(parsed, { publicKey: eventPublicKey() });
      assert.equal(verified.valid, true, verified.errors.join('; '));
      assert.equal(verified.digestMatches, true);

      const preserveEvent = world.eventLog.all().filter((e) => e.action === 'incident.preserve').at(-1);
      const meta = preserveEvent?.metadata as { digest?: string; events?: number; head?: string } | undefined;
      assert.equal(meta?.digest, result.digest);
      assert.equal(meta?.events, parsed.events.length);
      assert.equal(meta?.head, result.head);
      // The event carries no event content — digest + counts only.
      assert.equal((preserveEvent?.metadata as Record<string, unknown> | undefined)?.events !== undefined, true);
      assert.equal(JSON.stringify(preserveEvent?.metadata).includes(parsed.events[0]!.eventHash), false);
    } finally {
      cleanup();
    }
  });

  test('preserve pages past the M6 1000-event export cap', () => {
    const world = testWorld();
    issueAuditCapability(world);
    for (let i = 0; i < 1100; i++) {
      world.eventLog.append({
        tenantId: TENANT_A,
        principal: 'system',
        actor: 'system',
        actorKind: 'authorization',
        action: 'read',
        resourceId: `doc:bulk-${i}`,
        decision: 'allow',
        result: 'success',
        metadata: { phase: 'decision', i },
      });
    }
    const lastSeq = world.eventLog.all().at(-1)!.seq;
    const { dir, cleanup } = tempDir('h13-page-');
    try {
      const result = world.incident.preserve({
        principal: world.user,
        tenantId: TENANT_A,
        fromSeq: 0,
        toSeq: lastSeq,
        outPath: join(dir, 'bundle.json'),
      });
      assert.ok(result.events > 1000, `expected a paged export, got ${result.events}`);
      assert.equal(result.events, lastSeq + 1);
    } finally {
      cleanup();
    }
  });

  test('preserve without audit authority refuses with no file written', () => {
    const world = testWorld();
    const { dir, cleanup } = tempDir('h13-denied-');
    try {
      const outPath = join(dir, 'denied.json');
      const noAudit: Principal = testUser('user:no-audit', TENANT_A);
      assert.throws(
        () =>
          world.incident.preserve({
            principal: noAudit,
            tenantId: TENANT_A,
            fromSeq: 0,
            toSeq: world.eventLog.all().at(-1)!.seq,
            outPath,
          }),
        IncidentEvidenceError,
      );
      assert.equal(existsSync(outPath), false);
    } finally {
      cleanup();
    }
  });

  test('a tampered bundle fails offline verification', () => {
    const world = testWorld();
    issueAuditCapability(world);
    const { dir, cleanup } = tempDir('h13-tamper-');
    try {
      const outPath = join(dir, 'bundle.json');
      world.incident.preserve({
        principal: world.user,
        tenantId: TENANT_A,
        fromSeq: 0,
        toSeq: world.eventLog.all().at(-1)!.seq,
        outPath,
      });
      const parsed = JSON.parse(readFileSync(outPath, 'utf8')) as IncidentBundle;
      const tampered: IncidentBundle = {
        ...parsed,
        events: parsed.events.map((e, i) => (i === 0 ? { ...e, decision: e.decision === 'allow' ? 'deny' : 'allow' } : e)),
      };
      const verified = verifyIncidentBundle(tampered, { publicKey: eventPublicKey() });
      assert.equal(verified.valid, false);

      // A bundle whose digest no longer matches its content is refused too.
      const reDigested: IncidentBundle = { ...tampered, digest: bundleDigest(tampered) };
      assert.equal(verifyIncidentBundle(reDigested, { publicKey: eventPublicKey() }).digestMatches, true);
      assert.equal(verifyIncidentBundle(reDigested, { publicKey: eventPublicKey() }).valid, false);
    } finally {
      cleanup();
    }
  });

  test('reconstruct summarizes decisions, deny reasons, and incident actions', () => {
    const world = testWorld();
    issueAuditCapability(world);
    world.incident.engage({ scope: 'tenant', tenantId: TENANT_A, reason: 'report drill', actor: 'user:oncall' });
    world.authorization.authorize({ principal: world.agent, action: 'read', resourceId: world.resources.repoA! });

    const report = world.incident.reconstruct({
      principal: world.user,
      tenantId: TENANT_A,
      fromSeq: 0,
      toSeq: world.eventLog.all().at(-1)!.seq,
    });
    assert.ok(report.decisions.deny >= 1);
    assert.ok((report.denyReasons['incident-frozen'] ?? 0) >= 1);
    assert.ok(report.freezes >= 1);
    assert.ok(report.actors.includes('user:oncall'));
    assert.ok(report.events > 0);
  });

  test('structural invariant: no key material or secret canaries in channel records, incident events, or the bundle', () => {
    const channel = new InMemoryRevocationChannel();
    const world = testWorld({ channel });
    issueAuditCapability(world);
    world.incident.engage({ scope: 'tenant', tenantId: TENANT_A, reason: 'canary sweep', actor: 'user:oncall' });
    const { dir, cleanup } = tempDir('h13-secret-');
    try {
      const outPath = join(dir, 'bundle.json');
      world.incident.preserve({
        principal: world.user,
        tenantId: TENANT_A,
        fromSeq: 0,
        toSeq: world.eventLog.all().at(-1)!.seq,
        outPath,
      });
      const surfaces = [
        JSON.stringify(channel.since(-1)),
        JSON.stringify(world.eventLog.all().filter((e) => e.action.startsWith('incident.'))),
        readFileSync(outPath, 'utf8'),
      ];
      for (const surface of surfaces) {
        assert.equal(surface.includes('PRIVATE KEY'), false, 'no key material may reach an incident surface');
        for (const secret of world.secretValues) {
          assert.equal(surface.includes(secret), false, 'no secret value may reach an incident surface');
        }
      }
    } finally {
      cleanup();
    }
  });

  test('global incident evidence is reachable through the global view (audit 04)', () => {
    const world = testWorld();
    issueAuditCapability(world);
    world.incident.engage({ scope: 'global', reason: 'global drill', actor: 'user:oncall' });
    const engageEvent = world.eventLog.all().filter((e) => e.action === 'incident.engage').at(-1);
    assert.equal(engageEvent?.tenantId, '');

    const report = world.incident.reconstruct({
      principal: world.user,
      tenantId: '*',
      fromSeq: 0,
      toSeq: world.eventLog.all().at(-1)!.seq,
    });
    assert.ok(report.freezes >= 1);
    assert.ok(report.events >= 2, 'engage + freeze events');
    assert.ok(report.actors.includes('user:oncall'));

    // No authority, no global view.
    assert.throws(
      () =>
        world.incident.reconstruct({ principal: testUser('user:no-audit', TENANT_A), tenantId: '*', fromSeq: 0, toSeq: 9999 }),
      IncidentEvidenceError,
    );

    const { dir, cleanup } = tempDir('h13-global-');
    try {
      const outPath = join(dir, 'bundle.json');
      const result = world.incident.preserve({
        principal: world.user,
        tenantId: '*',
        fromSeq: 0,
        toSeq: world.eventLog.all().at(-1)!.seq,
        outPath,
      });
      assert.ok(result.events >= 2);
      const verified = verifyIncidentBundle(JSON.parse(readFileSync(outPath, 'utf8')) as IncidentBundle, { publicKey: eventPublicKey() });
      assert.equal(verified.valid, true, verified.errors.join('; '));
      // The preservation event itself stays retrievable under the preserving tenant.
      const preserveEvent = world.eventLog.all().filter((e) => e.action === 'incident.preserve').at(-1);
      assert.equal(preserveEvent?.tenantId, TENANT_A);
    } finally {
      cleanup();
    }
  });

  test('bootstrap:false builds a world that issues nothing (audit 06)', () => {
    const world = testWorld({ bootstrap: false });
    assert.equal(world.eventLog.all().length, 0);
    const result = world.incident.engage({ scope: 'tenant', tenantId: TENANT_A, reason: 'bare world', actor: 'user:oncall' });
    assert.equal(result.capabilitiesRevoked, 0);
    assert.equal(world.eventLog.all().every((e) => e.action.startsWith('incident.')), true);
  });
});
