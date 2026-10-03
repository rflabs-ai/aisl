/**
 * H2 acceptance suite (ADR-028): short-lived credentials and workload identity.
 *
 * The contract under test:
 * - the verification seam refuses tokens without a bounded, declared lifetime
 *   (`exp`, `iat`, `jti`, `sub`; `exp - iat` <= the configured ceiling);
 * - clock tolerance is bounded AND actually wired into jose (the old
 *   `clockToleranceSec` option name was silently ignored);
 * - workload identity is derived from a verified parent, time-capped, and
 *   carries no parent credential material;
 * - token revocation propagates over the H13 revocation channel before the
 *   REST layer mints a principal;
 * - no raw credential or payload canary reaches any event or error.
 *
 * Written before the implementation (red-first): every `validateTokenClaims`,
 * `workloadAuth`, `attachRevocationFeed`, `revokeToken`, and `omit` symbol
 * below is new in this milestone.
 */

import { request as httpRequest } from 'node:http';
import { describe, test } from 'node:test';
import assert from 'node:assert/strict';
import {
  IdentityProvider,
  IdentityConfigError,
  validateTokenClaims,
  DEFAULT_MAX_TOKEN_LIFETIME_SEC,
  DEFAULT_MAX_WORKLOAD_LIFETIME_SEC,
  MAX_CLOCK_SKEW_SEC,
  MAX_TOKEN_LIFETIME_CEILING_SEC,
  type TokenRevocationFeed,
} from '../src/identity.ts';
import {
  IncidentService,
  InMemoryRevocationChannel,
  type RevocationChannel,
  type RevocationInput,
} from '../src/incident.ts';
import { RestApi, type RestApiDeps } from '../src/rest-api.ts';
import { createMockIdP, mockAuth, testWorld } from '../src/testing.ts';
import { TENANT_A, type World } from '../src/scenario.ts';

/** Deterministic base time shared with the scenario clock (2026-01-01T00:00:00Z). */
const NOW = Date.UTC(2026, 0, 1);

const LIMITS = { maxTokenLifetimeSec: DEFAULT_MAX_TOKEN_LIFETIME_SEC, clockToleranceSec: 30 };

/** Deterministic LCG so the fuzz pass is reproducible. */
function makeRandom(seed: number): () => number {
  let state = seed >>> 0;
  return () => {
    state = (state * 1_664_525 + 1_013_904_223) >>> 0;
    return state / 0x1_0000_0000;
  };
}

function validPayload(overrides: Record<string, unknown> = {}): Record<string, unknown> {
  return {
    sub: 'user:alice',
    exp: Math.floor(NOW / 1000) + 600,
    iat: Math.floor(NOW / 1000),
    jti: 'tok-h2-valid',
    ...overrides,
  };
}

interface RawResponse {
  readonly status: number;
  readonly body: string;
}

function postAuthorize(port: number, token: string, body: string): Promise<RawResponse> {
  return new Promise((resolve, reject) => {
    const req = httpRequest(
      {
        host: '127.0.0.1',
        port,
        method: 'POST',
        path: '/v1/authorize',
        headers: { authorization: `Bearer ${token}`, 'content-type': 'application/json' },
      },
      (res) => {
        let data = '';
        res.on('data', (chunk: Buffer) => {
          data += chunk.toString('utf8');
        });
        res.on('end', () => resolve({ status: res.statusCode ?? 0, body: data }));
      },
    );
    req.on('error', reject);
    req.write(body);
    req.end();
  });
}

describe('H2: token claim admission contract', () => {
  test('a well-formed short-lived token is accepted with derived fields', () => {
    const result = validateTokenClaims(validPayload(), NOW, LIMITS);
    assert.equal(result.ok, true);
    if (!result.ok) return;
    assert.equal(result.tokenId, 'tok-h2-valid');
    assert.equal(result.issuedAt, Math.floor(NOW / 1000) * 1000);
    assert.equal(result.expiresAt, (Math.floor(NOW / 1000) + 600) * 1000);
    assert.equal(result.lifetimeSec, 600);
  });

  test('missing exp / iat / jti / sub are each refused', () => {
    for (const [field, reason] of [
      ['exp', 'claims-missing-exp'],
      ['iat', 'claims-missing-iat'],
      ['jti', 'claims-missing-jti'],
      ['sub', 'claims-missing-sub'],
    ] as const) {
      const payload = validPayload();
      delete payload[field];
      const result = validateTokenClaims(payload, NOW, LIMITS);
      assert.equal(result.ok, false, `missing ${field} must be refused`);
      if (!result.ok) assert.equal(result.reason, reason);
    }
  });

  test('ill-typed exp / iat / jti / sub are refused', () => {
    for (const [field, value] of [
      ['exp', 'tomorrow'],
      ['exp', Number.NaN],
      ['iat', 'yesterday'],
      ['iat', Number.POSITIVE_INFINITY],
      ['jti', 42],
      ['jti', ''],
      ['sub', 7],
      ['sub', ''],
    ] as const) {
      const result = validateTokenClaims(validPayload({ [field]: value }), NOW, LIMITS);
      assert.equal(result.ok, false, `${field}=${String(value)} must be refused`);
    }
  });

  test('a non-positive lifetime is refused; exp before iat is refused', () => {
    const equal = validateTokenClaims(validPayload({ exp: Math.floor(NOW / 1000), iat: Math.floor(NOW / 1000) }), NOW, LIMITS);
    assert.equal(equal.ok, false);
    if (!equal.ok) assert.equal(equal.reason, 'claims-lifetime-not-positive');

    const inverted = validateTokenClaims(validPayload({ exp: Math.floor(NOW / 1000) - 60, iat: Math.floor(NOW / 1000) }), NOW, LIMITS);
    assert.equal(inverted.ok, false);
    if (!inverted.ok) assert.equal(inverted.reason, 'claims-lifetime-not-positive');
  });

  test('the lifetime ceiling is inclusive at the boundary and refuses one second more', () => {
    const atCeiling = validateTokenClaims(
      validPayload({ exp: Math.floor(NOW / 1000) + DEFAULT_MAX_TOKEN_LIFETIME_SEC, iat: Math.floor(NOW / 1000) }),
      NOW,
      LIMITS,
    );
    assert.equal(atCeiling.ok, true, 'exactly the ceiling is accepted');

    const overCeiling = validateTokenClaims(
      validPayload({ exp: Math.floor(NOW / 1000) + DEFAULT_MAX_TOKEN_LIFETIME_SEC + 1, iat: Math.floor(NOW / 1000) }),
      NOW,
      LIMITS,
    );
    assert.equal(overCeiling.ok, false);
    if (!overCeiling.ok) assert.equal(overCeiling.reason, 'claims-lifetime-exceeds-ceiling');
  });

  test('a token issued in the future beyond tolerance is refused; within tolerance it is accepted', () => {
    const futureSec = Math.floor(NOW / 1000) + LIMITS.clockToleranceSec + 1;
    const beyond = validateTokenClaims(validPayload({ iat: futureSec, exp: futureSec + 60 }), NOW, LIMITS);
    assert.equal(beyond.ok, false);
    if (!beyond.ok) assert.equal(beyond.reason, 'claims-issued-in-future');

    const withinSec = Math.floor(NOW / 1000) + LIMITS.clockToleranceSec;
    const within = validateTokenClaims(validPayload({ iat: withinSec, exp: withinSec + 60 }), NOW, LIMITS);
    assert.equal(within.ok, true, 'iat exactly at tolerance is accepted');
  });

  test('expiry beyond tolerance is refused; within tolerance it is accepted', () => {
    const iatSec = Math.floor(NOW / 1000) - 200;
    const beyond = validateTokenClaims(validPayload({ iat: iatSec, exp: Math.floor(NOW / 1000) - LIMITS.clockToleranceSec - 1 }), NOW, LIMITS);
    assert.equal(beyond.ok, false);
    if (!beyond.ok) assert.equal(beyond.reason, 'claims-expired');

    const atBoundary = validateTokenClaims(
      validPayload({ iat: iatSec, exp: Math.floor(NOW / 1000) - LIMITS.clockToleranceSec }),
      NOW,
      LIMITS,
    );
    assert.equal(atBoundary.ok, true, 'exp exactly at tolerance is accepted');
  });

  test('fuzz: acceptance matches the declared predicate for generated claim triples', () => {
    const rand = makeRandom(0x5eed2026);
    const randInt = (lo: number, hi: number) => lo + Math.floor(rand() * (hi - lo + 1));
    const nowSec = Math.floor(NOW / 1000);
    const tolMs = LIMITS.clockToleranceSec * 1000;

    for (let i = 0; i < 2000; i++) {
      const iatSec = nowSec + randInt(-120, 120);
      const lifetimeSec = randInt(-10, 7200);
      const expSec = iatSec + lifetimeSec;
      const payload = validPayload({ iat: iatSec, exp: expSec, jti: `tok-fuzz-${i}` });
      const result = validateTokenClaims(payload, NOW, LIMITS);
      const expected =
        lifetimeSec > 0 &&
        lifetimeSec <= LIMITS.maxTokenLifetimeSec &&
        expSec * 1000 >= NOW - tolMs &&
        iatSec * 1000 <= NOW + tolMs;
      assert.equal(
        result.ok,
        expected,
        `i=${i} iat=${iatSec} exp=${expSec} lifetime=${lifetimeSec} expected=${expected} got=${result.ok ? 'ok' : result.reason}`,
      );
    }
  });
});

describe('H2: end-to-end token verification', () => {
  test('the defaults are pinned (1h token ceiling, 24h configured ceiling cap, 60s skew cap)', () => {
    assert.equal(DEFAULT_MAX_TOKEN_LIFETIME_SEC, 3600);
    assert.equal(DEFAULT_MAX_WORKLOAD_LIFETIME_SEC, 900);
    assert.equal(MAX_CLOCK_SKEW_SEC, 60);
    assert.equal(MAX_TOKEN_LIFETIME_CEILING_SEC, 86_400);
  });

  test('a default 1h token verifies; a 2h token is refused', async () => {
    const mockIdp = await createMockIdP();
    const idp = await mockIdp.createIdP();
    const good = await mockIdp.signJWT({ sub: 'user:alice' });
    const auth = await idp.verifyToken(good);
    assert.ok(auth, '1h token must verify');
    assert.equal(auth.subject, 'user:alice');
    assert.ok(auth.expiresAt - auth.issuedAt <= DEFAULT_MAX_TOKEN_LIFETIME_SEC * 1000);

    const longLived = await mockIdp.signJWT({ sub: 'user:alice', exp: Date.now() + 7_200_000 });
    assert.equal(await idp.verifyToken(longLived), undefined, '2h token must be refused by the ceiling');
  });

  test('tokens missing exp / iat / jti / sub are refused end-to-end', async () => {
    const mockIdp = await createMockIdP();
    const idp = await mockIdp.createIdP();
    for (const field of ['exp', 'iat', 'jti', 'sub'] as const) {
      const token = await mockIdp.signJWT({ sub: 'user:alice', omit: [field] });
      assert.equal(await idp.verifyToken(token), undefined, `token missing ${field} must be refused`);
    }
  });

  test('clock tolerance is bounded but actually applied: expired-by-10s verifies, expired-by-45s does not', async () => {
    const mockIdp = await createMockIdP();
    const idp = await mockIdp.createIdP();
    const nowSec = Math.floor(Date.now() / 1000);

    const recent = await mockIdp.signJWT({ sub: 'user:alice', iat: nowSec - 70, exp: (nowSec - 10) * 1000 });
    assert.ok(await idp.verifyToken(recent), 'exp within the 30s tolerance must verify');

    const stale = await mockIdp.signJWT({ sub: 'user:alice', iat: nowSec - 105, exp: (nowSec - 45) * 1000 });
    assert.equal(await idp.verifyToken(stale), undefined, 'exp beyond tolerance must be refused');
  });

  test('a token issued beyond the skew tolerance in the future is refused', async () => {
    const mockIdp = await createMockIdP();
    const idp = await mockIdp.createIdP();
    const nowSec = Math.floor(Date.now() / 1000);
    const future = await mockIdp.signJWT({ sub: 'user:alice', iat: nowSec + 120, exp: (nowSec + 180) * 1000 });
    assert.equal(await idp.verifyToken(future), undefined, 'future-issued token must be refused');
  });

  test('config validation fails closed at construction', () => {
    const base = { issuer: 'https://idp.test.example.com', audience: 'test-audience' };
    for (const bad of [
      { clockToleranceSec: -1 },
      { clockToleranceSec: MAX_CLOCK_SKEW_SEC + 1 },
      { clockToleranceSec: Number.NaN },
      { maxTokenLifetimeSec: 0 },
      { maxTokenLifetimeSec: -60 },
      { maxTokenLifetimeSec: MAX_TOKEN_LIFETIME_CEILING_SEC + 1 },
      { maxTokenLifetimeSec: Number.POSITIVE_INFINITY },
    ]) {
      assert.throws(
        () => new IdentityProvider({ ...base, ...bad }),
        IdentityConfigError,
        `config ${JSON.stringify({ ...bad })} must be refused`,
      );
    }
    // Boundaries are valid.
    new IdentityProvider({ ...base, clockToleranceSec: MAX_CLOCK_SKEW_SEC, maxTokenLifetimeSec: MAX_TOKEN_LIFETIME_CEILING_SEC });
  });
});

describe('H2: workload identity derivation', () => {
  const CANARY = 'CANARY-H2-PARENT-CLAIM-0001';

  test('workloadAuth caps the lifetime, clears amr/claims, and records derivation', () => {
    const parent = mockAuth({ subject: 'user:alice', tokenId: 'tok_parent_1', expiresAt: NOW + 3_600_000, claims: { canary: CANARY } });
    const derived = IdentityProvider.workloadAuth(parent, 'agent:w1', NOW);
    assert.equal(derived.subject, 'agent:w1');
    assert.equal(derived.tokenId, `wl:agent:w1:${parent.tokenId}`);
    assert.equal(derived.issuedAt, NOW);
    assert.equal(derived.expiresAt, NOW + DEFAULT_MAX_WORKLOAD_LIFETIME_SEC * 1000);
    assert.deepEqual(derived.amr, []);
    assert.deepEqual(derived.claims, {});
    assert.equal(derived.derivedFrom?.subject, parent.subject);
    assert.equal(derived.derivedFrom?.tokenId, parent.tokenId);
    assert.ok(!JSON.stringify(derived).includes(CANARY), 'the parent payload must not ride along');
  });

  test('a derived context never outlives its parent', () => {
    const parent = mockAuth({ expiresAt: NOW + 120_000 });
    const derived = IdentityProvider.workloadAuth(parent, 'agent:w1', NOW);
    assert.equal(derived.expiresAt, parent.expiresAt);
  });

  test('a custom workload ceiling is honored; invalid ids and ceilings are refused', () => {
    const parent = mockAuth({ expiresAt: NOW + 3_600_000 });
    const derived = IdentityProvider.workloadAuth(parent, 'svc:indexer', NOW, { maxLifetimeSec: 60 });
    assert.equal(derived.expiresAt, NOW + 60_000);

    assert.throws(() => IdentityProvider.workloadAuth(parent, '', NOW), IdentityConfigError);
    for (const maxLifetimeSec of [0, -1, Number.NaN, MAX_TOKEN_LIFETIME_CEILING_SEC + 1]) {
      assert.throws(() => IdentityProvider.workloadAuth(parent, 'agent:w1', NOW, { maxLifetimeSec }), IdentityConfigError);
    }
  });

  test('an expired parent yields an already-expired derived context (fail closed at the PDP)', () => {
    const parent = mockAuth({ expiresAt: NOW - 1_000, issuedAt: NOW - 10_000 });
    const derived = IdentityProvider.workloadAuth(parent, 'agent:w1', NOW);
    assert.ok(derived.expiresAt <= NOW);
    const principal = IdentityProvider.authenticatedPrincipal(derived, TENANT_A);
    const world = testWorld();
    const decision = world.authorization.authorize({ principal, action: 'read', resourceId: world.resources.repoA! });
    assert.equal(decision.decision, 'deny');
    assert.equal(decision.denyReason, 'unauthenticated-principal');
  });

  test('a valid derived context passes the M2 guard (it denies on authority, not authentication)', () => {
    const parent = mockAuth({ expiresAt: NOW + 3_600_000 });
    const derived = IdentityProvider.workloadAuth(parent, 'agent:w1', NOW);
    const principal = IdentityProvider.authenticatedPrincipal(derived, TENANT_A);
    const world = testWorld();
    const decision = world.authorization.authorize({ principal, action: 'read', resourceId: world.resources.repoA! });
    assert.equal(decision.decision, 'deny');
    assert.equal(decision.denyReason, 'no-capability');
  });

  test('sessionAgent routes through workloadAuth (no human credential shape inherited)', () => {
    const parent = mockAuth({ subject: 'user:alice', tokenId: 'tok_parent_2', expiresAt: NOW + 3_600_000, claims: { canary: CANARY } });
    const agent = IdentityProvider.sessionAgent(parent, 'agent:summarizer-1', TENANT_A, ['worker'], NOW);
    assert.ok(agent.auth);
    assert.notEqual(agent.auth, parent);
    assert.equal(agent.auth.subject, 'agent:summarizer-1');
    assert.ok(agent.auth.tokenId.startsWith('wl:agent:summarizer-1:'));
    assert.equal(agent.auth.expiresAt, NOW + DEFAULT_MAX_WORKLOAD_LIFETIME_SEC * 1000);
    assert.deepEqual(agent.auth.claims, {});
    assert.deepEqual(agent.auth.amr, []);
    assert.ok(!JSON.stringify(agent).includes(CANARY));
  });
});

describe('H2: revocation propagation over the H13 channel', () => {
  interface Nodes {
    readonly world: World;
    readonly channel: InMemoryRevocationChannel;
    readonly mockIdp: Awaited<ReturnType<typeof createMockIdP>>;
    readonly idpA: IdentityProvider;
    readonly idpB: IdentityProvider;
    readonly nodeA: IncidentService;
  }

  async function twoNodes(): Promise<Nodes> {
    const channel = new InMemoryRevocationChannel();
    const world = testWorld({ channel });
    const mockIdp = await createMockIdP();
    const idpA = await mockIdp.createIdP();
    const idpB = await mockIdp.createIdP();
    idpB.attachRevocationFeed(channel, { syncIntervalMs: 0 });
    const nodeA = new IncidentService({
      authorization: world.authorization,
      sessions: world.sessions,
      audit: world.audit,
      eventLog: world.eventLog,
      channel,
      identity: idpA,
      clock: world.clock.now,
    });
    return { world, channel, mockIdp, idpA, idpB, nodeA };
  }

  test('a token revoked on node A is rejected on node B after the channel syncs', async () => {
    const { mockIdp, idpA, idpB, nodeA } = await twoNodes();
    const token = await mockIdp.signJWT({ sub: 'agent:summarizer-1', jti: 'tok-two-node' });
    assert.ok(await idpA.verifyToken(token), 'valid on node A before revocation');
    assert.ok(await idpB.verifyToken(token), 'valid on node B before revocation');

    nodeA.revokeToken('tok-two-node', TENANT_A, 'credential-leak drill');

    assert.equal(await idpA.verifyToken(token), undefined, 'node A rejects immediately (local-first)');
    assert.equal(await idpB.verifyToken(token), undefined, 'node B rejects after consuming the channel');
  });

  test('the operator path applies locally first, publishes, and audits', async () => {
    const { world, channel, mockIdp, idpA, nodeA } = await twoNodes();
    const token = await mockIdp.signJWT({ sub: 'agent:summarizer-1', jti: 'tok-revoke-me' });

    // Warm node A's local state with the token.
    assert.ok(await idpA.verifyToken(token));

    const before = world.eventLog.all().length;
    nodeA.revokeToken('tok-revoke-me', TENANT_A, 'credential-leak drill');
    assert.equal(idpA.isTokenRevoked('tok-revoke-me'), true, 'local enforcement is immediate');
    assert.equal(await idpA.verifyToken(token), undefined, 'node A rejects the revoked token immediately');

    const records = channel.since(-1);
    const record = records.find((r) => r.action === 'revoke-token');
    assert.ok(record, 'a revoke-token record must be published');
    assert.equal(record?.targetId, 'tok-revoke-me');

    const events = world.eventLog.all().slice(before);
    const evidence = events.find((e) => e.action === 'incident.revoke');
    assert.ok(evidence, 'the operator revocation must be audited');
    assert.equal((evidence?.metadata as { tokenId?: string } | undefined)?.tokenId, 'tok-revoke-me');
  });

  test('node B learns a revocation through the feed (attachRevocationFeed)', async () => {
    const channel = new InMemoryRevocationChannel();
    const mockIdp = await createMockIdP();
    const idpA = await mockIdp.createIdP();
    const idpB = await mockIdp.createIdP();
    idpB.attachRevocationFeed(channel, { syncIntervalMs: 0 });

    const token = await mockIdp.signJWT({ sub: 'agent:summarizer-1', jti: 'tok-cross-node' });
    assert.ok(await idpA.verifyToken(token));
    assert.ok(await idpB.verifyToken(token), 'valid on node B before the revocation');

    idpA.revokeToken('tok-cross-node');
    channel.publish({ action: 'revoke-token', scope: 'tenant', tenantId: TENANT_A, targetId: 'tok-cross-node', reason: 'drill', at: NOW });
    assert.equal(await idpB.verifyToken(token), undefined, 'node B must reject after consuming the feed');
  });

  test('an incident sync routes revoke-token records to the local IdP (applyRecord path)', async () => {
    const channel = new InMemoryRevocationChannel();
    const world = testWorld({ channel });
    const mockIdp = await createMockIdP();
    const idp = await mockIdp.createIdP();
    const node = new IncidentService({
      authorization: world.authorization,
      sessions: world.sessions,
      audit: world.audit,
      eventLog: world.eventLog,
      channel,
      identity: idp,
      clock: world.clock.now,
    });
    channel.publish({ action: 'revoke-token', scope: 'tenant', tenantId: TENANT_A, targetId: 'tok-via-sync', reason: 'drill', at: NOW });
    node.sync(true);
    assert.equal(idp.isTokenRevoked('tok-via-sync'), true);
  });

  test('revoke-token records without a target are ignored, not applied', async () => {
    const channel = new InMemoryRevocationChannel();
    const world = testWorld({ channel });
    const mockIdp = await createMockIdP();
    const idp = await mockIdp.createIdP();
    const node = new IncidentService({
      authorization: world.authorization,
      sessions: world.sessions,
      audit: world.audit,
      eventLog: world.eventLog,
      channel,
      identity: idp,
      clock: world.clock.now,
    });
    channel.publish({ action: 'revoke-token', scope: 'global', reason: 'no target', at: NOW });
    node.sync(true);
    assert.equal(idp.isTokenRevoked(''), false);
  });

  test('a feed outage does not break verification (propagation is delayed, not availability)', async () => {
    const mockIdp = await createMockIdP();
    const idp = await mockIdp.createIdP();
    const brokenFeed: TokenRevocationFeed = {
      refresh() {},
      since(): readonly never[] {
        throw new Error('feed down');
      },
    };
    idp.attachRevocationFeed(brokenFeed, { syncIntervalMs: 0 });
    const token = await mockIdp.signJWT({ sub: 'user:alice' });
    const auth = await idp.verifyToken(token);
    assert.ok(auth, 'verification stays available while the revocation feed is down');
  });

  test('attachRevocationFeed rejects a negative sync interval', async () => {
    const mockIdp = await createMockIdP();
    const idp = await mockIdp.createIdP();
    assert.throws(() => idp.attachRevocationFeed(new InMemoryRevocationChannel(), { syncIntervalMs: -1 }), IdentityConfigError);
  });

  test('a REST request with a channel-revoked token is 403 before a principal is minted', async () => {
    const channel = new InMemoryRevocationChannel();
    const world = testWorld({ channel });
    const mockIdp = await createMockIdP();
    const idp = await mockIdp.createIdP();
    idp.attachRevocationFeed(channel, { syncIntervalMs: 0 });
    const resolvePrincipal: RestApiDeps['resolvePrincipal'] = (auth) => (auth.subject === world.user.id ? world.user : undefined);
    const api = new RestApi({ authorization: world.authorization, idp, eventLog: world.eventLog, resolvePrincipal });
    const port = await api.start();
    try {
      const token = await mockIdp.signJWT({ sub: 'user:alice', jti: 'tok-rest-revoke' });
      const allowed = await postAuthorize(port, token, JSON.stringify({ action: 'read', resourceId: world.resources.repoA! }));
      assert.notEqual(JSON.parse(allowed.body).denyReason, 'unauthenticated-principal', 'expected to authenticate before revocation');

      channel.publish({ action: 'revoke-token', scope: 'tenant', tenantId: TENANT_A, targetId: 'tok-rest-revoke', reason: 'drill', at: Date.now() });
      const denied = await postAuthorize(port, token, JSON.stringify({ action: 'read', resourceId: world.resources.repoA! }));
      assert.equal(denied.status, 403);
      assert.equal(JSON.parse(denied.body).denyReason, 'unauthenticated-principal');
    } finally {
      api.stop();
    }
  });
});

describe('H2: credential material never reaches evidence or errors', () => {
  const CANARY = 'CANARY-H2-TOKEN-PAYLOAD-0001';

  test('a channel-failure operator revoke still applies locally first and audits', async () => {
    class BrokenChannel extends InMemoryRevocationChannel {
      override publish(_input: RevocationInput): void {
        throw new Error('channel down');
      }
    }
    const channel = new BrokenChannel();
    const world = testWorld({ channel: channel as RevocationChannel });
    const mockIdp = await createMockIdP();
    const idp = await mockIdp.createIdP();
    const node = new IncidentService({
      authorization: world.authorization,
      sessions: world.sessions,
      audit: world.audit,
      eventLog: world.eventLog,
      channel,
      identity: idp,
      clock: world.clock.now,
    });
    assert.throws(() => node.revokeToken('tok-local-first', TENANT_A, 'channel down drill'));
    assert.equal(idp.isTokenRevoked('tok-local-first'), true, 'local enforcement precedes the broadcast');
    assert.ok(
      world.eventLog.all().some((e) => e.action === 'incident.revoke' && (e.metadata as { tokenId?: string } | undefined)?.tokenId === 'tok-local-first'),
      'the revocation is audited even when the broadcast throws',
    );
  });

  test('the raw token and a payload canary appear in no event and no response', async () => {
    const channel = new InMemoryRevocationChannel();
    const world = testWorld({ channel });
    const mockIdp = await createMockIdP();
    const idp = await mockIdp.createIdP();
    const resolvePrincipal: RestApiDeps['resolvePrincipal'] = (auth) => (auth.subject === world.user.id ? world.user : undefined);
    const api = new RestApi({ authorization: world.authorization, idp, eventLog: world.eventLog, resolvePrincipal });
    const port = await api.start();
    try {
      const good = await mockIdp.signJWT({ sub: 'user:alice', sessionCanary: CANARY });
      const ok = await postAuthorize(port, good, JSON.stringify({ action: 'read', resourceId: world.resources.repoA! }));
      assert.ok(!ok.body.includes(good), 'the raw token must not be echoed');
      assert.ok(!ok.body.includes(CANARY), 'a payload claim must not be echoed');

      const garbage = `not-a-jwt-${CANARY}`;
      const bad = await postAuthorize(port, garbage, '{}');
      assert.equal(bad.status, 403);
      assert.ok(!bad.body.includes(garbage), 'the rejected credential must not be echoed');
      assert.ok(!bad.body.includes(CANARY), 'rejection bodies must not echo claim material');
    } finally {
      api.stop();
    }

    const log = JSON.stringify(world.eventLog.all());
    assert.ok(!log.includes(CANARY), 'no event may contain a token payload claim');
    assert.ok(!log.includes('"claims"'), 'no event may carry a serialized AuthContext claims payload');
    for (let i = 0; i < world.secretValues.length; i++) {
      assert.ok(!log.includes(world.secretValues[i]!), `no event may contain registered secret value #${i}`);
    }
    const auth = await idp.verifyToken(await mockIdp.signJWT({ sub: 'user:alice' }));
    assert.ok(auth);
    assert.ok(!JSON.stringify(auth).includes('eyJ'), 'the AuthContext must not carry the compact JWT');
  });

  test('a PDP decision made under a derived workload identity leaves no parent material in the event log', async () => {
    const world = testWorld();
    const parent = mockAuth({ subject: 'user:alice', tokenId: 'tok_parent_canary', claims: { canary: CANARY } });
    const derived = IdentityProvider.workloadAuth(parent, 'agent:w1', world.clock.now());
    const principal = { ...IdentityProvider.authenticatedPrincipal(derived, TENANT_A), roles: ['worker'] };
    const decision = world.authorization.authorize({ principal, action: 'read', resourceId: world.resources.repoA! });
    assert.equal(decision.decision, 'deny');
    const log = JSON.stringify(world.eventLog.all());
    assert.ok(!log.includes(CANARY), 'parent claims must never enter evidence');
    assert.ok(!log.includes('tok_parent_canary'), 'the parent token id must not leak through the derived principal');
  });
});
