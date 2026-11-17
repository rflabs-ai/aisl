/**
 * Ticket 06: the H13 revocation feed is wired by the production assembly, not
 * just by tests.
 *
 * Before this test existed, `attachRevocationFeed` had no caller under `src/`:
 * a running server verified tokens whose `jti` another node had revoked and
 * never learned about the revocation. These cases boot the real server
 * assembly (`startRestServer` -> persistent world factory -> REST server) and
 * assert the feed is attached, that a `revoke-token` record rejects the token
 * on the next verify, and that a failed attach is reported in `/healthz`
 * instead of being skipped silently.
 */

import { request as httpRequest } from 'node:http';
import { describe, test } from 'node:test';
import assert from 'node:assert/strict';
import { startRestServer } from '../src/server.ts';
import { IdentityProvider } from '../src/identity.ts';
import { InMemoryRevocationChannel } from '../src/incident.ts';
import { TENANT_A, type World } from '../src/scenario.ts';
import { createMockIdP } from '../src/testing.ts';

const AGENT = 'agent:summarizer-1';

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

function getJson(port: number, path: string): Promise<Record<string, unknown>> {
  return new Promise((resolve, reject) => {
    httpRequest({ host: '127.0.0.1', port, path, method: 'GET' }, (res) => {
      let data = '';
      res.on('data', (chunk: Buffer) => {
        data += chunk.toString('utf8');
      });
      res.on('end', () => resolve(JSON.parse(data) as Record<string, unknown>));
    })
      .on('error', reject)
      .end();
  });
}

describe('H13: revocation feed wiring in the production assembly', () => {
  test('the server assembly attaches the feed and a revoke-token record rejects the token on the next verify', async () => {
    const channel = new InMemoryRevocationChannel();
    const mockIdp = await createMockIdP();
    const idp = await mockIdp.createIdP();
    let world: World | undefined;
    const started = await startRestServer({
      idp,
      channel,
      revocationSyncIntervalMs: 0,
      resolvePrincipal: (auth) => (world !== undefined && auth.subject === world.agent.id ? world.agent : undefined),
    });
    world = started.world;
    try {
      // The assembly, not the test, performed the attach.
      assert.equal(world.revocationAttached, true, 'the world factory attached the feed');
      assert.equal(idp.hasRevocationFeed(), true, 'the identity service consumed the feed');

      // bootstrap: false means the server mints no fixture authority; issue one
      // capability explicitly so the first verify proves the token was valid.
      world.authorization.issue(world.root, {
        subject: world.agent.id,
        tenantId: TENANT_A,
        resourceIds: [world.resources.repoA!],
        actions: ['read'],
        maxClassification: 'internal',
        expiresAt: world.clock.now() + 3_600_000,
        provenance: { source: 'session-bootstrap', taskId: 'ticket-06-revocation-feed' },
      });

      const token = await mockIdp.signJWT({ sub: AGENT, jti: 'tok-assembly-revoke' });
      const body = JSON.stringify({ action: 'read', resourceId: world.resources.repoA });
      const allowed = await postAuthorize(started.port, token, body);
      assert.equal(allowed.status, 200, allowed.body);

      channel.publish({
        action: 'revoke-token',
        scope: 'tenant',
        tenantId: TENANT_A,
        targetId: 'tok-assembly-revoke',
        reason: 'drill',
        at: Date.now(),
      });
      const denied = await postAuthorize(started.port, token, body);
      assert.equal(denied.status, 403, 'the next verify rejects the revoked jti');
      assert.equal((JSON.parse(denied.body) as { denyReason?: string }).denyReason, 'unauthenticated-principal');

      const health = await getJson(started.port, '/healthz');
      assert.equal(health.revocation, 'ok');
    } finally {
      started.api.stop();
    }
  });

  test('a failed attach is recorded in health, not skipped silently', async () => {
    class FailingFeedIdp extends IdentityProvider {
      override attachRevocationFeed(): void {
        throw new Error('revocation channel not ready');
      }
    }
    const idp = new FailingFeedIdp({
      issuer: 'https://idp.test.example.com',
      audience: 'test-audience',
      jwksUri: 'https://idp.test.example.com/jwks',
    });
    const started = await startRestServer({ idp, resolvePrincipal: () => undefined });
    try {
      assert.equal(started.world.revocationAttached, false);
      assert.match(started.world.revocationAttachError ?? '', /revocation channel not ready/);
      const health = await getJson(started.port, '/healthz');
      assert.equal(health.revocation, 'unavailable', 'the gap is operator-visible');
      assert.equal(health.idp, 'healthy');
    } finally {
      started.api.stop();
    }
  });
});
