/**
 * Fix audit tickets 01 + 02 from session-audit M15.
 *
 * Ticket 01: approve handler must persist BEFORE consuming the single-use
 * capability. If persist throws after the in-memory approval, the capability
 * is consumed but the approval is lost on restart — permanent data loss.
 * Ticket 02: `updateCapabilityRequestStatus` must reject statuses outside
 * the typed vocabulary (`pending | approved | denied | expired`).
 */

import { test, describe } from 'node:test';
import assert from 'node:assert/strict';
import { request as httpRequest } from 'node:http';
import { RestApi } from '../src/rest-api.ts';
import { SessionManager } from '../src/session-manager.ts';
import { CapabilityRequestService } from '../src/capability-request.ts';
import { registerSessionRoutes } from '../src/rest-sessions.ts';
import { type World } from '../src/scenario.ts';
import { createMockIdP, testWorld, type MockIdP } from '../src/testing.ts';
import { PersistenceStore } from '../src/persistence.ts';
import type { Principal } from '../src/domain.ts';

interface Booted {
  readonly api: RestApi;
  readonly world: World;
  readonly mockIdp: MockIdP;
  readonly port: number;
  readonly requests: CapabilityRequestService;
}

/**
 * Boot with a PersistenceStore wired to a DELIBERATELY-BAD URL. The store
 * constructor is lazy (postgres.js connects on first query), so construction
 * succeeds; the first `createCapabilityRequest` / `updateCapabilityRequestStatus`
 * call throws because the URL is unparseable. This is the simplest way to
 * exercise the persist-failure path without a live Postgres dependency.
 */
async function bootWithFailingStore(): Promise<Booted> {
  const world = testWorld();
  const mockIdp = await createMockIdP();
  const idp = await mockIdp.createIdP();
  const registry: Record<string, Principal> = {
    'user:alice': world.user,
    'agent:summarizer-1': world.agent,
  };
  const failingStore = new PersistenceStore({ url: 'postgres://postgres:postgres@127.0.0.1:1/db' });
  const api = new RestApi({
    authorization: world.authorization,
    idp,
    eventLog: world.eventLog,
    resolvePrincipal: (auth): Principal | undefined => registry[auth.subject],
  });
  const sessions = new SessionManager();
  const requests = new CapabilityRequestService(world.eventLog, world.authorization, world.root);
  registerSessionRoutes(api, { sessions, requests, requestsStore: failingStore });
  const port = await api.start();
  return { api, world, mockIdp, port, requests };
}

function rawRequest(options: {
  port: number;
  method: string;
  path: string;
  headers?: Record<string, string>;
  body?: string;
}): Promise<{ status: number; body: string }> {
  return new Promise((resolve, reject) => {
    const req = httpRequest(
      { host: '127.0.0.1', port: options.port, path: options.path, method: options.method, headers: options.headers },
      (res) => {
        let data = '';
        res.on('data', (chunk: Buffer) => (data += chunk.toString('utf8')));
        res.on('end', () => resolve({ status: res.statusCode ?? 0, body: data }));
      },
    );
    req.on('error', reject);
    if (options.body !== undefined) req.write(options.body);
    req.end();
  });
}

async function agentToken(booted: Booted): Promise<string> {
  return booted.mockIdp.signJWT({ sub: 'agent:summarizer-1', amr: ['pwd', 'mfa'] });
}
async function userToken(booted: Booted, sub = 'user:alice'): Promise<string> {
  return booted.mockIdp.signJWT({ sub, amr: ['pwd', 'mfa'] });
}

describe('PersistenceStore.updateCapabilityRequestStatus (audit ticket 02)', () => {
  /**
   * Live-DB guard for invalid status strings. Skips without DATABASE_URL —
   * the guard is at the app boundary, so the test can still exercise it
   * by constructing a store with a bad URL (the validation runs before
   * any SQL is issued).
   */
  test('rejects statuses outside the typed vocabulary', async () => {
    const store = new PersistenceStore({ url: 'postgres://postgres:postgres@127.0.0.1:1/db' });
    try {
      await assert.rejects(
        store.updateCapabilityRequestStatus('t1', 'req-1', 'banana', 'user:alice'),
        /invalid capability request status/,
      );
      await assert.rejects(
        store.updateCapabilityRequestStatus('t1', 'req-1', '', 'user:alice'),
        /invalid capability request status/,
      );
      await assert.rejects(
        store.updateCapabilityRequestStatus('t1', 'req-1', 'approved; DROP TABLE', 'user:alice'),
        /invalid capability request status/,
      );
    } finally {
      store.close();
    }
  });
});

describe('approve handler ordering (audit ticket 01)', () => {
  test('persist failure on approve does NOT consume the capability or record approval in memory', async () => {
    const booted = await bootWithFailingStore();
    try {
      // Submit a capability request.
      const submitRes = await rawRequest({
        port: booted.port,
        method: 'POST',
        path: '/v1/capability-requests',
        headers: { authorization: `Bearer ${await agentToken(booted)}`, 'content-type': 'application/json' },
        body: JSON.stringify({ sessionId: 'sess-1', resources: ['doc:acme-merger'], actions: ['read'], maxClassification: 'confidential' }),
      });
      assert.equal(submitRes.status, 500, 'submit must fail when persist fails (fail closed)');

      // The submit handler has the same ordering bug (ticket 01, submit case) — fix
      // is a larger refactor; this test only asserts the approve case.

      // For the approve test, we need a request that exists in the service. Seed it
      // directly through the service (bypassing the submit handler).
      const seeded = booted.requests.submit(
        booted.world.agent,
        'sess-2',
        ['doc:acme-merger'],
        ['read'],
        'confidential',
        'need it',
      );
      const requestId = seeded.id;
      const issueCountBefore = booted.world.eventLog.all().filter((e) => e.action === 'capability.issue').length;

      const approveRes = await rawRequest({
        port: booted.port,
        method: 'POST',
        path: `/v1/capability-requests/${requestId}/approvals`,
        headers: { authorization: `Bearer ${await userToken(booted)}`, 'content-type': 'application/json' },
        body: '{}',
      });

      // Persist must fail (bad URL) → handler propagates → 500 to client.
      assert.equal(approveRes.status, 500);

      // The capability must NOT be consumed: no new capability.issue event.
      const issueCountAfter = booted.world.eventLog.all().filter((e) => e.action === 'capability.issue').length;
      assert.equal(issueCountAfter, issueCountBefore, 'capability must not be consumed when persist fails');

      // The request must still be pending in the service — approvable again after the store recovers.
      const stillPending = booted.requests.get(requestId);
      assert.ok(stillPending);
      assert.equal(stillPending.status, 'pending', 'request must stay pending when persist fails');
    } finally {
      booted.api.stop();
    }
  });
});
