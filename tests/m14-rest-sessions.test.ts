/**
 * M14 Phase 2B acceptance suite: REST session routes and the M4
 * capability-request flow over ADR-019's HTTP boundary. Every test boots its
 * own world + server (per-test teardown, no cross-test state) and talks raw
 * node:http, mirroring the m14-rest-api acceptance pattern.
 */

import { request as httpRequest } from 'node:http';
import { randomUUID } from 'node:crypto';
import { test, describe } from 'node:test';
import assert from 'node:assert/strict';
import { RestApi } from '../src/rest-api.ts';
import { SessionManager } from '../src/session-manager.ts';
import { CapabilityRequestService } from '../src/capability-request.ts';
import { registerSessionRoutes } from '../src/rest-sessions.ts';
import { TENANT_A, TENANT_B, type World } from '../src/scenario.ts';
import { createMockIdP, testWorld, type MockIdP } from '../src/testing.ts';
import type { AuthContext, Principal } from '../src/domain.ts';

interface Booted {
  readonly api: RestApi;
  readonly world: World;
  readonly mockIdp: MockIdP;
  readonly port: number;
  readonly sessions: SessionManager;
  readonly requests: CapabilityRequestService;
  readonly bob: Principal;
}

interface RawResponse {
  readonly status: number;
  readonly body: string;
}

interface JsonResponse {
  readonly status: number;
  readonly text: string;
  readonly body: Record<string, unknown>;
}

async function boot(): Promise<Booted> {
  const world = testWorld();
  const mockIdp = await createMockIdP();
  const idp = await mockIdp.createIdP();
  const carol: Principal = { id: 'user:carol', kind: 'user', tenantId: TENANT_A, roles: ['reviewer'], attributes: {} };
  const bob: Principal = { id: 'user:bob', kind: 'user', tenantId: TENANT_B, roles: [], attributes: {} };
  const registry: Record<string, Principal> = {
    'user:alice': world.user,
    'user:carol': carol,
    'user:bob': bob,
    'agent:summarizer-1': world.agent,
  };
  const api = new RestApi({
    authorization: world.authorization,
    idp,
    eventLog: world.eventLog,
    resolvePrincipal: (auth: AuthContext): Principal | undefined => registry[auth.subject],
  });
  const sessions = new SessionManager();
  const requests = new CapabilityRequestService(world.eventLog, world.authorization, world.root);
  registerSessionRoutes(api, { sessions, requests });
  const port = await api.start();
  return { api, world, mockIdp, port, sessions, requests, bob };
}

function token(booted: Booted, sub: string, amr: readonly string[] = ['pwd', 'mfa']): Promise<string> {
  return booted.mockIdp.signJWT({ sub, amr });
}

function rawRequest(options: {
  port: number;
  method: string;
  path: string;
  headers?: Record<string, string>;
  body?: string;
}): Promise<RawResponse> {
  return new Promise((resolve, reject) => {
    const req = httpRequest(
      {
        host: '127.0.0.1',
        port: options.port,
        method: options.method,
        path: options.path,
        headers: options.headers,
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
    if (options.body !== undefined) req.write(options.body);
    req.end();
  });
}

async function jsonRequest(options: {
  port: number;
  method: string;
  path: string;
  token?: string;
  body?: unknown;
}): Promise<JsonResponse> {
  const headers: Record<string, string> = {};
  if (options.token !== undefined) {
    headers.authorization = `Bearer ${options.token}`;
    headers['content-type'] = 'application/json';
  }
  const res = await rawRequest({
    port: options.port,
    method: options.method,
    path: options.path,
    headers,
    ...(options.body !== undefined ? { body: JSON.stringify(options.body) } : {}),
  });
  const parsed = res.body.length > 0 ? (JSON.parse(res.body) as Record<string, unknown>) : {};
  return { status: res.status, text: res.body, body: parsed };
}

async function createSession(booted: Booted, sub: string, amr?: readonly string[]): Promise<JsonResponse> {
  return jsonRequest({
    port: booted.port,
    method: 'POST',
    path: '/v1/sessions',
    token: await token(booted, sub, amr),
    body: {},
  });
}

async function submitAgentRequest(
  booted: Booted,
  overrides: Record<string, unknown> = {},
): Promise<JsonResponse> {
  return jsonRequest({
    port: booted.port,
    method: 'POST',
    path: '/v1/capability-requests',
    token: await token(booted, 'agent:summarizer-1'),
    body: {
      sessionId: 'sess-agent-1',
      resources: ['doc:acme-merger'],
      actions: ['read'],
      maxClassification: 'confidential',
      justification: 'summarize the merger document',
      ...overrides,
    },
  });
}

async function approve(
  booted: Booted,
  requestId: string,
  sub: string,
  body: unknown,
  amr?: readonly string[],
): Promise<JsonResponse> {
  return jsonRequest({
    port: booted.port,
    method: 'POST',
    path: `/v1/capability-requests/${requestId}/approvals`,
    token: await token(booted, sub, amr),
    body,
  });
}

function eventsOf(booted: Booted, action: string) {
  return booted.world.eventLog.all().filter((event) => event.action === action);
}

describe('rest sessions: POST /v1/sessions', () => {
  test('MFA user token → 201 whitelisted projection with no auth/claims/token echo', async () => {
    const booted = await boot();
    try {
      const t = await token(booted, 'user:alice');
      const res = await jsonRequest({ port: booted.port, method: 'POST', path: '/v1/sessions', token: t, body: {} });
      assert.equal(res.status, 201);
      assert.deepEqual(Object.keys(res.body).sort(), ['createdAt', 'expiresAt', 'id', 'mfaVerified']);
      assert.equal(res.body.mfaVerified, true);
      assert.equal(typeof res.body.id, 'string');
      assert.equal(typeof res.body.createdAt, 'number');
      assert.equal(typeof res.body.expiresAt, 'number');
      assert.ok(!res.text.includes('"auth"'), 'auth context must never reach the wire');
      assert.ok(!res.text.includes('"claims"'), 'token claims must never reach the wire');
      assert.ok(!res.text.includes(t), 'raw JWT must never reach the wire');
    } finally {
      booted.api.stop();
    }
  });

  test('non-MFA token → 403 approval-mfa-required', async () => {
    const booted = await boot();
    try {
      const res = await createSession(booted, 'user:alice', ['pwd']);
      assert.equal(res.status, 403);
      assert.deepEqual(res.body, { error: 'approval-mfa-required' });
    } finally {
      booted.api.stop();
    }
  });
});

describe('rest sessions: DELETE /v1/sessions/:id', () => {
  test('own session → 200 revoked:true; immediate propagation in SessionManager', async () => {
    const booted = await boot();
    try {
      const created = await createSession(booted, 'user:alice');
      const id = String(created.body.id);
      const res = await jsonRequest({
        port: booted.port,
        method: 'DELETE',
        path: `/v1/sessions/${id}`,
        token: await token(booted, 'user:alice'),
      });
      assert.equal(res.status, 200);
      assert.deepEqual(res.body, { revoked: true });
      assert.equal(booted.sessions.get(id), undefined, 'revocation must propagate immediately');
    } finally {
      booted.api.stop();
    }
  });

  test('unknown id → 404 not-found', async () => {
    const booted = await boot();
    try {
      const res = await jsonRequest({
        port: booted.port,
        method: 'DELETE',
        path: `/v1/sessions/${randomUUID()}`,
        token: await token(booted, 'user:alice'),
      });
      assert.equal(res.status, 404);
      assert.deepEqual(res.body, { error: 'not-found' });
    } finally {
      booted.api.stop();
    }
  });

  test('cross-tenant session → 403 tenant-mismatch', async () => {
    const booted = await boot();
    try {
      const created = await createSession(booted, 'user:bob');
      const id = String(created.body.id);
      const res = await jsonRequest({
        port: booted.port,
        method: 'DELETE',
        path: `/v1/sessions/${id}`,
        token: await token(booted, 'user:alice'),
      });
      assert.equal(res.status, 403);
      assert.deepEqual(res.body, { error: 'tenant-mismatch' });
      assert.notEqual(booted.sessions.get(id), undefined, 'foreign session must survive the denied revocation');
    } finally {
      booted.api.stop();
    }
  });

  test('same-tenant foreign session → 403 no-capability (owner-only ceiling)', async () => {
    const booted = await boot();
    try {
      const created = await createSession(booted, 'user:carol');
      const id = String(created.body.id);
      const res = await jsonRequest({
        port: booted.port,
        method: 'DELETE',
        path: `/v1/sessions/${id}`,
        token: await token(booted, 'user:alice'),
      });
      assert.equal(res.status, 403);
      assert.deepEqual(res.body, { error: 'no-capability' });
      assert.notEqual(booted.sessions.get(id), undefined, 'foreign session must survive the denied revocation');
    } finally {
      booted.api.stop();
    }
  });
});

describe('rest capability-requests: submit + list', () => {
  test('agent submits → 201 whitelisted pending request + capability.request event', async () => {
    const booted = await boot();
    try {
      const res = await submitAgentRequest(booted);
      assert.equal(res.status, 201);
      assert.deepEqual(Object.keys(res.body).sort(), [
        'createdAt',
        'id',
        'justification',
        'maxClassification',
        'principalId',
        'requestedActions',
        'requestedResources',
        'sessionId',
        'status',
        'tenantId',
      ]);
      assert.equal(res.body.status, 'pending');
      assert.equal(res.body.principalId, 'agent:summarizer-1');
      assert.equal(res.body.tenantId, 'acme');
      assert.ok(eventsOf(booted, 'capability.request').length > 0);
    } finally {
      booted.api.stop();
    }
  });

  test('hostile body fields are dropped by the whitelist, tenant stays verified', async () => {
    const booted = await boot();
    try {
      const res = await submitAgentRequest(booted, {
        authority: { admin: true },
        signature: 'x',
        tenantId: 'globex',
      });
      assert.equal(res.status, 201);
      assert.equal(res.body.authority, undefined);
      assert.equal(res.body.signature, undefined);
      assert.equal(res.body.tenantId, 'acme');
      assert.ok(!res.text.includes('"authority"'), 'authority key must never reach the wire');
      assert.ok(!res.text.includes('"signature"'), 'signature key must never reach the wire');
      assert.ok(!res.text.includes('globex'), 'client-supplied tenant value must never reach the wire');
      const event = eventsOf(booted, 'capability.request').at(-1);
      assert.ok(event, 'capability.request event must exist');
      assert.ok(!JSON.stringify(event.metadata).includes('globex'), 'event metadata must not carry the smuggled tenant');
    } finally {
      booted.api.stop();
    }
  });

  test('pending list is tenant-scoped: alice sees acme, not the globex seed', async () => {
    const booted = await boot();
    try {
      const globexRequest = booted.requests.submit(
        booted.bob,
        'sess-globex',
        ['doc:globex-strategy'],
        ['read'],
        'internal',
        'seed globex request',
      );
      const submitted = await submitAgentRequest(booted);
      assert.equal(submitted.status, 201);
      const agentRequestId = String(submitted.body.id);

      const res = await jsonRequest({
        port: booted.port,
        method: 'GET',
        path: '/v1/capability-requests',
        token: await token(booted, 'user:alice'),
      });
      assert.equal(res.status, 200);
      const list = res.body.requests;
      assert.ok(Array.isArray(list), 'requests must be an array');
      assert.ok(
        list.some((r) => typeof r === 'object' && r !== null && (r as Record<string, unknown>).id === agentRequestId),
        'the agent pending request must be listed',
      );
      assert.ok(!res.text.includes(globexRequest.id), 'the globex request must not appear for alice');
      assert.ok(
        list.every(
          (r) => typeof r === 'object' && r !== null && (r as Record<string, unknown>).tenantId === 'acme',
        ),
        'every listed request must be in the reviewer tenant',
      );
    } finally {
      booted.api.stop();
    }
  });
});

describe('rest capability-requests: approvals', () => {
  test('MFA user approves without scope → 201 with capability, no signature leaked', async () => {
    const booted = await boot();
    try {
      const submitted = await submitAgentRequest(booted);
      const requestId = String(submitted.body.id);
      const res = await approve(booted, requestId, 'user:alice', {});
      assert.equal(res.status, 201);
      const request = res.body.request as Record<string, unknown>;
      const capability = res.body.capability as Record<string, unknown>;
      assert.equal(request.status, 'approved');
      assert.equal(request.reviewedBy, 'user:alice');
      assert.equal(typeof request.reviewedAt, 'number');
      assert.equal(capability.subject, 'agent:summarizer-1');
      assert.equal(capability.singleUse, true);
      assert.deepEqual(Object.keys(capability).sort(), [
        'actions',
        'expiresAt',
        'id',
        'maxClassification',
        'provenance',
        'resourceIds',
        'singleUse',
        'subject',
        'tenantId',
      ]);
      assert.ok(!res.text.includes('"signature"'), 'capability signature must never reach the wire');
      assert.ok(eventsOf(booted, 'capability.approve').length > 0);
    } finally {
      booted.api.stop();
    }
  });

  test('narrowing scope mints exactly the narrowed resource set', async () => {
    const booted = await boot();
    try {
      const submitted = await submitAgentRequest(booted, { sessionId: 'sess-agent-2' });
      const requestId = String(submitted.body.id);
      const res = await approve(booted, requestId, 'user:alice', {
        scope: { resources: ['doc:acme-onboarding'] },
      });
      assert.equal(res.status, 201);
      const capability = res.body.capability as Record<string, unknown>;
      assert.deepEqual(capability.resourceIds, ['doc:acme-onboarding']);
    } finally {
      booted.api.stop();
    }
  });

  test('self-approval → 403 capability-request-denied', async () => {
    const booted = await boot();
    try {
      const submitted = await jsonRequest({
        port: booted.port,
        method: 'POST',
        path: '/v1/capability-requests',
        token: await token(booted, 'user:alice'),
        body: {
          sessionId: 'sess-alice-1',
          resources: ['doc:acme-merger'],
          actions: ['read'],
          maxClassification: 'confidential',
        },
      });
      const res = await approve(booted, String(submitted.body.id), 'user:alice', {});
      assert.equal(res.status, 403);
      assert.deepEqual(res.body, { error: 'capability-request-denied' });
    } finally {
      booted.api.stop();
    }
  });

  test('agent token as approver → 403 capability-request-denied', async () => {
    const booted = await boot();
    try {
      const submitted = await submitAgentRequest(booted);
      const res = await approve(booted, String(submitted.body.id), 'agent:summarizer-1', {});
      assert.equal(res.status, 403);
      assert.deepEqual(res.body, { error: 'capability-request-denied' });
    } finally {
      booted.api.stop();
    }
  });

  test('non-MFA approver → 403 approval-mfa-required at the boundary', async () => {
    const booted = await boot();
    try {
      const submitted = await submitAgentRequest(booted);
      const res = await approve(booted, String(submitted.body.id), 'user:alice', {}, ['pwd']);
      assert.equal(res.status, 403);
      assert.deepEqual(res.body, { error: 'approval-mfa-required' });
    } finally {
      booted.api.stop();
    }
  });

  test('approve unknown id → 404 not-found', async () => {
    const booted = await boot();
    try {
      const res = await approve(booted, randomUUID(), 'user:alice', {});
      assert.equal(res.status, 404);
      assert.deepEqual(res.body, { error: 'not-found' });
    } finally {
      booted.api.stop();
    }
  });

  test('cross-tenant approve → 403 tenant-mismatch', async () => {
    const booted = await boot();
    try {
      const submitted = await submitAgentRequest(booted);
      const res = await approve(booted, String(submitted.body.id), 'user:bob', {});
      assert.equal(res.status, 403);
      assert.deepEqual(res.body, { error: 'tenant-mismatch' });
    } finally {
      booted.api.stop();
    }
  });

  test('double approve → second gets 409 not-pending', async () => {
    const booted = await boot();
    try {
      const submitted = await submitAgentRequest(booted);
      const requestId = String(submitted.body.id);
      const first = await approve(booted, requestId, 'user:alice', {});
      assert.equal(first.status, 201);
      const second = await approve(booted, requestId, 'user:alice', {});
      assert.equal(second.status, 409);
      assert.deepEqual(second.body, { error: 'not-pending' });
    } finally {
      booted.api.stop();
    }
  });

  test('malformed body → 400 invalid-body; server keeps serving', async () => {
    const booted = await boot();
    try {
      const res = await submitAgentRequest(booted, { resources: 'doc' });
      assert.equal(res.status, 400);
      assert.deepEqual(res.body, { error: 'invalid-body' });

      const followUp = await jsonRequest({ port: booted.port, method: 'GET', path: '/healthz' });
      assert.equal(followUp.status, 200, 'server must keep serving after a structured rejection');

      const retry = await submitAgentRequest(booted);
      assert.equal(retry.status, 201, 'a clean retry must succeed after the malformed body');
    } finally {
      booted.api.stop();
    }
  });
});
