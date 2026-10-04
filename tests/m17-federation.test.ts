/**
 * M17 federation acceptance (ADR-022): the two ASL-side REST routes the
 * control-plane client needs. `POST /v1/anchors` registers a foreign event-log
 * head-hash (the M3 anchor pattern across repos) and records it in ASL's own
 * evidence plane; `GET /v1/capability-requests/:id` lets a requester learn its
 * request's outcome (and the minted capability) instead of it vanishing from
 * the pending-only list.
 *
 * These close the two gaps ticketed during the control-plane implementation
 * (`.scratch/m17-federation/issues/04`, `05`). Invariants preserved here:
 * tenant comes from the verified principal (never the body), digests only in
 * events (no plaintext), and the mint remains exactly the M4 mint.
 */

import { request as httpRequest } from 'node:http';
import { randomUUID, type KeyObject } from 'node:crypto';
import { test, describe } from 'node:test';
import assert from 'node:assert/strict';
import { RestApi } from '../src/rest-api.ts';
import { SessionManager } from '../src/session-manager.ts';
import { CapabilityRequestService } from '../src/capability-request.ts';
import { registerSessionRoutes } from '../src/rest-sessions.ts';
import { registerAnchorRoutes, AnchorRegistry } from '../src/rest-anchors.ts';
import { TENANT_A, TENANT_B, type World } from '../src/scenario.ts';
import { createMockIdP, testWorld, type MockIdP } from '../src/testing.ts';
import type { AuthContext, Principal } from '../src/domain.ts';
import type { AuditExport, AuditFilters, ChainVerification, EventInput, EventStore, SecurityEvent } from '../src/events.ts';

const HASH_A = 'a'.repeat(64);
const HASH_B = 'b'.repeat(64);
const HASH_C = 'c'.repeat(64);
const HASH_D = 'd'.repeat(64);

interface Booted {
  readonly api: RestApi;
  readonly world: World;
  readonly mockIdp: MockIdP;
  readonly port: number;
  readonly requests: CapabilityRequestService;
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
  const bob: Principal = { id: 'user:bob', kind: 'user', tenantId: TENANT_B, roles: [], attributes: {} };
  const registry: Record<string, Principal> = {
    'user:alice': world.user,
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
  registerAnchorRoutes(api, { eventLog: world.eventLog });
  const port = await api.start();
  return { api, world, mockIdp, port, requests };
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
  const raw = await new Promise<{ status: number; body: string }>((resolve, reject) => {
    const req = httpRequest(
      {
        host: '127.0.0.1',
        port: options.port,
        method: options.method,
        path: options.path,
        headers,
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
    if (options.body !== undefined) req.write(JSON.stringify(options.body));
    req.end();
  });
  const parsed = raw.body.length > 0 ? (JSON.parse(raw.body) as Record<string, unknown>) : {};
  return { status: raw.status, text: raw.body, body: parsed };
}

function token(booted: Booted, sub: string, amr: readonly string[] = ['pwd', 'mfa']): Promise<string> {
  return booted.mockIdp.signJWT({ sub, amr });
}

function anchorBody(overrides: Record<string, unknown> = {}): Record<string, unknown> {
  return {
    tenant: TENANT_A,
    headHash: HASH_A,
    eventCount: 12,
    anchoredAt: 1_700_000_000_000,
    ...overrides,
  };
}

function anchorEvents(booted: Booted) {
  return booted.world.eventLog.all().filter((event) => event.action === 'anchor.register');
}

describe('M17 POST /v1/anchors', () => {
  test('authorized client registers a head-hash → 201 id/acceptedAt + anchor.register event', async () => {
    const booted = await boot();
    try {
      const res = await jsonRequest({
        port: booted.port,
        method: 'POST',
        path: '/v1/anchors',
        token: await token(booted, 'agent:summarizer-1'),
        body: anchorBody(),
      });
      assert.equal(res.status, 201);
      assert.equal(typeof res.body.id, 'string');
      assert.equal(typeof res.body.acceptedAt, 'number');
      assert.equal(res.body.tamper, undefined, 'a first anchor has no predecessor to mismatch');
      const event = anchorEvents(booted).at(-1);
      assert.ok(event, 'anchor.register event must be recorded in ASL evidence');
      assert.equal(event.tenantId, TENANT_A);
      assert.equal(event.metadata?.headHash, HASH_A);
      assert.equal(event.metadata?.eventCount, 12);
      assert.ok(!res.text.includes('"signature"'), 'no capability/attestation internals reach the wire');
    } finally {
      booted.api.stop();
    }
  });

  test('chained anchor with the accepted previous head → 201, no tamper', async () => {
    const booted = await boot();
    try {
      const first = await jsonRequest({
        port: booted.port,
        method: 'POST',
        path: '/v1/anchors',
        token: await token(booted, 'agent:summarizer-1'),
        body: anchorBody({ headHash: HASH_A }),
      });
      assert.equal(first.status, 201);
      const second = await jsonRequest({
        port: booted.port,
        method: 'POST',
        path: '/v1/anchors',
        token: await token(booted, 'agent:summarizer-1'),
        body: anchorBody({ headHash: HASH_B, previousHeadHash: HASH_A, eventCount: 20 }),
      });
      assert.equal(second.status, 201);
      assert.equal(second.body.tamper, undefined);
    } finally {
      booted.api.stop();
    }
  });

  test('tamper: previous head mismatch → 201 tamper:true + recorded in the event metadata', async () => {
    const booted = await boot();
    try {
      await jsonRequest({
        port: booted.port,
        method: 'POST',
        path: '/v1/anchors',
        token: await token(booted, 'agent:summarizer-1'),
        body: anchorBody({ headHash: HASH_A }),
      });
      const res = await jsonRequest({
        port: booted.port,
        method: 'POST',
        path: '/v1/anchors',
        token: await token(booted, 'agent:summarizer-1'),
        body: anchorBody({ headHash: HASH_B, previousHeadHash: 'c'.repeat(64), eventCount: 20 }),
      });
      assert.equal(res.status, 201);
      assert.equal(res.body.tamper, true);
      const event = anchorEvents(booted).at(-1);
      assert.equal(event?.metadata?.tamper, true);
      assert.equal(event?.metadata?.expectedHeadHash, HASH_A);
    } finally {
      booted.api.stop();
    }
  });

  test('body tenant must match the verified principal → 403 tenant-mismatch', async () => {
    const booted = await boot();
    try {
      const res = await jsonRequest({
        port: booted.port,
        method: 'POST',
        path: '/v1/anchors',
        token: await token(booted, 'agent:summarizer-1'),
        body: anchorBody({ tenant: 'globex' }),
      });
      assert.equal(res.status, 403);
      assert.deepEqual(res.body, { error: 'tenant-mismatch' });
      assert.equal(anchorEvents(booted).length, 0, 'a refused anchor must record no evidence');
    } finally {
      booted.api.stop();
    }
  });

  test('non-sha256 head-hash → 400 invalid-body', async () => {
    const booted = await boot();
    try {
      const res = await jsonRequest({
        port: booted.port,
        method: 'POST',
        path: '/v1/anchors',
        token: await token(booted, 'agent:summarizer-1'),
        body: anchorBody({ headHash: 'not-a-hash' }),
      });
      assert.equal(res.status, 400);
      assert.deepEqual(res.body, { error: 'invalid-body' });
    } finally {
      booted.api.stop();
    }
  });

  test('unauthenticated anchor → 401 unauthenticated-principal', async () => {
    const booted = await boot();
    try {
      const res = await jsonRequest({ port: booted.port, method: 'POST', path: '/v1/anchors', body: anchorBody() });
      assert.equal(res.status, 401);
    } finally {
      booted.api.stop();
    }
  });
});

/** EventStore stub that throws on append when `failOnAppend` is set (session-audit ticket 01). */
class ThrowingEventLog implements EventStore {
  failOnAppend = false;
  append(input: EventInput): SecurityEvent {
    if (this.failOnAppend) throw new Error('synthetic append failure');
    return {
      ...input,
      seq: 0,
      timestamp: input.timestamp ?? Date.now(),
      previousEventHash: '0'.repeat(64),
      eventHash: HASH_A,
    };
  }
  all(): readonly SecurityEvent[] {
    return [];
  }
  forTenant(): readonly SecurityEvent[] {
    return [];
  }
  query(_filters: AuditFilters): readonly SecurityEvent[] {
    return [];
  }
  exportFor(_filters: AuditFilters): AuditExport {
    return { tenantId: '', generatedAt: 0, fromSeq: 0, toSeq: 0, events: [], head: '', previousHead: null };
  }
  verify(_options?: { publicKey?: KeyObject }): ChainVerification {
    return { valid: true, count: 0 };
  }
  bundle(): string {
    return '';
  }
  anchor(): string {
    return '';
  }
  async flushAnchors(): Promise<void> {}
  close(): void {}
}

describe('AnchorRegistry: a throwing event append must not poison the registry', () => {
  test('session-audit ticket 01: registry head advances only on successful append', () => {
    const store = new ThrowingEventLog();
    const registry = new AnchorRegistry(store);
    const principal: Principal = { id: 'agent:cp', kind: 'agent', tenantId: TENANT_A, roles: [], attributes: {} };

    assert.equal(registry.record(principal, { tenant: TENANT_A, headHash: HASH_A, eventCount: 5, anchoredAt: 1 }).tamper, false);
    assert.equal(
      registry.record(principal, { tenant: TENANT_A, headHash: HASH_B, previousHeadHash: HASH_A, eventCount: 10, anchoredAt: 2 }).tamper,
      false,
    );

    // Third anchor: the EventLog throws. The registry must NOT advance to HASH_C.
    store.failOnAppend = true;
    assert.throws(
      () => registry.record(principal, { tenant: TENANT_A, headHash: HASH_C, previousHeadHash: HASH_B, eventCount: 15, anchoredAt: 3 }),
      /synthetic append failure/,
    );
    store.failOnAppend = false;

    // Fourth anchor honestly chains to HASH_B — the head the evidence plane actually
    // accepted. It must NOT be flagged tamper (pre-fix: registry said HASH_C).
    const fourth = registry.record(principal, {
      tenant: TENANT_A,
      headHash: HASH_D,
      previousHeadHash: HASH_B,
      eventCount: 20,
      anchoredAt: 4,
    });
    assert.equal(fourth.tamper, false, 'a failed append must leave the last accepted head unchanged');
  });
});

describe('M17 GET /v1/capability-requests/:id', () => {
  async function submitAgentRequest(booted: Booted, overrides: Record<string, unknown> = {}): Promise<JsonResponse> {
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

  test('pending request → 200 with status pending and no capability', async () => {
    const booted = await boot();
    try {
      const submitted = await submitAgentRequest(booted);
      const id = String(submitted.body.id);
      const res = await jsonRequest({
        port: booted.port,
        method: 'GET',
        path: `/v1/capability-requests/${id}`,
        token: await token(booted, 'user:alice'),
      });
      assert.equal(res.status, 200);
      const request = res.body.request as Record<string, unknown>;
      assert.equal(request.id, id);
      assert.equal(request.status, 'pending');
      assert.equal(res.body.capability, undefined, 'a pending request has minted no capability');
    } finally {
      booted.api.stop();
    }
  });

  test('approved request → 200 with the minted capability; scope equals the approved scope', async () => {
    const booted = await boot();
    try {
      const submitted = await submitAgentRequest(booted);
      const id = String(submitted.body.id);
      const approved = await jsonRequest({
        port: booted.port,
        method: 'POST',
        path: `/v1/capability-requests/${id}/approvals`,
        token: await token(booted, 'user:alice'),
        body: { scope: { resources: ['doc:acme-onboarding'] } },
      });
      assert.equal(approved.status, 201);
      const res = await jsonRequest({
        port: booted.port,
        method: 'GET',
        path: `/v1/capability-requests/${id}`,
        token: await token(booted, 'agent:summarizer-1'),
      });
      assert.equal(res.status, 200);
      const request = res.body.request as Record<string, unknown>;
      const capability = res.body.capability as Record<string, unknown>;
      assert.equal(request.status, 'approved');
      assert.equal(request.capabilityId, capability.id);
      assert.deepEqual(capability.resourceIds, ['doc:acme-onboarding']);
      assert.equal(capability.singleUse, true);
      assert.ok(!res.text.includes('"signature"'), 'capability signature must never reach the wire');
    } finally {
      booted.api.stop();
    }
  });

  test('denied request → 200 status denied, no capability', async () => {
    const booted = await boot();
    try {
      const submitted = await submitAgentRequest(booted);
      const id = String(submitted.body.id);
      booted.requests.deny(id, booted.world.user);
      const res = await jsonRequest({
        port: booted.port,
        method: 'GET',
        path: `/v1/capability-requests/${id}`,
        token: await token(booted, 'agent:summarizer-1'),
      });
      assert.equal(res.status, 200);
      assert.equal((res.body.request as Record<string, unknown>).status, 'denied');
      assert.equal(res.body.capability, undefined);
    } finally {
      booted.api.stop();
    }
  });

  test('unknown id → 404 not-found', async () => {
    const booted = await boot();
    try {
      const res = await jsonRequest({
        port: booted.port,
        method: 'GET',
        path: `/v1/capability-requests/${randomUUID()}`,
        token: await token(booted, 'user:alice'),
      });
      assert.equal(res.status, 404);
      assert.deepEqual(res.body, { error: 'not-found' });
    } finally {
      booted.api.stop();
    }
  });

  test('cross-tenant read → 403 tenant-mismatch', async () => {
    const booted = await boot();
    try {
      const submitted = await submitAgentRequest(booted);
      const id = String(submitted.body.id);
      const res = await jsonRequest({
        port: booted.port,
        method: 'GET',
        path: `/v1/capability-requests/${id}`,
        token: await token(booted, 'user:bob'),
      });
      assert.equal(res.status, 403);
      assert.deepEqual(res.body, { error: 'tenant-mismatch' });
      assert.ok(!res.text.includes(id), 'a foreign request id must not be echoed');
    } finally {
      booted.api.stop();
    }
  });

  test('unauthenticated status read → 401', async () => {
    const booted = await boot();
    try {
      const submitted = await submitAgentRequest(booted);
      const res = await jsonRequest({
        port: booted.port,
        method: 'GET',
        path: `/v1/capability-requests/${String(submitted.body.id)}`,
      });
      assert.equal(res.status, 401);
    } finally {
      booted.api.stop();
    }
  });
});
