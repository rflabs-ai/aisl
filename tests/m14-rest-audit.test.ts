/**
 * M14 Phase 2C acceptance tests: REST audit-query + task-execution routes
 * (ADR-019). Audit routes through AuditQueryService UNCHANGED — tenant
 * pass-through parity (a client-supplied tenantId reaches the service, which
 * denies cross-tenant AND appends the deny event); tasks route through the ONE
 * existing AgentSession.run() path; fail-closed mapping for throwing runTask.
 */

import { request as httpRequest } from 'node:http';
import { test, describe } from 'node:test';
import assert from 'node:assert/strict';
import { RestApi, type RestApiDeps } from '../src/rest-api.ts';
import { registerAuditRoutes, type TaskRunner } from '../src/rest-audit.ts';
import { AgentSession, LocalSandbox } from '../src/runtime.ts';
import { ContainerSandbox } from '../src/container-sandbox.ts';
import { TENANT_A, TENANT_B, summarizeRepoModel, type World } from '../src/scenario.ts';
import { createMockIdP, testWorld, type MockIdP } from '../src/testing.ts';
import { secretLeakCheck } from '../src/verification.ts';
import type { IdentityProvider } from '../src/identity.ts';

interface Booted {
  readonly api: RestApi;
  readonly world: World;
  readonly mockIdp: MockIdP;
  readonly port: number;
}

interface RawResponse {
  readonly status: number;
  readonly body: string;
}

function makeRunTask(world: World): TaskRunner {
  return async (principal, task) => {
    const session = new AgentSession({
      principal,
      agentId: principal.id,
      model: summarizeRepoModel(),
      task,
      registry: world.registry,
      authorization: world.authorization,
      eventLog: world.eventLog,
      tools: world.tools,
      sandbox: new ContainerSandbox(new LocalSandbox()),
      content: world.content,
      checks: [secretLeakCheck(world.secretValues)],
      canaries: world.secretValues,
      now: world.clock.now,
    });
    return session.run([]);
  };
}

async function boot(options: { withRunTask?: boolean } = {}): Promise<Booted> {
  const world = testWorld();
  const mockIdp = await createMockIdP();
  const idp = await mockIdp.createIdP();
  const resolvePrincipal: RestApiDeps['resolvePrincipal'] = (auth) => {
    if (auth.subject === world.user.id) return world.user;
    if (auth.subject === world.agent.id) return world.agent;
    return undefined;
  };
  world.authorization.issue(world.root, {
    subject: world.user.id,
    tenantId: TENANT_A,
    resourceIds: ['audit-log:acme'],
    actions: ['query.audit'],
    maxClassification: 'internal',
    expiresAt: Date.now() + 3_600_000,
    provenance: { source: 'policy-grant' },
  });
  const api = new RestApi({
    authorization: world.authorization,
    idp,
    eventLog: world.eventLog,
    resolvePrincipal,
  });
  registerAuditRoutes(api, {
    audit: world.audit,
    ...(options.withRunTask ? { runTask: makeRunTask(world) } : {}),
  });
  const port = await api.start();
  return { api, world, mockIdp, port };
}

function aliceToken(booted: Booted): Promise<string> {
  return booted.mockIdp.signJWT({ sub: 'user:alice', amr: ['pwd', 'mfa'] });
}

function agentToken(booted: Booted): Promise<string> {
  return booted.mockIdp.signJWT({ sub: 'agent:summarizer-1', amr: ['pwd', 'mfa'] });
}

function rawRequest(options: {
  port: number;
  method: string;
  path: string;
  token?: string;
  body?: string;
}): Promise<RawResponse> {
  return new Promise((resolve, reject) => {
    const req = httpRequest(
      {
        host: '127.0.0.1',
        port: options.port,
        method: options.method,
        path: options.path,
        headers: {
          ...(options.token !== undefined ? { authorization: `Bearer ${options.token}` } : {}),
          ...(options.body !== undefined ? { 'content-type': 'application/json' } : {}),
        },
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

describe('m14 rest-audit: GET /v1/audit', () => {
  test('allow → 200 { events } with eventHash + signature intact', async () => {
    const booted = await boot();
    try {
      const res = await rawRequest({ port: booted.port, method: 'GET', path: '/v1/audit', token: await aliceToken(booted) });
      assert.equal(res.status, 200);
      const body = JSON.parse(res.body) as { events: { eventHash: string; signature?: string }[] };
      assert.ok(body.events.length >= 1);
      assert.match(body.events[0]!.eventHash, /^[0-9a-f]{64}$/);
      assert.equal(typeof body.events[0]!.signature, 'string');
    } finally {
      booted.api.stop();
    }
  });

  test('cross-tenant query → 403 tenant-mismatch AND deny event appended (in-process parity)', async () => {
    const booted = await boot();
    try {
      const res = await rawRequest({
        port: booted.port,
        method: 'GET',
        path: '/v1/audit?tenantId=globex',
        token: await aliceToken(booted),
      });
      assert.equal(res.status, 403);
      const body = JSON.parse(res.body) as { denyReason: string };
      assert.equal(body.denyReason, 'tenant-mismatch');

      const denyEvent = booted.world.eventLog
        .all()
        .filter((event) => event.action === 'query.audit' && event.denyReason === 'tenant-mismatch')
        .at(-1);
      assert.ok(denyEvent, 'service must append the tenant-mismatch deny event');
    } finally {
      booted.api.stop();
    }
  });

  test('no tenant param → filters.tenantId defaults to principal tenant', async () => {
    const booted = await boot();
    try {
      const res = await rawRequest({ port: booted.port, method: 'GET', path: '/v1/audit', token: await aliceToken(booted) });
      assert.equal(res.status, 200);
      const body = JSON.parse(res.body) as { events: unknown[] };
      assert.ok(Array.isArray(body.events));
    } finally {
      booted.api.stop();
    }
  });

  test('bad filters → 400 invalid-filter; server keeps serving', async () => {
    const booted = await boot();
    try {
      const token = await aliceToken(booted);
      const cases: { path: string }[] = [
        { path: '/v1/audit?limit=0' },
        { path: '/v1/audit?limit=2000' },
        { path: '/v1/audit?offset=-1' },
        { path: `/v1/audit?fromTime=${Date.now() - 91 * 86_400_000}&toTime=${Date.now()}` },
      ];
      for (const c of cases) {
        const res = await rawRequest({ port: booted.port, method: 'GET', path: c.path, token });
        assert.equal(res.status, 400, c.path);
        assert.equal((JSON.parse(res.body) as { error: string }).error, 'invalid-filter', c.path);
      }
      const followUp = await rawRequest({ port: booted.port, method: 'GET', path: '/healthz' });
      assert.equal(followUp.status, 200);
    } finally {
      booted.api.stop();
    }
  });

  test('bad decision value → 400 invalid-query', async () => {
    const booted = await boot();
    try {
      const res = await rawRequest({
        port: booted.port,
        method: 'GET',
        path: '/v1/audit?decision=bananas',
        token: await aliceToken(booted),
      });
      assert.equal(res.status, 400);
      assert.equal((JSON.parse(res.body) as { error: string }).error, 'invalid-query');
    } finally {
      booted.api.stop();
    }
  });

  test('non-integer seq → 400 invalid-filter', async () => {
    const booted = await boot();
    try {
      const res = await rawRequest({
        port: booted.port,
        method: 'GET',
        path: '/v1/audit?fromSeq=abc',
        token: await aliceToken(booted),
      });
      assert.equal(res.status, 400);
      assert.equal((JSON.parse(res.body) as { error: string }).error, 'invalid-filter');
    } finally {
      booted.api.stop();
    }
  });

  test('agent without audit capability → 403 no-capability; error body carries no events field', async () => {
    const booted = await boot();
    try {
      const res = await rawRequest({ port: booted.port, method: 'GET', path: '/v1/audit', token: await agentToken(booted) });
      assert.equal(res.status, 403);
      const body = JSON.parse(res.body) as { denyReason: string; reason: string };
      assert.equal(body.denyReason, 'no-capability');
      assert.equal('events' in body, false);
    } finally {
      booted.api.stop();
    }
  });
});

describe('m14 rest-audit: POST /v1/tasks', () => {
  test('agent + runTask → 200 trace summary; no sealed/ciphertext/output in response', async () => {
    const booted = await boot({ withRunTask: true });
    try {
      const res = await rawRequest({
        port: booted.port,
        method: 'POST',
        path: '/v1/tasks',
        token: await agentToken(booted),
        body: JSON.stringify({ task: 'Summarize repository A and report findings.' }),
      });
      assert.equal(res.status, 200);
      const body = JSON.parse(res.body) as {
        sessionId: string;
        principal: string;
        agentId: string;
        modelId: string;
        modelText: string;
        steps: { action: string; resourceId: string; decision: string; executed: boolean }[];
      };
      assert.equal(typeof body.sessionId, 'string');
      assert.equal(body.principal, 'agent:summarizer-1');
      assert.equal(body.agentId, 'agent:summarizer-1');
      assert.equal(body.modelId, 'scripted-summarizer-v1');
      assert.equal(typeof body.modelText, 'string');
      assert.equal(body.steps.length, 1);
      assert.equal(body.steps[0]!.decision, 'allow');
      assert.equal(body.steps[0]!.resourceId, 'repo:acme/repo-a');
      assert.equal(body.steps[0]!.executed, true);
      assert.ok(!res.body.includes('sealed'));
      assert.ok(!res.body.includes('ciphertext'));
      assert.ok(!('output' in (body.steps[0] as object)));

      const startEvent = booted.world.eventLog.all().filter((event) => event.action === 'session.start').at(-1);
      assert.ok(startEvent, 'in-process parity: session.start event must be appended');
    } finally {
      booted.api.stop();
    }
  });

  test('user without capabilities → 200 with deny step (PDP decides; honest denial)', async () => {
    const booted = await boot({ withRunTask: true });
    try {
      const res = await rawRequest({
        port: booted.port,
        method: 'POST',
        path: '/v1/tasks',
        token: await aliceToken(booted),
        body: JSON.stringify({ task: 'Summarize repository A and report findings.' }),
      });
      assert.equal(res.status, 200);
      const body = JSON.parse(res.body) as { principal: string; steps: { decision: string; executed: boolean }[] };
      assert.equal(body.principal, 'user:alice');
      assert.equal(body.steps.length, 1);
      assert.equal(body.steps[0]!.decision, 'deny');
      assert.equal(body.steps[0]!.executed, false);
    } finally {
      booted.api.stop();
    }
  });

  test('unconfigured runTask → 503 tasks-unconfigured', async () => {
    const booted = await boot();
    try {
      const res = await rawRequest({
        port: booted.port,
        method: 'POST',
        path: '/v1/tasks',
        token: await agentToken(booted),
        body: JSON.stringify({ task: 'anything' }),
      });
      assert.equal(res.status, 503);
      assert.equal((JSON.parse(res.body) as { error: string }).error, 'tasks-unconfigured');
    } finally {
      booted.api.stop();
    }
  });

  test('body whitelist: extra tenantId/approvals fields are dropped', async () => {
    const booted = await boot({ withRunTask: true });
    try {
      const res = await rawRequest({
        port: booted.port,
        method: 'POST',
        path: '/v1/tasks',
        token: await agentToken(booted),
        body: JSON.stringify({ task: 'Summarize repository A and report findings.', tenantId: TENANT_B, approvals: [] }),
      });
      assert.equal(res.status, 200);
      const body = JSON.parse(res.body) as { principal: string };
      assert.equal(body.principal, 'agent:summarizer-1');

      const globexEvents = booted.world.eventLog.all().filter((event) => event.tenantId === TENANT_B);
      assert.deepEqual(globexEvents, [], 'no globex events may be appended from a smuggled tenant field');
    } finally {
      booted.api.stop();
    }
  });

  test('throwing runTask → 500 internal-error AND evaluation-error deny event', async () => {
    const world = testWorld();
    const mockIdp = await createMockIdP();
    const idp = await mockIdp.createIdP();
    const api = new RestApi({
      authorization: world.authorization,
      idp,
      eventLog: world.eventLog,
      resolvePrincipal: (auth) => (auth.subject === world.agent.id ? world.agent : undefined),
    });
    registerAuditRoutes(api, {
      audit: world.audit,
      runTask: async () => {
        throw new Error('task executor exploded');
      },
    });
    const port = await api.start();
    try {
      const token = await mockIdp.signJWT({ sub: 'agent:summarizer-1' });
      const res = await rawRequest({
        port,
        method: 'POST',
        path: '/v1/tasks',
        token,
        body: JSON.stringify({ task: 'boom' }),
      });
      assert.equal(res.status, 500);
      assert.equal((JSON.parse(res.body) as { error: string }).error, 'internal-error');
      assert.ok(!res.body.includes('task executor exploded'), 'raw error text must never reach the response');

      const deny = world.eventLog
        .all()
        .filter((event) => (event.metadata as { phase?: string } | undefined)?.phase === 'rest-api')
        .at(-1);
      assert.ok(deny, 'deny event must be appended');
      assert.equal(deny.denyReason, 'evaluation-error');
      assert.equal(deny.action, 'rest.request');
    } finally {
      api.stop();
    }
  });
});
