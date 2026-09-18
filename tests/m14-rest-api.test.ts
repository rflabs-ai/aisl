/**
 * M14 acceptance suite for the REST API surface (ADR-019): whitelist router,
 * JWT-bearer authn, body pipeline, fail-closed mapping, health, and the
 * structural invariant that headers cannot mint a principal.
 */

import { request as httpRequest } from 'node:http';
import { test, describe } from 'node:test';
import assert from 'node:assert/strict';
import { RestApi, str, strArray, optStr, RestRejection, type RestApiDeps } from '../src/rest-api.ts';
import { AuthorizationService } from '../src/pdp.ts';
import { TENANT_A, type World } from '../src/scenario.ts';
import { createMockIdP, testWorld, type MockIdP } from '../src/testing.ts';
import type { IdentityProvider } from '../src/identity.ts';

interface Booted {
  readonly api: RestApi;
  readonly world: World;
  readonly idp: IdentityProvider;
  readonly mockIdp: MockIdP;
  readonly port: number;
}

interface RawResponse {
  readonly status: number;
  readonly body: string;
}

interface ClosedResult {
  readonly gotResponse: boolean;
  readonly errorCode?: string;
}

async function boot(options: { storeHealth?: () => 'ok' | 'unavailable'; maxBodyBytes?: number } = {}): Promise<Booted> {
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
    resourceIds: ['repo:acme/repo-a'],
    actions: ['task.approve'],
    maxClassification: 'internal',
    expiresAt: Date.now() + 3_600_000,
    provenance: { source: 'session-bootstrap', taskId: 'task:rest-test' },
  });
  const api = new RestApi({
    authorization: world.authorization,
    idp,
    eventLog: world.eventLog,
    resolvePrincipal,
    ...(options.storeHealth !== undefined ? { storeHealth: options.storeHealth } : {}),
    ...(options.maxBodyBytes !== undefined ? { maxBodyBytes: options.maxBodyBytes } : {}),
  });
  const port = await api.start();
  return { api, world, idp, mockIdp, port };
}

function userToken(booted: Booted): Promise<string> {
  return booted.mockIdp.signJWT({ sub: 'user:alice' });
}

function agentToken(booted: Booted): Promise<string> {
  return booted.mockIdp.signJWT({ sub: 'agent:summarizer-1', amr: ['pwd', 'mfa'] });
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

function expectConnectionClosed(options: {
  port: number;
  method: string;
  path: string;
  headers?: Record<string, string>;
}): Promise<ClosedResult> {
  return new Promise((resolve) => {
    let settled = false;
    const finish = (result: ClosedResult) => {
      if (settled) return;
      settled = true;
      resolve(result);
    };
    const req = httpRequest(
      {
        host: '127.0.0.1',
        port: options.port,
        method: options.method,
        path: options.path,
        headers: options.headers,
      },
      (res) => {
        res.resume();
        res.on('end', () => finish({ gotResponse: true }));
      },
    );
    req.on('error', (error: NodeJS.ErrnoException) => finish({ gotResponse: false, errorCode: error.code ?? error.message }));
    req.end();
  });
}

async function postAuthorize(booted: Booted, token: string, rawBody: string): Promise<RawResponse> {
  return rawRequest({
    port: booted.port,
    method: 'POST',
    path: '/v1/authorize',
    headers: { authorization: `Bearer ${token}`, 'content-type': 'application/json' },
    body: rawBody,
  });
}

const AGENT_READ_ALLOW_BODY = JSON.stringify({ action: 'read', resourceId: 'repo:acme/repo-a' });
const USER_APPROVE_ALLOW_BODY = JSON.stringify({ action: 'task.approve', resourceId: 'repo:acme/repo-a' });

describe('rest api: authn matrix', () => {
  test('missing token → 401 unauthenticated-principal', async () => {
    const booted = await boot();
    try {
      const res = await rawRequest({ port: booted.port, method: 'POST', path: '/v1/authorize', body: '{}' });
      assert.equal(res.status, 401);
      assert.equal(JSON.parse(res.body).denyReason, 'unauthenticated-principal');
    } finally {
      booted.api.stop();
    }
  });

  test('malformed authorization header (not Bearer) → 401', async () => {
    const booted = await boot();
    try {
      const res = await rawRequest({
        port: booted.port,
        method: 'POST',
        path: '/v1/authorize',
        headers: { authorization: 'Basic dXNlcjpwYXNz' },
        body: '{}',
      });
      assert.equal(res.status, 401);
      assert.equal(JSON.parse(res.body).denyReason, 'unauthenticated-principal');
    } finally {
      booted.api.stop();
    }
  });

  test('garbage token → 403 unauthenticated-principal', async () => {
    const booted = await boot();
    try {
      const res = await rawRequest({
        port: booted.port,
        method: 'POST',
        path: '/v1/authorize',
        headers: { authorization: 'Bearer garbage-token-not-a-jwt' },
        body: '{}',
      });
      assert.equal(res.status, 403);
      assert.equal(JSON.parse(res.body).denyReason, 'unauthenticated-principal');
    } finally {
      booted.api.stop();
    }
  });

  test('expired token → 403 unauthenticated-principal', async () => {
    const booted = await boot();
    try {
      const token = await booted.mockIdp.signJWT({ sub: 'user:alice', exp: Date.now() - 60_000 });
      const res = await postAuthorize(booted, token, '{}');
      assert.equal(res.status, 403);
      assert.equal(JSON.parse(res.body).denyReason, 'unauthenticated-principal');
    } finally {
      booted.api.stop();
    }
  });

  test('revoked token → 403 unauthenticated-principal', async () => {
    const booted = await boot();
    try {
      const token = await booted.mockIdp.signJWT({ sub: 'user:alice', jti: 'revoked-jti-1' });
      booted.idp.revokeToken('revoked-jti-1');
      const res = await postAuthorize(booted, token, '{}');
      assert.equal(res.status, 403);
      assert.equal(JSON.parse(res.body).denyReason, 'unauthenticated-principal');
    } finally {
      booted.api.stop();
    }
  });

  test('valid user token → 200; valid agent token → 200', async () => {
    const booted = await boot();
    try {
      const user = await postAuthorize(booted, await userToken(booted), USER_APPROVE_ALLOW_BODY);
      assert.equal(user.status, 200);
      assert.equal(JSON.parse(user.body).decision, 'allow');

      const agent = await postAuthorize(booted, await agentToken(booted), AGENT_READ_ALLOW_BODY);
      assert.equal(agent.status, 200);
      assert.equal(JSON.parse(agent.body).decision, 'allow');
    } finally {
      booted.api.stop();
    }
  });

  test('identity headers cannot mint a principal (structural invariant)', async () => {
    const booted = await boot();
    try {
      const res = await rawRequest({
        port: booted.port,
        method: 'POST',
        path: '/v1/authorize',
        headers: { 'x-principal-id': 'user:alice', 'x-tenant-id': 'globex' },
        body: '{}',
      });
      assert.equal(res.status, 401);
      assert.equal(JSON.parse(res.body).denyReason, 'unauthenticated-principal');
      const minted = booted.world.eventLog.all().filter((event) => event.principal === 'user:alice');
      assert.deepEqual(minted, [], 'no event may ever carry a header-supplied principal');
    } finally {
      booted.api.stop();
    }
  });
});

describe('rest api: /v1/authorize route', () => {
  test('deny → 403 with structured denyReason (tenant-mismatch, unknown-resource)', async () => {
    const booted = await boot();
    try {
      const token = await agentToken(booted);
      const crossTenant = await postAuthorize(
        booted,
        token,
        JSON.stringify({ action: 'read', resourceId: 'doc:globex-strategy' }),
      );
      assert.equal(crossTenant.status, 403);
      assert.equal(JSON.parse(crossTenant.body).denyReason, 'tenant-mismatch');

      const unknown = await postAuthorize(
        booted,
        token,
        JSON.stringify({ action: 'read', resourceId: 'doc:does-not-exist' }),
      );
      assert.equal(unknown.status, 403);
      assert.equal(JSON.parse(unknown.body).denyReason, 'unknown-resource');
    } finally {
      booted.api.stop();
    }
  });

  test('allow → 200 { decision, reason } for agent reading bootstrap repo', async () => {
    const booted = await boot();
    try {
      const res = await postAuthorize(booted, await agentToken(booted), AGENT_READ_ALLOW_BODY);
      assert.equal(res.status, 200);
      const body = JSON.parse(res.body) as { decision: string; reason: string };
      assert.equal(body.decision, 'allow');
      assert.equal(typeof body.reason, 'string');
      assert.ok(body.reason.length > 0);
    } finally {
      booted.api.stop();
    }
  });

  test('body whitelist drops smuggled fields (tenantId never reaches the event)', async () => {
    const booted = await boot();
    try {
      const before = booted.world.eventLog.all().length;
      const res = await postAuthorize(
        booted,
        await agentToken(booted),
        JSON.stringify({ action: 'read', resourceId: 'repo:acme/repo-a', smuggled: 'injection', tenantId: 'globex', params: {} }),
      );
      assert.equal(res.status, 200);
      assert.equal(JSON.parse(res.body).decision, 'allow');

      const decision = booted.world.eventLog
        .all()
        .slice(before)
        .filter((event) => event.decision === 'allow' && event.resourceId === 'repo:acme/repo-a')
        .at(-1);
      assert.ok(decision, 'PDP decision event must exist');
      const metadataJson = JSON.stringify(decision.metadata);
      assert.ok(!metadataJson.includes('globex'), 'smuggled tenant must not surface in event metadata');
      assert.ok(!metadataJson.includes('smuggled'), 'smuggled field must not surface in event metadata');
    } finally {
      booted.api.stop();
    }
  });

  test('wrong-typed field → 400 structured; server keeps serving', async () => {
    const booted = await boot();
    try {
      const res = await postAuthorize(booted, await agentToken(booted), JSON.stringify({ action: 42, resourceId: 'repo:acme/repo-a' }));
      assert.equal(res.status, 400);
      assert.equal(JSON.parse(res.body).error, 'invalid-body');

      const followUp = await rawRequest({ port: booted.port, method: 'GET', path: '/healthz' });
      assert.equal(followUp.status, 200);
    } finally {
      booted.api.stop();
    }
  });

  test('params whitelist is prototype-pollution safe', async () => {
    const booted = await boot();
    try {
      const rawBody =
        '{"action":"read","resourceId":"repo:acme/repo-a","params":{"__proto__":{"admin":true}}}';
      const res = await postAuthorize(booted, await agentToken(booted), rawBody);
      assert.equal(res.status, 200, 'request must complete with the hostile params key dropped');

      const objectProto = Object.prototype as Record<string, unknown>;
      assert.equal(objectProto.admin, undefined, 'Object.prototype must stay clean');
      assert.deepEqual(Object.keys(objectProto).filter((k) => k === 'admin' || k === '__proto__'), []);

      booted.api.addRoute('GET', '/v1/echo/:name', (ctx) => ({ status: 200, body: { keys: Object.keys(ctx.params) } }));
      const echo = await rawRequest({
        port: booted.port,
        method: 'GET',
        path: '/v1/echo/hello',
        headers: { authorization: `Bearer ${await agentToken(booted)}` },
      });
      assert.equal(echo.status, 200);
      assert.deepEqual(JSON.parse(echo.body), { keys: ['name'] }, 'route params copy only clean names');

      assert.throws(
        () => booted.api.addRoute('GET', '/v1/pollute/:__proto__', () => ({ status: 200, body: {} })),
        /not permitted/,
        'a hostile param name must be rejected at registration',
      );
    } finally {
      booted.api.stop();
    }
  });
});

describe('rest api: body handling', () => {
  test('oversized body → 413 body-too-large before parsing; server keeps serving', async () => {
    const booted = await boot({ maxBodyBytes: 1024 });
    try {
      const res = await rawRequest({
        port: booted.port,
        method: 'POST',
        path: '/v1/authorize',
        headers: { authorization: `Bearer ${await agentToken(booted)}`, 'content-type': 'application/json' },
        body: 'x'.repeat(2048),
      });
      assert.equal(res.status, 413);
      assert.equal(JSON.parse(res.body).error, 'body-too-large');

      const followUp = await postAuthorize(booted, await agentToken(booted), AGENT_READ_ALLOW_BODY);
      assert.equal(followUp.status, 200);
    } finally {
      booted.api.stop();
    }
  });

  test('garbage JSON → 400 invalid-json; server keeps serving', async () => {
    const booted = await boot();
    try {
      const res = await postAuthorize(booted, await agentToken(booted), 'this is not json{{{');
      assert.equal(res.status, 400);
      assert.equal(JSON.parse(res.body).error, 'invalid-json');

      const scalar = await postAuthorize(booted, await agentToken(booted), '"just a string"');
      assert.equal(scalar.status, 400);
      assert.equal(JSON.parse(scalar.body).error, 'invalid-json');

      const followUp = await postAuthorize(booted, await agentToken(booted), AGENT_READ_ALLOW_BODY);
      assert.equal(followUp.status, 200);
    } finally {
      booted.api.stop();
    }
  });
});

describe('rest api: fail-closed', () => {
  test('throwing PDP → 500 internal-error AND evaluation-error deny event', async () => {
    const world = testWorld();
    const mockIdp = await createMockIdP();
    const idp = await mockIdp.createIdP();
    const failingAuth = {
      authorize: () => {
        throw new Error('pdp exploded with internal details');
      },
    } as unknown as AuthorizationService;
    const api = new RestApi({
      authorization: failingAuth,
      idp,
      eventLog: world.eventLog,
      resolvePrincipal: (auth) => {
        if (auth.subject === world.agent.id) return world.agent;
        return undefined;
      },
    });
    const port = await api.start();
    try {
      const token = await mockIdp.signJWT({ sub: 'agent:summarizer-1' });
      const res = await rawRequest({
        port,
        method: 'POST',
        path: '/v1/authorize',
        headers: { authorization: `Bearer ${token}`, 'content-type': 'application/json' },
        body: AGENT_READ_ALLOW_BODY,
      });
      assert.equal(res.status, 500);
      assert.equal(JSON.parse(res.body).error, 'internal-error');
      assert.ok(!res.body.includes('pdp exploded'), 'raw error text must never reach the response');

      const deny = world.eventLog
        .all()
        .filter((event) => (event.metadata as { phase?: string } | undefined)?.phase === 'rest-api')
        .at(-1);
      assert.ok(deny, 'deny event must be appended');
      assert.equal(deny.denyReason, 'evaluation-error');
      assert.equal(deny.decision, 'deny');
      assert.equal(deny.action, 'rest.request');
      assert.equal(deny.principal, world.agent.id);
      assert.ok(!JSON.stringify(deny.metadata).includes('pdp exploded'), 'raw error text must never reach the event');
    } finally {
      api.stop();
    }
  });

  test('unhandled paths close the connection with NO response; server keeps serving', async () => {
    const booted = await boot();
    try {
      const unknownGet = await expectConnectionClosed({ port: booted.port, method: 'GET', path: '/nope' });
      assert.equal(unknownGet.gotResponse, false, 'GET /nope must get no response');
      assert.ok(unknownGet.errorCode !== undefined, 'client must observe a connection error');

      const unknownPost = await expectConnectionClosed({ port: booted.port, method: 'POST', path: '/v1/unknown' });
      assert.equal(unknownPost.gotResponse, false, 'POST /v1/unknown must get no response');
      assert.ok(unknownPost.errorCode !== undefined, 'client must observe a connection error');

      const followUp = await postAuthorize(booted, await agentToken(booted), AGENT_READ_ALLOW_BODY);
      assert.equal(followUp.status, 200);
      const health = await rawRequest({ port: booted.port, method: 'GET', path: '/healthz' });
      assert.equal(health.status, 200);
    } finally {
      booted.api.stop();
    }
  });
});

describe('rest api: health', () => {
  test('GET /healthz reports idp and store status without a token', async () => {
    const booted = await boot();
    try {
      const res = await rawRequest({ port: booted.port, method: 'GET', path: '/healthz' });
      assert.equal(res.status, 200);
      assert.deepEqual(JSON.parse(res.body), { idp: 'healthy', store: 'ok' });
    } finally {
      booted.api.stop();
    }
  });

  test('unavailable store surfaces on /healthz; body carries no token material', async () => {
    const booted = await boot({ storeHealth: () => 'unavailable' });
    try {
      const res = await rawRequest({ port: booted.port, method: 'GET', path: '/healthz' });
      assert.equal(res.status, 200);
      const body = JSON.parse(res.body) as Record<string, string>;
      assert.equal(body.store, 'unavailable');
      assert.equal(body.idp, 'healthy');
      assert.deepEqual(Object.keys(body).sort(), ['idp', 'store'], 'no secrets or internals in the health body');
    } finally {
      booted.api.stop();
    }
  });
});

describe('rest api: no-secrets invariant', () => {
  test('responses never contain the raw JWT', async () => {
    const booted = await boot();
    try {
      const token = await agentToken(booted);
      const res = await postAuthorize(booted, token, AGENT_READ_ALLOW_BODY);
      assert.equal(res.status, 200);
      assert.ok(!res.body.includes(token), 'allow response must not echo the token');

      const denied = await postAuthorize(
        booted,
        token,
        JSON.stringify({ action: 'read', resourceId: 'doc:globex-strategy' }),
      );
      assert.equal(denied.status, 403);
      assert.ok(!denied.body.includes(token), 'deny response must not echo the token');
    } finally {
      booted.api.stop();
    }
  });
});

describe('rest api: whitelist helpers', () => {
  test('str/strArray/optStr accept valid input and reject hostile input', () => {
    assert.equal(str('read', 'action'), 'read');
    assert.deepEqual(strArray(['a', 'b'], 'ids'), ['a', 'b']);
    assert.equal(optStr(undefined, 'note'), undefined);
    assert.equal(optStr('x', 'note'), 'x');

    assert.throws(() => str(42, 'action'), RestRejection);
    assert.throws(() => str('', 'action'), RestRejection);
    assert.throws(() => strArray('nope', 'ids'), RestRejection);
    assert.throws(() => strArray(['a', 42], 'ids'), RestRejection);
    assert.throws(() => optStr(42, 'note'), RestRejection);
    try {
      str(42, 'action');
    } catch (error) {
      assert.ok(error instanceof RestRejection);
      assert.equal(error.status, 400);
      assert.equal(error.code, 'invalid-body');
    }
  });
});
