/**
 * M15 acceptance: minimal UI (ADR-020) — one static page served by the M14
 * server, a client of POST /v1/tasks and GET /v1/audit. No new authorization
 * surface; no canary/secret/absolute URL in any served page (secret-scan);
 * accessibility basics (semantic HTML, labeled inputs, keyboard-reachable
 * buttons — no div/onclick patterns).
 */

import { request as httpRequest } from 'node:http';
import { test, describe } from 'node:test';
import assert from 'node:assert/strict';
import { createRestApi, staticPageFromFile, type RestApiDeps } from '../src/rest-api.ts';
import { AuthorizationService } from '../src/pdp.ts';
import { TENANT_A, type World } from '../src/scenario.ts';
import { createMockIdP, testWorld, type MockIdP } from '../src/testing.ts';
import type { IdentityProvider } from '../src/identity.ts';
import { SessionManager } from '../src/session-manager.ts';
import { CapabilityRequestService } from '../src/capability-request.ts';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';

const ROOT = join(dirname(fileURLToPath(import.meta.url)), '..');
const PAGE_PATH = join(ROOT, 'tools', 'ui', 'index.html');

interface Booted {
  readonly api: ReturnType<typeof createRestApi>;
  readonly world: World;
  readonly mockIdp: MockIdP;
  readonly port: number;
}

async function boot(): Promise<Booted> {
  const world = testWorld();
  const mockIdp = await createMockIdP();
  const idp = await mockIdp.createIdP();
  const resolvePrincipal: RestApiDeps['resolvePrincipal'] = (auth) =>
    auth.subject === world.user.id || auth.subject === world.agent.id ? world.user : undefined;
  const page = staticPageFromFile('/ui', PAGE_PATH, 'text/html; charset=utf-8');
  const api = createRestApi({
    authorization: world.authorization,
    idp,
    eventLog: world.eventLog,
    resolvePrincipal,
    sessions: new SessionManager(),
    requests: new CapabilityRequestService(world.eventLog, world.authorization, world.root),
    audit: world.audit,
    staticPages: [page, { ...page, route: '/' }],
  });
  const port = await api.start();
  return { api, world, mockIdp, port };
}

function get(port: number, path: string): Promise<{ status: number; body: string; contentType: string | undefined }> {
  return new Promise((resolve, reject) => {
    httpRequest({ host: '127.0.0.1', port, path, method: 'GET' }, (res) => {
      let data = '';
      res.on('data', (chunk: Buffer) => (data += chunk.toString('utf8')));
      res.on('end', () => resolve({ status: res.statusCode ?? 0, body: data, contentType: res.headers['content-type'] }));
    }).on('error', reject).end();
  });
}

describe('minimal UI (ADR-020)', () => {
  test('the page is served at /ui and / as text/html', async () => {
    const booted = await boot();
    try {
      for (const path of ['/ui', '/']) {
        const res = await get(booted.port, path);
        assert.equal(res.status, 200);
        assert.match(res.contentType ?? '', /^text\/html/);
        assert.match(res.body, /<!doctype html>/);
      }
    } finally {
      booted.api.stop();
    }
  });

  test('secret scan: no canary, secret, credential, or absolute URL in any served page', async () => {
    const booted = await boot();
    try {
      const res = await get(booted.port, '/ui');
      for (const canary of [...booted.world.secretValues, 'CAPABILITY_SIGNING_KEY', 'SECRET_MASTER_KEY', 'postgres://', 'http://', 'https://']) {
        assert.equal(res.body.includes(canary), false, `served page must not contain '${canary}'`);
      }
    } finally {
      booted.api.stop();
    }
  });

  test('accessibility basics: labeled inputs, semantic landmarks, keyboard-native controls', async () => {
    const booted = await boot();
    try {
      const { body } = await get(booted.port, '/ui');
      assert.match(body, /<label for="token">/);
      assert.match(body, /<label for="task">/);
      assert.match(body, /<label for="limit">/);
      assert.match(body, /<main>/);
      assert.match(body, /<h1>/);
      assert.match(body, /aria-live="polite"/);
      // Every submit is a real <button type="submit"> — keyboard-native, no div/onclick.
      assert.equal((body.match(/<button type="submit">/g) ?? []).length, 2);
      assert.equal(body.includes('onclick'), false);
    } finally {
      booted.api.stop();
    }
  });

  test('the page is a client of /v1 — both routes it calls are authorized like any other client', async () => {
    const booted = await boot();
    try {
      // No token: both endpoints deny with the unauthenticated reason — the UI adds no bypass.
      const tasks = await new Promise<{ status: number; body: string }>((resolve, reject) => {
        httpRequest(
          { host: '127.0.0.1', port: booted.port, path: '/v1/tasks', method: 'POST', headers: { 'content-type': 'application/json' } },
          (res) => {
            let data = '';
            res.on('data', (chunk: Buffer) => (data += chunk.toString('utf8')));
            res.on('end', () => resolve({ status: res.statusCode ?? 0, body: data }));
          },
        ).on('error', reject).end('{}');
      });
      assert.equal(tasks.status, 401);
      const audit = await get(booted.port, '/v1/audit');
      assert.equal(audit.status, 401);
      assert.match(audit.body, /unauthenticated-principal/);

      // With a token, the audit view works through the ordinary PDP path.
      const token = await booted.mockIdp.signJWT({ sub: 'user:alice' });
      const world = booted.world;
      world.authorization.issue(world.root, {
        subject: world.user.id,
        tenantId: TENANT_A,
        resourceIds: ['audit-log:acme'],
        actions: ['query.audit'],
        maxClassification: 'restricted',
        expiresAt: Date.now() + 3_600_000,
        provenance: { source: 'session-bootstrap', taskId: 'task:m15-ui-test' },
      });
      const ok = await new Promise<{ status: number; body: string }>((resolve, reject) => {
        httpRequest(
          { host: '127.0.0.1', port: booted.port, path: '/v1/audit?limit=5', method: 'GET', headers: { authorization: `Bearer ${token}` } },
          (res) => {
            let data = '';
            res.on('data', (chunk: Buffer) => (data += chunk.toString('utf8')));
            res.on('end', () => resolve({ status: res.statusCode ?? 0, body: data }));
          },
        ).on('error', reject).end();
      });
      assert.equal(ok.status, 200);
      assert.match(ok.body, /"events"/);
    } finally {
      booted.api.stop();
    }
  });
});
