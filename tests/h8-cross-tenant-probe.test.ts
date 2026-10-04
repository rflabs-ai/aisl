/**
 * H8 cross-tenant isolation probe (ADR-030).
 *
 * ONE table-driven probe over the whole cross-tenant surface:
 * - every REST route (authorize, sessions, capability requests, audit, tasks,
 *   anchors, healthz, static pages);
 * - every in-process query surface (audit query/export, event-store reads,
 *   registry, sessions, capability requests, persistence).
 *
 * Each row asserts exactly one of:
 * - `enforced`: isolation in both directions — the foreign read/action is
 *   refused and the caller's visible records carry no foreign marker/content;
 * - `log-scan`: no foreign tenant marker or content appears in the caller's
 *   visible records or responses (a no-leak property; no refusal to assert);
 * - `global-by-design`: a named operator/chain surface that is deliberately
 *   cross-tenant and has no tenant-facing route.
 *
 * A new tenant-facing surface MUST add a row here; a surface without a row is
 * unproven. Postgres-gated rows skip cleanly without `DATABASE_URL`.
 */

import { request as httpRequest } from 'node:http';
import { randomUUID } from 'node:crypto';
import { mkdtempSync, readFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { after, before, beforeEach, describe, test } from 'node:test';
import assert from 'node:assert/strict';
import postgres from 'postgres';
import { createRestApi, type RestApi } from '../src/rest-api.ts';
import { CapabilityRequestService } from '../src/capability-request.ts';
import { PostgresEventLog } from '../src/event-store-pg.ts';
import { PersistenceStore } from '../src/persistence.ts';
import { authorizationRoot } from '../src/pdp.ts';
import { keyIdForTenant, sealFor } from '../src/seal.ts';
import { AUDIT_POLICY_RULE, TENANT_A, TENANT_B, type World } from '../src/scenario.ts';
import { createMockIdP, mockAuth, testWorld, type MockIdP } from '../src/testing.ts';
import type { Principal } from '../src/domain.ts';
import type { PolicyRule } from '../src/policy.ts';
import type { SessionTrace } from '../src/runtime.ts';
import type { TaskRunner } from '../src/rest-audit.ts';

// Deterministic keys for this process only (test files run in their own process).
process.env.CAPABILITY_SIGNING_KEY ??= 'h8-probe-capability-key';
process.env.EVIDENCE_SEALING_KEY ??= 'h8-probe-evidence-master-key';

const DATABASE_URL = process.env.DATABASE_URL;
const PG_SKIP = !DATABASE_URL && 'DATABASE_URL is not set (ADR-018: Postgres tests skip cleanly)';

const FOREIGN_DOC = 'doc:globex-strategy';
const MARKER_A = `h8probe-a-${randomUUID()}`;
const MARKER_B = `h8probe-b-${randomUUID()}`;
const B_SECRET_CONTENT = `globex-sealed-${MARKER_B}`;

/** Evidence decrypt for the probe's auditor role (same shape as tests/evidence.test.ts). */
const EVIDENCE_RULE: PolicyRule = {
  id: 'allow-auditor-evidence-decrypt',
  effect: 'allow',
  principals: { roles: ['auditor'] },
  actions: ['evidence.decrypt'],
  resources: { types: ['system'] },
};

interface RestResult {
  readonly status: number;
  readonly text: string;
  readonly body: Record<string, unknown>;
}

interface ProbeRig {
  readonly world: World;
  readonly api: RestApi;
  readonly port: number;
  readonly mockIdp: MockIdP;
  readonly alice: Principal;
  readonly bob: Principal;
  readonly bAgent: Principal;
  readonly auditorA: Principal;
  readonly auditorB: Principal;
  readonly mallory: Principal;
  readonly requests: CapabilityRequestService;
  readonly taskCalls: { principal: Principal; task: string }[];
  readonly bSealedKeyId: string;
}

interface ProbeCase {
  readonly id: string;
  readonly surface: string;
  readonly exposure: 'enforced' | 'log-scan' | 'global-by-design';
  readonly run: (rig: ProbeRig) => Promise<void> | void;
}

function token(rig: ProbeRig, sub: string): Promise<string> {
  return rig.mockIdp.signJWT({ sub, amr: ['pwd', 'mfa'] });
}

function call(rig: ProbeRig, method: string, path: string, options: { token?: string; body?: unknown } = {}): Promise<RestResult> {
  return new Promise((resolve, reject) => {
    const payload = options.body === undefined ? undefined : JSON.stringify(options.body);
    const req = httpRequest(
      {
        host: '127.0.0.1',
        port: rig.port,
        method,
        path,
        headers: {
          ...(options.token !== undefined ? { authorization: `Bearer ${options.token}` } : {}),
          ...(payload !== undefined ? { 'content-type': 'application/json' } : {}),
        },
      },
      (res) => {
        let text = '';
        res.on('data', (chunk: Buffer) => {
          text += chunk.toString('utf8');
        });
        res.on('end', () => {
          let body: Record<string, unknown> = {};
          try {
            const parsed: unknown = JSON.parse(text);
            if (typeof parsed === 'object' && parsed !== null && !Array.isArray(parsed)) {
              body = parsed as Record<string, unknown>;
            }
          } catch {
            // static pages are not JSON; keep the raw text.
          }
          resolve({ status: res.statusCode ?? 0, text, body });
        });
      },
    );
    req.on('error', reject);
    if (payload !== undefined) req.write(payload);
    req.end();
  });
}

async function buildProbeRig(): Promise<ProbeRig> {
  const world = testWorld({ policies: [AUDIT_POLICY_RULE, EVIDENCE_RULE] });
  const mockIdp = await createMockIdP();
  const idp = await mockIdp.createIdP();

  const alice = world.user;
  const bob: Principal = {
    id: 'user:h8-bob', kind: 'user', tenantId: TENANT_B, roles: [], attributes: {},
    auth: mockAuth({ subject: 'user:h8-bob' }),
  };
  const bAgent: Principal = {
    id: 'agent:h8-globex', kind: 'agent', tenantId: TENANT_B, roles: [], attributes: {},
    auth: mockAuth({ subject: 'agent:h8-globex' }),
  };
  const auditorA: Principal = {
    id: 'user:h8-auditor-a', kind: 'user', tenantId: TENANT_A, roles: ['auditor'], attributes: {},
    auth: mockAuth({ subject: 'user:h8-auditor-a' }),
  };
  const auditorB: Principal = {
    id: 'user:h8-auditor-b', kind: 'user', tenantId: TENANT_B, roles: ['auditor'], attributes: {},
    auth: mockAuth({ subject: 'user:h8-auditor-b' }),
  };
  const mallory: Principal = {
    id: 'user:h8-mallory', kind: 'user', tenantId: TENANT_B, roles: [], attributes: {},
    auth: mockAuth({ subject: 'user:h8-mallory' }),
  };
  const bRoot = authorizationRoot(TENANT_B);

  world.authorization.issue(world.root, {
    subject: alice.id, tenantId: TENANT_A, resourceIds: [`audit-log:${TENANT_A}`], actions: ['query.audit'],
    maxClassification: 'internal', expiresAt: Date.now() + 3_600_000, provenance: { source: 'policy-grant' },
  });
  world.authorization.issue(bRoot, {
    subject: bob.id, tenantId: TENANT_B, resourceIds: [`audit-log:${TENANT_B}`], actions: ['query.audit'],
    maxClassification: 'internal', expiresAt: Date.now() + 3_600_000, provenance: { source: 'policy-grant' },
  });
  // The crypto attack capability: tenant A names tenant B's v2 key id. Resource
  // ids are opaque strings, so this mint is legal — the key binding must refuse.
  world.authorization.issue(world.root, {
    subject: auditorA.id, tenantId: TENANT_A, resourceIds: [keyIdForTenant(TENANT_B, 'confidential')],
    actions: ['evidence.decrypt'], maxClassification: 'confidential',
    expiresAt: Date.now() + 3_600_000, provenance: { source: 'policy-grant' },
  });
  // Positive control: tenant B's own clearance for the same key id.
  world.authorization.issue(bRoot, {
    subject: auditorB.id, tenantId: TENANT_B, resourceIds: [keyIdForTenant(TENANT_B, 'confidential')],
    actions: ['evidence.decrypt'], maxClassification: 'confidential',
    expiresAt: Date.now() + 3_600_000, provenance: { source: 'policy-grant' },
  });

  world.eventLog.append({
    tenantId: TENANT_A, principal: alice.id, actor: alice.id, actorKind: 'user',
    action: 'read', resourceId: 'doc:acme-onboarding', result: 'success',
    metadata: { phase: 'h8-probe', marker: MARKER_A },
  });
  world.eventLog.append({
    tenantId: TENANT_B, principal: bAgent.id, actor: bAgent.id, actorKind: 'agent',
    action: 'read', resourceId: FOREIGN_DOC, result: 'success',
    metadata: { phase: 'h8-probe', marker: MARKER_B },
  });
  const sealed = sealFor(TENANT_B, B_SECRET_CONTENT, 'confidential');
  world.eventLog.append({
    tenantId: TENANT_B, principal: bAgent.id, actor: bAgent.id, actorKind: 'agent',
    action: 'write', resourceId: FOREIGN_DOC, result: 'success',
    metadata: { phase: 'h8-probe-sealed', sealed },
  });
  world.eventLog.append({
    tenantId: '', principal: 'operator:h8-probe', actor: 'operator:h8-probe', actorKind: 'user',
    action: 'incident.freeze', resourceId: 'global', result: 'success',
    metadata: { phase: 'h8-probe-global' },
  });

  const requests = new CapabilityRequestService(world.eventLog, world.authorization, world.root, world.clock.now);
  const taskCalls: { principal: Principal; task: string }[] = [];
  const runTask: TaskRunner = async (principal, task) => {
    taskCalls.push({ principal, task });
    const trace: SessionTrace = {
      sessionId: 'h8-probe-task', principal: principal.id, agentId: principal.id,
      modelId: 'h8-probe-model', modelText: 'probe', steps: [], injectionSignals: [],
      startedAt: 0, endedAt: 0,
    };
    return trace;
  };

  const principals: Record<string, Principal> = {
    [alice.id]: alice, [bob.id]: bob, [bAgent.id]: bAgent,
    [auditorA.id]: auditorA, [auditorB.id]: auditorB, [mallory.id]: mallory,
    [world.agent.id]: world.agent,
  };

  const api = createRestApi({
    authorization: world.authorization,
    idp,
    eventLog: world.eventLog,
    resolvePrincipal: (auth) => principals[auth.subject],
    staticPages: [{ route: '/ui', body: '<html><body>h8-probe-ui</body></html>', contentType: 'text/html' }],
    sessions: world.sessions,
    requests,
    audit: world.audit,
    runTask,
  });
  const port = await api.start();

  return { world, api, port, mockIdp, alice, bob, bAgent, auditorA, auditorB, mallory, requests, taskCalls, bSealedKeyId: sealed.keyId };
}

const REST_CASES: readonly ProbeCase[] = [
  {
    id: 'rest-authorize-cross-tenant',
    surface: 'POST /v1/authorize',
    exposure: 'enforced',
    run: async (rig) => {
      const aCross = await call(rig, 'POST', '/v1/authorize', {
        token: await token(rig, rig.alice.id),
        body: { action: 'read', resourceId: FOREIGN_DOC },
      });
      assert.equal(aCross.status, 403);
      assert.equal(aCross.body.denyReason, 'tenant-mismatch');

      const bCross = await call(rig, 'POST', '/v1/authorize', {
        token: await token(rig, rig.bob.id),
        body: { action: 'read', resourceId: 'repo:acme/repo-a' },
      });
      assert.equal(bCross.status, 403);
      assert.equal(bCross.body.denyReason, 'tenant-mismatch');
    },
  },
  {
    id: 'rest-sessions-cross-tenant',
    surface: 'POST /v1/sessions + DELETE /v1/sessions/:id',
    exposure: 'enforced',
    run: async (rig) => {
      const created = await call(rig, 'POST', '/v1/sessions', { token: await token(rig, rig.bob.id), body: {} });
      assert.equal(created.status, 201);
      const id = String(created.body.id);

      const foreign = await call(rig, 'DELETE', `/v1/sessions/${id}`, { token: await token(rig, rig.alice.id) });
      assert.equal(foreign.status, 403);
      assert.equal(foreign.body.error, 'tenant-mismatch');
      assert.notEqual(rig.world.sessions.get(id), undefined, 'a refused cross-tenant delete must not revoke the session');

      const own = await call(rig, 'DELETE', `/v1/sessions/${id}`, { token: await token(rig, rig.bob.id) });
      assert.equal(own.status, 200);
    },
  },
  {
    id: 'rest-audit-own-tenant-only',
    surface: 'GET /v1/audit',
    exposure: 'enforced',
    run: async (rig) => {
      const res = await call(rig, 'GET', '/v1/audit', { token: await token(rig, rig.alice.id) });
      assert.equal(res.status, 200);
      const events = res.body.events as { tenantId: string; eventHash: string }[];
      assert.ok(Array.isArray(events) && events.length > 0);
      assert.ok(events.every((event) => event.tenantId === TENANT_A));
      assert.match(events[0]!.eventHash, /^[0-9a-f]{64}$/);
      assert.equal(res.text.includes(MARKER_B), false);
      assert.equal(res.text.includes(B_SECRET_CONTENT), false);
    },
  },
  {
    id: 'rest-audit-cross-tenant',
    surface: 'GET /v1/audit?tenantId=<other>',
    exposure: 'enforced',
    run: async (rig) => {
      const foreign = await call(rig, 'GET', `/v1/audit?tenantId=${TENANT_B}`, { token: await token(rig, rig.alice.id) });
      assert.equal(foreign.status, 403);
      assert.equal(foreign.body.denyReason, 'tenant-mismatch');
      assert.equal(foreign.text.includes(MARKER_B), false);

      const reverse = await call(rig, 'GET', `/v1/audit?tenantId=${TENANT_A}`, { token: await token(rig, rig.bob.id) });
      assert.equal(reverse.status, 403);
      assert.equal(reverse.body.denyReason, 'tenant-mismatch');

      const deny = rig.world.eventLog
        .all()
        .filter((event) => event.action === 'query.audit' && event.denyReason === 'tenant-mismatch')
        .at(-1);
      assert.ok(deny, 'the in-process service must append the cross-tenant deny event');
    },
  },
  {
    id: 'rest-capability-requests-cross-tenant',
    surface: 'POST/GET /v1/capability-requests + GET/:id + POST/:id/approvals',
    exposure: 'enforced',
    run: async (rig) => {
      const submit = await call(rig, 'POST', '/v1/capability-requests', {
        token: await token(rig, rig.bAgent.id),
        body: {
          sessionId: 'h8-probe-session', resources: [FOREIGN_DOC], actions: ['read'],
          maxClassification: 'confidential', justification: `globex need ${MARKER_B}`,
        },
      });
      assert.equal(submit.status, 201);
      assert.equal(submit.body.tenantId, TENANT_B);
      const requestId = String(submit.body.id);
      assert.equal(submit.text.includes(MARKER_A), false);

      const listA = await call(rig, 'GET', '/v1/capability-requests', { token: await token(rig, rig.alice.id) });
      assert.equal(listA.status, 200);
      assert.equal(listA.text.includes(requestId), false, 'the globex request must not appear in the acme list');
      assert.equal(listA.text.includes(MARKER_B), false);

      const getA = await call(rig, 'GET', `/v1/capability-requests/${requestId}`, { token: await token(rig, rig.alice.id) });
      assert.equal(getA.status, 403);
      assert.equal(getA.body.error, 'tenant-mismatch');
      assert.equal(getA.text.includes(MARKER_B), false);

      const approveA = await call(rig, 'POST', `/v1/capability-requests/${requestId}/approvals`, {
        token: await token(rig, rig.alice.id), body: {},
      });
      assert.equal(approveA.status, 403);
      assert.equal(approveA.body.error, 'tenant-mismatch');
      assert.equal(approveA.text.includes(MARKER_B), false);

      const getB = await call(rig, 'GET', `/v1/capability-requests/${requestId}`, { token: await token(rig, rig.bAgent.id) });
      assert.equal(getB.status, 200);
      const own = getB.body.request as Record<string, unknown>;
      assert.equal(own.id, requestId);
      assert.equal(own.tenantId, TENANT_B);
    },
  },
  {
    id: 'rest-anchors-cross-tenant',
    surface: 'POST /v1/anchors',
    exposure: 'enforced',
    run: async (rig) => {
      const cross = await call(rig, 'POST', '/v1/anchors', {
        token: await token(rig, rig.alice.id),
        body: { tenant: TENANT_B, headHash: 'a'.repeat(64), eventCount: 1, anchoredAt: 1 },
      });
      assert.equal(cross.status, 403);
      assert.equal(cross.body.error, 'tenant-mismatch');

      const own = await call(rig, 'POST', '/v1/anchors', {
        token: await token(rig, rig.bob.id),
        body: { tenant: TENANT_B, headHash: 'b'.repeat(64), eventCount: 1, anchoredAt: 1 },
      });
      assert.equal(own.status, 201);
      const anchors = rig.world.eventLog.all().filter((event) => event.action === 'anchor.register');
      assert.ok(anchors.length > 0);
      assert.ok(anchors.every((event) => event.tenantId === TENANT_B));
      assert.equal(
        rig.world.eventLog.all().some((event) => event.action === 'anchor.register' && event.tenantId === TENANT_A),
        false,
        'a refused foreign anchor must not be recorded under the caller tenant',
      );
    },
  },
  {
    id: 'rest-tasks-principal-tenant',
    surface: 'POST /v1/tasks',
    exposure: 'enforced',
    run: async (rig) => {
      const res = await call(rig, 'POST', '/v1/tasks', {
        token: await token(rig, rig.bAgent.id),
        body: { task: 'h8 probe task', tenantId: TENANT_A, resources: ['repo:acme/repo-a'] },
      });
      assert.equal(res.status, 200);
      assert.equal(res.body.principal, rig.bAgent.id);
      const captured = rig.taskCalls.at(-1)!;
      assert.equal(captured.principal.tenantId, TENANT_B, 'the task runs as the verified principal tenant, never a body field');
      assert.equal(captured.task, 'h8 probe task');
      assert.equal(res.text.includes(MARKER_A), false);
    },
  },
  {
    id: 'rest-healthz-and-static-page',
    surface: 'GET /healthz + GET /ui',
    exposure: 'log-scan',
    run: async (rig) => {
      const health = await call(rig, 'GET', '/healthz');
      assert.equal(health.status, 200);
      assert.deepEqual(Object.keys(health.body).sort(), ['idp', 'store']);
      assert.equal(health.text.includes(MARKER_A), false);
      assert.equal(health.text.includes(MARKER_B), false);

      const page = await call(rig, 'GET', '/ui');
      assert.equal(page.status, 200);
      assert.ok(page.text.includes('h8-probe-ui'));
      assert.equal(page.text.includes(MARKER_B), false);
    },
  },
];

const IN_PROCESS_CASES: readonly ProbeCase[] = [
  {
    id: 'audit-query-isolation',
    surface: 'AuditQueryService.query',
    exposure: 'enforced',
    run: (rig) => {
      const result = rig.world.audit.query(rig.alice, { tenantId: TENANT_A, limit: 1000 });
      assert.equal(result.decision.decision, 'allow');
      assert.ok(result.events.length > 0);
      assert.ok(result.events.every((event) => event.tenantId === TENANT_A));
      assert.equal(JSON.stringify(result.events).includes(MARKER_B), false);
    },
  },
  {
    id: 'audit-query-cross-tenant',
    surface: 'AuditQueryService.query (cross-tenant filters)',
    exposure: 'enforced',
    run: (rig) => {
      const denied = rig.world.audit.query(rig.alice, { tenantId: TENANT_B });
      assert.equal(denied.decision.decision, 'deny');
      assert.equal(denied.decision.denyReason, 'tenant-mismatch');
      assert.equal(denied.events.length, 0);

      const reverse = rig.world.audit.query(rig.bob, { tenantId: TENANT_A });
      assert.equal(reverse.decision.decision, 'deny');
      assert.equal(reverse.decision.denyReason, 'tenant-mismatch');
      assert.equal(reverse.events.length, 0);
    },
  },
  {
    id: 'audit-export-cross-tenant',
    surface: 'AuditQueryService.exportFor',
    exposure: 'enforced',
    run: (rig) => {
      const denied = rig.world.audit.exportFor(rig.alice, { tenantId: TENANT_B });
      assert.deepEqual(denied.events, []);

      const own = rig.world.audit.exportFor(rig.alice, { tenantId: TENANT_A, limit: 1000 });
      assert.ok(own.events.length > 0);
      assert.ok(own.events.every((event) => event.tenantId === TENANT_A));
      assert.equal(JSON.stringify(own).includes(MARKER_B), false);
    },
  },
  {
    id: 'event-store-reads',
    surface: 'EventStore.query/forTenant/exportFor',
    exposure: 'enforced',
    run: (rig) => {
      const store = rig.world.eventLog;
      const forA = store.forTenant(TENANT_A);
      assert.ok(forA.length > 0);
      assert.ok(forA.every((event) => event.tenantId === TENANT_A));
      assert.equal(JSON.stringify(forA).includes(MARKER_B), false);

      assert.ok(store.query({ tenantId: TENANT_A, limit: 1000 }).every((event) => event.tenantId === TENANT_A));
      const exported = store.exportFor({ tenantId: TENANT_A, limit: 1000 });
      assert.ok(exported.events.every((event) => event.tenantId === TENANT_A));
      assert.equal(JSON.stringify(exported.events).includes(MARKER_B), false);
      assert.equal(JSON.stringify(store.forTenant(TENANT_B)).includes(MARKER_A), false);
    },
  },
  {
    id: 'event-store-global-chain',
    surface: 'EventStore.all/bundle/verify (operator chain view)',
    exposure: 'global-by-design',
    run: (rig) => {
      const all = rig.world.eventLog.all();
      assert.ok(all.some((event) => event.tenantId === TENANT_A));
      assert.ok(all.some((event) => event.tenantId === TENANT_B));
      assert.ok(all.some((event) => event.tenantId === '' && event.action === 'incident.freeze'));
      assert.equal(rig.world.eventLog.verify().valid, true);
      assert.equal(typeof rig.world.eventLog.bundle(), 'string');
      // Deliberately cross-tenant: one signer, world-order seq, resume/verify.
      // No REST route exposes it (probe-proven by the cases above).
    },
  },
  {
    id: 'registry-isolation',
    surface: 'ResourceRegistry.list/get + PDP tenant guard',
    exposure: 'enforced',
    run: (rig) => {
      const aResources = rig.world.registry.list(TENANT_A);
      assert.ok(aResources.length > 0);
      assert.ok(aResources.every((resource) => resource.tenantId === TENANT_A));
      assert.equal(JSON.stringify(aResources).includes(MARKER_B), false);

      const bResources = rig.world.registry.list(TENANT_B);
      assert.ok(bResources.every((resource) => resource.tenantId === TENANT_B));
      assert.ok(bResources.some((resource) => resource.id === FOREIGN_DOC));

      const decision = rig.world.authorization.authorize({ principal: rig.alice, action: 'read', resourceId: FOREIGN_DOC });
      assert.equal(decision.decision, 'deny');
      assert.equal(decision.denyReason, 'tenant-mismatch');
    },
  },
  {
    id: 'session-manager-tenant-scoped-bulk',
    surface: 'SessionManager tenant-wide revocation',
    exposure: 'enforced',
    run: (rig) => {
      const bSession = rig.world.sessions.create(rig.bob, rig.bob.auth!);
      const aSession = rig.world.sessions.create(rig.alice, rig.alice.auth!);
      rig.world.sessions.revokeAllForTenant(TENANT_A);
      assert.notEqual(
        rig.world.sessions.get(bSession.id),
        undefined,
        'a tenant-wide revocation must not cross tenants',
      );
      assert.equal(rig.world.sessions.get(aSession.id), undefined, 'the bulk revoke hits its own tenant');

      const aSession2 = rig.world.sessions.create(rig.alice, rig.alice.auth!);
      rig.world.sessions.revokeAllForTenant(TENANT_B);
      assert.notEqual(
        rig.world.sessions.get(aSession2.id),
        undefined,
        'the reverse direction must not cross tenants either',
      );

      rig.world.sessions.revoke(bSession.id);
      rig.world.sessions.revoke(aSession2.id);
    },
  },
  {
    id: 'capability-request-service-tenancy',
    surface: 'CapabilityRequestService.approve/deny',
    exposure: 'enforced',
    run: (rig) => {
      const before = rig.world.eventLog.all().filter((event) => event.action === 'capability.approve').length;
      const request = rig.requests.submit(
        rig.world.agent, 'h8-probe-session-a', ['doc:acme-onboarding'], ['read'], 'internal', `acme request ${MARKER_A}`,
      );
      assert.throws(() => rig.requests.approve(request.id, rig.bob), /tenant/);
      assert.throws(() => rig.requests.deny(request.id, rig.bob), /tenant/);
      assert.equal(
        rig.world.eventLog.all().filter((event) => event.action === 'capability.approve').length,
        before,
        'a refused cross-tenant review must write nothing',
      );
      assert.equal(rig.requests.get(request.id)?.status, 'pending');

      const sameTenant = rig.requests.approve(request.id, rig.alice);
      assert.equal(sameTenant.request.status, 'approved');
      assert.equal(sameTenant.capability.tenantId, TENANT_A);
    },
  },
  {
    id: 'evidence-key-binding',
    surface: 'AuthorizationService.revealEvidence (v2 key tenant binding)',
    exposure: 'enforced',
    run: (rig) => {
      const sealedEvent = rig.world.eventLog
        .all()
        .find((event) => (event.metadata as { phase?: string } | undefined)?.phase === 'h8-probe-sealed');
      assert.ok(sealedEvent);
      assert.equal(rig.bSealedKeyId, keyIdForTenant(TENANT_B, 'confidential'));

      // Tenant A holds a capability naming tenant B's key id (resource ids are
      // opaque strings). The decrypt must refuse, and must not bind B's key to A.
      const stolen = rig.world.authorization.revealEvidence(rig.auditorA, sealedEvent);
      assert.equal(stolen, undefined, 'a v2 key must only open for the tenant it names');
      assert.notEqual(rig.world.registry.get(rig.bSealedKeyId)?.tenantId, TENANT_A);

      // Positive control: the bound tenant's clearance opens exactly the content.
      assert.equal(rig.world.authorization.revealEvidence(rig.auditorB, sealedEvent), B_SECRET_CONTENT);
    },
  },
  {
    id: 'incident-global-view',
    surface: 'IncidentService.reconstruct (tenantId: *)',
    exposure: 'enforced',
    run: (rig) => {
      const all = rig.world.eventLog.all();
      const toSeq = all.at(-1)!.seq;
      const expectedGlobalEvents = all.filter((event) => event.tenantId === '').length;
      assert.ok(expectedGlobalEvents >= 1);

      const report = rig.world.incident.reconstruct({ principal: rig.alice, tenantId: '*', fromSeq: 0, toSeq });
      assert.equal(report.tenantId, '*');
      assert.equal(report.events, expectedGlobalEvents, 'the global view exposes only tenant-less events');
      assert.equal(report.actors.some((actor) => actor.includes('h8-globex')), false);

      // Denied without the caller's own audit authority...
      assert.throws(
        () => rig.world.incident.reconstruct({ principal: rig.mallory, tenantId: '*', fromSeq: 0, toSeq }),
        /denied/,
      );
      // ...and denied for another tenant's window.
      assert.throws(
        () => rig.world.incident.reconstruct({ principal: rig.alice, tenantId: TENANT_B, fromSeq: 0, toSeq }),
        /denied/,
      );
    },
  },
  {
    id: 'incident-preserve-global',
    surface: 'IncidentService.preserve (tenantId: *)',
    exposure: 'enforced',
    run: (rig) => {
      const dir = mkdtempSync(join(tmpdir(), 'h8-probe-'));
      const outPath = join(dir, 'global-bundle.json');
      try {
        const toSeq = rig.world.eventLog.all().at(-1)!.seq;
        const result = rig.world.incident.preserve({ principal: rig.alice, tenantId: '*', fromSeq: 0, toSeq, outPath });
        assert.ok(result.events >= 1);
        const raw = readFileSync(outPath, 'utf8');
        const bundle = JSON.parse(raw) as { tenantId: string; events: { tenantId: string }[] };
        assert.equal(bundle.tenantId, '*');
        assert.ok(bundle.events.every((event) => event.tenantId === ''));
        assert.equal(raw.includes(MARKER_B), false);
        assert.equal(raw.includes(B_SECRET_CONTENT), false);
      } finally {
        rmSync(dir, { recursive: true, force: true });
      }
    },
  },
  {
    id: 'log-scan',
    surface: "tenant A's visible records and exports",
    exposure: 'log-scan',
    run: (rig) => {
      const corpora = [
        JSON.stringify(rig.world.audit.query(rig.alice, { tenantId: TENANT_A, limit: 1000 }).events),
        JSON.stringify(rig.world.audit.exportFor(rig.alice, { tenantId: TENANT_A, limit: 1000 }).events),
        JSON.stringify(rig.world.eventLog.forTenant(TENANT_A)),
      ];
      for (const corpus of corpora) {
        assert.equal(corpus.includes(MARKER_B), false, 'tenant B marker must not appear in tenant A visible records');
        assert.equal(corpus.includes(B_SECRET_CONTENT), false, 'tenant B sealed plaintext must never appear');
      }
    },
  },
];

let rig: ProbeRig | undefined;

before(async () => {
  rig = await buildProbeRig();
});

after(() => {
  rig?.api.stop();
});

function runCases(title: string, cases: readonly ProbeCase[]): void {
  describe(title, () => {
    for (const probeCase of cases) {
      test(`${probeCase.id} — ${probeCase.surface} [${probeCase.exposure}]`, async () => {
        assert.ok(rig, 'probe rig must be initialized');
        await probeCase.run(rig);
      });
    }
  });
}

runCases('H8 probe: REST routes', REST_CASES);
runCases('H8 probe: in-process query surfaces', IN_PROCESS_CASES);

// Postgres-gated rows. Module-level admin + hooks (mirrors tests/tenant-rls.test.ts)
// so the skipped suite enumerates its cases when DATABASE_URL is unset.
const pgAdmin: ReturnType<typeof postgres> | undefined = DATABASE_URL ? postgres(DATABASE_URL) : undefined;

after(async () => {
  if (pgAdmin) await pgAdmin.end({ timeout: 1_000 });
});

// DATABASE_URL points at a disposable scratch database: wipe before every case
// so each starts from a fresh schema (matches the M12 suites).
beforeEach(async () => {
  if (!pgAdmin) return;
  await pgAdmin`DROP SCHEMA public CASCADE`;
  await pgAdmin`CREATE SCHEMA public`;
});

describe('H8 probe: Postgres-gated storage surfaces', () => {
  test('probe-pg-persistence — tenant-bound reads and lists over Postgres', { skip: PG_SKIP }, async () => {
    const log = new PostgresEventLog({ url: DATABASE_URL!, migrateUrl: DATABASE_URL! });
    await log.whenReady();
    const store = new PersistenceStore({ url: DATABASE_URL! });
    try {
      await store.createProject('t1', 'proj-1', `proj-${MARKER_A}`);
      await store.createProject('t2', 'proj-2', `proj-${MARKER_B}`);
      await store.createTask('t1', 'task-1', 'proj-1', { marker: MARKER_A });
      await store.createTask('t2', 'task-2', 'proj-2', { marker: MARKER_B });
      await store.saveSession('t1', 'sess-1', 'task-1', 'agent:t1', { marker: MARKER_A });
      await store.saveSession('t2', 'sess-2', 'task-2', 'agent:t2', { marker: MARKER_B });
      const expiry = new Date(Date.now() + 300_000);
      await store.createCapabilityRequest('t1', 'req-1', 'agent:t1', { marker: MARKER_A }, expiry);
      await store.createCapabilityRequest('t2', 'req-2', 'agent:t2', { marker: MARKER_B }, expiry);

      assert.equal(await store.getProject('t1', 'proj-2'), undefined);
      assert.equal(await store.getTask('t1', 'task-2'), undefined);
      assert.equal(await store.getSession('t1', 'sess-2'), undefined);
      assert.equal(await store.getCapabilityRequest('t1', 'req-2'), undefined);
      assert.equal(await store.updateTaskStatus('t1', 'task-2', 'done'), undefined);
      assert.equal(await store.updateCapabilityRequestStatus('t1', 'req-2', 'approved', 'user:t1'), undefined);

      const t1Projects = await store.listProjects('t1');
      assert.ok(t1Projects.length > 0);
      assert.ok(t1Projects.every((project) => project.tenantId === 't1'));
      assert.equal(JSON.stringify(t1Projects).includes(MARKER_B), false);
      assert.equal((await store.listTasksForProject('t1', 'proj-2')).length, 0);
      assert.equal((await store.listSessionsForTask('t1', 'task-2')).length, 0);
      const t1Requests = await store.listCapabilityRequestsForTenant('t1');
      assert.ok(t1Requests.some((request) => request.id === 'req-1'));
      assert.equal(t1Requests.some((request) => request.id === 'req-2'), false);
      assert.equal(JSON.stringify(t1Requests).includes(MARKER_B), false);
    } finally {
      store.close();
      log.close();
    }
  });

  test('probe-pg-event-store — the port reads stay tenant-scoped over Postgres', { skip: PG_SKIP }, async () => {
    const log = new PostgresEventLog({ url: DATABASE_URL!, migrateUrl: DATABASE_URL! });
    try {
      await log.whenReady();
      log.append({
        tenantId: 't1', principal: 'p1', actor: 'agent:t1', actorKind: 'agent', action: 'read',
        resourceId: `doc:${MARKER_A}`, result: 'success', metadata: { marker: MARKER_A },
      });
      log.append({
        tenantId: 't2', principal: 'p2', actor: 'agent:t2', actorKind: 'agent', action: 'read',
        resourceId: `doc:${MARKER_B}`, result: 'success', metadata: { marker: MARKER_B },
      });
      const forT1 = log.forTenant('t1');
      assert.ok(forT1.length >= 1);
      assert.ok(forT1.every((event) => event.tenantId === 't1'));
      assert.equal(JSON.stringify(forT1).includes(MARKER_B), false);
      assert.ok(log.query({ tenantId: 't1', limit: 1000 }).every((event) => event.tenantId === 't1'));
      assert.ok(log.exportFor({ tenantId: 't1', limit: 1000 }).events.every((event) => event.tenantId === 't1'));
    } finally {
      log.close();
    }
  });
});
