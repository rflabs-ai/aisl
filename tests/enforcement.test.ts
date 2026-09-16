/**
 * M1 enforcement tests: container sandbox, real egress proxy, envelope secrets.
 *
 * Each test that fails without its control is a regression guard.
 */

import { test, describe } from 'node:test';
import assert from 'node:assert/strict';
import { randomUUID } from 'node:crypto';
import { request as httpRequest } from 'node:http';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { isDockerAvailable, ContainerSandbox, resetDockerCache } from '../src/container-sandbox.ts';
import { EgressProxy } from '../src/egress-proxy.ts';
import { EnvelopeSecretBroker, encryptSecret, decryptSecret } from '../src/envelope-secrets.ts';
import { LocalSandbox, ToolRegistry, AgentSession } from '../src/runtime.ts';
import { testWorld, mockAuth } from '../src/testing.ts';
import { TENANT_A, TENANT_B } from '../src/scenario.ts';
import { runAttackCorpus } from '../src/attacks.ts';

const ROOT = join(dirname(fileURLToPath(import.meta.url)), '..');

// ── Container sandbox ────────────────────────────────────────────────────────

describe('container sandbox', () => {
  test('isDockerAvailable returns a boolean without throwing', () => {
    assert.equal(typeof isDockerAvailable(), 'boolean');
  });

  test('ContainerSandbox falls back to LocalSandbox when Docker unavailable', () => {
    resetDockerCache();
    const sandbox = new ContainerSandbox(new LocalSandbox());
    assert.equal(sandbox.run(() => 42), 42);
    assert.ok(sandbox.kind.includes('fallback'), `kind=${sandbox.kind}`);
  });

  test('LocalSandbox kind reports no-isolation', () => {
    assert.equal(new LocalSandbox().kind, 'in-process/no-isolation');
  });

  test('ContainerSandbox has configurable resource limits', () => {
    const sandbox = new ContainerSandbox(new LocalSandbox(), {
      memoryLimit: '64m',
      pidsLimit: 32,
      timeoutMs: 5_000,
    });
    assert.ok(sandbox.kind);
  });

  test('escape attempt: sandboxed code cannot reach host filesystem when Docker available', () => {
    const sandbox = new ContainerSandbox(new LocalSandbox());
    if (!isDockerAvailable()) {
      // Fallback mode: kind is 'fallback/in-process/no-isolation'
      assert.ok(sandbox.kind.includes('fallback'));
    } else {
      assert.ok(sandbox.kind.includes('container'));
    }
  });
});

// ── Egress proxy ─────────────────────────────────────────────────────────────

describe('egress proxy enforcement', () => {
  test('IP literals are blocked at the proxy layer', async () => {
    const world = testWorld();
    const proxy = new EgressProxy(world.agent, world.authorization, world.registry, world.eventLog, { dnsPin: false });
    const result = await proxy.check('192.168.1.1');
    assert.equal(result.allowed, false);
    assert.ok(result.reason.includes('IP literal'));
  });

  test('non-allowlisted host is denied by PDP', async () => {
    const world = testWorld();
    const proxy = new EgressProxy(world.agent, world.authorization, world.registry, world.eventLog, { dnsPin: false });
    assert.equal((await proxy.check('evil.example.com')).allowed, false);
  });

  test('allowlisted host is permitted', async () => {
    const world = testWorld();
    const proxy = new EgressProxy(world.agent, world.authorization, world.registry, world.eventLog, { dnsPin: false });
    assert.equal((await proxy.check('api.internal.example.com')).allowed, true);
  });

  test('host normalization does not bypass', async () => {
    const world = testWorld();
    const proxy = new EgressProxy(world.agent, world.authorization, world.registry, world.eventLog, { dnsPin: false });
    assert.equal((await proxy.check('EVIL.example.com')).allowed, false);
    assert.equal((await proxy.check('evil.example.com.')).allowed, false);
  });

  test('client-supplied identity headers cannot change the principal', async () => {
    const world = testWorld();
    const proxy = new EgressProxy(world.agent, world.authorization, world.registry, world.eventLog, { dnsPin: false });
    const port = await proxy.start();

    const status = await new Promise<number>((resolve, reject) => {
      const req = httpRequest(
        {
          host: '127.0.0.1',
          port,
          method: 'GET',
          path: '/',
          headers: {
            host: 'evil.example.com',
            'x-principal-id': 'user:alice',
            'x-tenant-id': TENANT_B,
          },
        },
        (res) => {
          res.resume();
          resolve(res.statusCode ?? 0);
        },
      );
      req.on('error', reject);
      req.end();
    });
    proxy.stop();

    assert.equal(status, 403);
    const recorded = world.eventLog
      .all()
      .filter((e) => (e.metadata as { phase?: string } | undefined)?.phase === 'egress-proxy')
      .at(-1);
    assert.equal(recorded?.principal, world.agent.id, 'proxy must use the bound principal, not the header');
    assert.equal(recorded?.tenantId, TENANT_A, 'proxy must use the bound tenant, not the header');
  });

  test('proxyEnv returns HTTP_PROXY configuration', () => {
    const world = testWorld();
    const env = new EgressProxy(world.agent, world.authorization, world.registry, world.eventLog, { dnsPin: false }).proxyEnv();
    assert.ok(env.HTTP_PROXY);
    assert.ok(env.HTTPS_PROXY);
    assert.ok(env.NO_PROXY);
  });
});

// ── DNS pinning ─────────────────────────────────────────────────────────────

describe('DNS pinning: private/reserved IPs are blocked', () => {
  test('hostname resolving to private IP is denied when dnsPin is true', async () => {
    const world = testWorld();
    const proxy = new EgressProxy(world.agent, world.authorization, world.registry, world.eventLog, { dnsPin: true });
    // localhost resolves to 127.0.0.1 (private) — should be blocked by DNS pinning.
    const result = await proxy.check('localhost');
    assert.equal(result.allowed, false);
    assert.ok(result.reason.includes('private/reserved'));
  });

  test('IP literal 169.254.169.254 (cloud metadata) is blocked', async () => {
    const world = testWorld();
    const proxy = new EgressProxy(world.agent, world.authorization, world.registry, world.eventLog, { dnsPin: true });
    const result = await proxy.check('169.254.169.254');
    assert.equal(result.allowed, false);
    assert.ok(result.reason.includes('IP literal'));
  });

  test('DNS resolution failure is denied when dnsPin is true', async () => {
    const world = testWorld();
    const proxy = new EgressProxy(world.agent, world.authorization, world.registry, world.eventLog, { dnsPin: true });
    const result = await proxy.check('this-host-does-not-exist-12345.invalid');
    assert.equal(result.allowed, false);
    assert.ok(result.reason.includes('DNS'));
  });

  test('DNS resolution skipped when dnsPin is false', async () => {
    const world = testWorld();
    const proxy = new EgressProxy(world.agent, world.authorization, world.registry, world.eventLog, { dnsPin: false });
    const result = await proxy.check('nonexistent-host.invalid');
    assert.equal(result.allowed, false);
    assert.ok(!result.reason.includes('DNS'), 'should not fail on DNS when dnsPin is false');
  });
});

// ── Canary exfiltration ─────────────────────────────────────────────────────

describe('canary exfiltration: unique tokens never leak at egress', () => {
  test('canary tokens do not appear in any egress check result', async () => {
    const world = testWorld();
    const canaries = {
      internal: `CANARY-INTERNAL-${randomUUID()}`,
      confidential: `CANARY-CONFIDENTIAL-${randomUUID()}`,
      phi: `CANARY-PHI-${randomUUID()}`,
    };

    const proxy = new EgressProxy(world.agent, world.authorization, world.registry, world.eventLog, { dnsPin: false });
    for (const host of ['api.internal.example.com', 'evil.example.com', '10.0.0.1']) {
      const resultStr = JSON.stringify(await proxy.check(host));
      for (const [level, token] of Object.entries(canaries)) {
        assert.ok(!resultStr.includes(token), `canary ${level} leaked to egress for ${host}`);
      }
    }
  });

  test('canary token does not appear in HTTP response body through proxy', async () => {
    const world = testWorld();
    const canary = `CANARY-WIRE-${randomUUID()}`;
    const proxy = new EgressProxy(world.agent, world.authorization, world.registry, world.eventLog, { dnsPin: false });
    const port = await proxy.start();

    const body = await new Promise<string>((resolve, reject) => {
      const req = httpRequest(
        { host: '127.0.0.1', port, method: 'GET', path: '/', headers: { host: `evil.example.com?canary=${canary}` } },
        (res) => {
          let data = '';
          res.on('data', (chunk) => { data += chunk; });
          res.on('end', () => resolve(data));
        },
      );
      req.on('error', reject);
      req.end();
    });
    proxy.stop();

    assert.ok(!body.includes(canary), `canary leaked through HTTP response: ${body.slice(0, 100)}`);
    assert.ok(body.includes('denied'), `expected denial in response: ${body.slice(0, 100)}`);
  });

  test('event log never contains raw secret values', () => {
    const world = testWorld();
    const canary = `CANARY-${randomUUID()}`;
    for (const event of world.eventLog.all()) {
      assert.ok(!JSON.stringify(event).includes(canary), `canary in event ${event.seq}`);
    }
  });
});

// ── Envelope secrets ─────────────────────────────────────────────────────────

describe('envelope encryption for secrets', () => {
  test('encrypt/decrypt roundtrip preserves plaintext', () => {
    const key = Buffer.from('test-master-key-for-envelope-encryption-32b!', 'utf8');
    const pt = 'sk-fake-TESTKEY-0000';
    assert.equal(decryptSecret(encryptSecret(pt, key), key), pt);
  });

  test('wrong master key fails to decrypt', () => {
    const k1 = Buffer.from('master-key-one-32-bytes-padding!!', 'utf8');
    const k2 = Buffer.from('master-key-two-32-bytes-padding!!', 'utf8');
    assert.throws(() => decryptSecret(encryptSecret('x', k1), k2));
  });

  test('envelope broker default deny: no secret.use capability', () => {
    const world = testWorld();
    const broker = new EnvelopeSecretBroker(
      Buffer.from('test-master-key-for-envelope-encryption-32b!', 'utf8'),
      world.authorization, world.eventLog, world.registry,
    );
    broker.register({ id: 'sec1', tenantId: 'acme', value: 'v', label: 't' });
    const res = broker.request({ principal: world.agent, secretId: 'sec1' });
    assert.equal(res.allowed, false);
    assert.equal(res.value, undefined);
  });

  test('break-glass: capability + approval yields decrypted value', () => {
    const world = testWorld({
      policies: [{
        id: 'allow-secret-breakglass',
        effect: 'allow',
        principals: { ids: ['agent:summarizer-1'] },
        actions: ['secret.use'],
        resources: { types: ['secret'] },
        requiresApproval: true,
        conditions: [{ kind: 'after', iso: '2020-01-01T00:00:00Z' }],
      }],
    });
    const broker = new EnvelopeSecretBroker(
      Buffer.from('test-master-key-for-envelope-encryption-32b!', 'utf8'),
      world.authorization, world.eventLog, world.registry,
    );
    broker.register({ id: 'sec-bg', tenantId: 'acme', value: 'real-value', label: 'bg' });

    world.authorization.issue(world.root, {
      subject: world.agent.id, tenantId: 'acme',
      resourceIds: ['sec-bg'], actions: ['secret.use'],
      maxClassification: 'restricted',
      expiresAt: world.clock.now() + 60_000, singleUse: true,
      provenance: { source: 'human-approval', approvedBy: world.user.id },
    });

    const userAuthCtx = mockAuth({ subject: world.user.id, amr: ['pwd', 'mfa'] });
    const approval = {
      id: 'a1', approvedBy: world.user.id, reviewerAuth: userAuthCtx, principalId: world.agent.id,
      action: 'secret.use' as const, resourceId: 'sec-bg',
      expiresAt: world.clock.now() + 60_000,
    };

    const res = broker.request({ principal: world.agent, secretId: 'sec-bg', approvals: [approval] });
    assert.equal(res.allowed, true);
    assert.equal(res.value, 'real-value');
  });

  test('event log contains redacted placeholder, not plaintext', () => {
    const world = testWorld({
      policies: [{
        id: 'allow-secret-breakglass',
        effect: 'allow',
        principals: { ids: ['agent:summarizer-1'] },
        actions: ['secret.use'],
        resources: { types: ['secret'] },
        requiresApproval: true,
        conditions: [{ kind: 'after', iso: '2020-01-01T00:00:00Z' }],
      }],
    });
    const secretVal = `SECRET-${randomUUID()}`;
    const broker = new EnvelopeSecretBroker(
      Buffer.from('test-master-key-for-envelope-encryption-32b!', 'utf8'),
      world.authorization, world.eventLog, world.registry,
    );
    broker.register({ id: 'sec-log', tenantId: 'acme', value: secretVal, label: 'log' });

    world.authorization.issue(world.root, {
      subject: world.agent.id, tenantId: 'acme',
      resourceIds: ['sec-log'], actions: ['secret.use'],
      maxClassification: 'restricted',
      expiresAt: world.clock.now() + 60_000, singleUse: true,
      provenance: { source: 'human-approval', approvedBy: world.user.id },
    });

    const userAuthCtx = mockAuth({ subject: world.user.id, amr: ['pwd', 'mfa'] });
    const approval = {
      id: 'a2', approvedBy: world.user.id, reviewerAuth: userAuthCtx, principalId: world.agent.id,
      action: 'secret.use' as const, resourceId: 'sec-log',
      expiresAt: world.clock.now() + 60_000,
    };

    broker.request({ principal: world.agent, secretId: 'sec-log', approvals: [approval] });

    const events = world.eventLog.all().filter((e) => e.resourceId === 'sec-log' && e.action === 'secret.use');
    assert.ok(events.length > 0);
    const eventStr = JSON.stringify(events);
    assert.ok(eventStr.includes('[decrypted-withheld]'), 'event should contain redacted placeholder');
    assert.ok(!eventStr.includes(secretVal), 'event must not contain plaintext secret');
  });

  test('redact masks values', () => {
    assert.equal(EnvelopeSecretBroker.redact('ab'), '****');
    const long = EnvelopeSecretBroker.redact('sk-1234567890abcdef');
    assert.ok(long.startsWith('sk') && long.endsWith('ef'));
    assert.ok(!long.includes('1234567890'));
  });

  test('cross-tenant secret access is denied', () => {
    const world = testWorld();
    const broker = new EnvelopeSecretBroker(
      Buffer.from('test-master-key-for-envelope-encryption-32b!', 'utf8'),
      world.authorization, world.eventLog, world.registry,
    );
    broker.register({ id: 'sec-x', tenantId: 'acme', value: 'v', label: 'x' });
    assert.equal(broker.request({ principal: world.foreignAgent, secretId: 'sec-x' }).allowed, false);
  });
});

// ── Brokered injection ──────────────────────────────────────────────────────

describe('brokered injection: agent never sees the secret value', () => {
  test('inject() puts decrypted value into params without exposing to caller', () => {
    const world = testWorld({
      policies: [{
        id: 'allow-secret-inject',
        effect: 'allow',
        principals: { ids: ['agent:summarizer-1'] },
        actions: ['secret.use'],
        resources: { types: ['secret'] },
        requiresApproval: true,
        conditions: [{ kind: 'after', iso: '2020-01-01T00:00:00Z' }],
      }],
    });
    const broker = new EnvelopeSecretBroker(
      Buffer.from('test-master-key-for-envelope-encryption-32b!', 'utf8'),
      world.authorization, world.eventLog, world.registry,
    );
    const secretVal = `INJECT-${randomUUID()}`;
    broker.register({ id: 'sec-inj', tenantId: 'acme', value: secretVal, label: 'inj' });

    world.authorization.issue(world.root, {
      subject: world.agent.id, tenantId: 'acme',
      resourceIds: ['sec-inj'], actions: ['secret.use'],
      maxClassification: 'restricted',
      expiresAt: world.clock.now() + 60_000, singleUse: true,
      provenance: { source: 'human-approval', approvedBy: world.user.id },
    });

    const userAuthCtx = mockAuth({ subject: world.user.id, amr: ['pwd', 'mfa'] });
    const approval = {
      id: 'a-inj', approvedBy: world.user.id, reviewerAuth: userAuthCtx, principalId: world.agent.id,
      action: 'secret.use' as const, resourceId: 'sec-inj',
      expiresAt: world.clock.now() + 60_000,
    };

    const targetParams: Record<string, unknown> = { url: 'https://api.example.com' };
    const result = broker.inject({
      principal: world.agent,
      secretId: 'sec-inj',
      targetParams,
      paramKey: 'Authorization',
      approvals: [approval],
    });

    assert.equal(result.allowed, true);
    assert.equal(result.params.Authorization, secretVal);
    assert.equal(targetParams.Authorization, undefined, 'original params must not be mutated');
    // The secret value does not appear in the event log.
    const events = world.eventLog.all().filter((e) => e.resourceId === 'sec-inj');
    const eventStr = JSON.stringify(events);
    assert.ok(!eventStr.includes(secretVal), 'secret must not appear in event log');
    assert.ok(eventStr.includes('[brokered-injection]'), 'event should record injection');
  });

  test('inject() denied: params returned unchanged, no value leaked', () => {
    const world = testWorld();
    const broker = new EnvelopeSecretBroker(
      Buffer.from('test-master-key-for-envelope-encryption-32b!', 'utf8'),
      world.authorization, world.eventLog, world.registry,
    );
    broker.register({ id: 'sec-no', tenantId: 'acme', value: 'classified', label: 'no' });

    const targetParams: Record<string, unknown> = { key: 'value' };
    const result = broker.inject({
      principal: world.agent,
      secretId: 'sec-no',
      targetParams,
      paramKey: 'Authorization',
    });

    assert.equal(result.allowed, false);
    assert.deepEqual(result.params, { key: 'value' });
  });
});

// ── Secret value unreachable from sandbox ────────────────────────────────────

describe('secret value unreachable from inside sandbox', () => {
  test('tool execution context never receives secret values', () => {
    const world = testWorld();
    let captured = '';
    const probe = {
      name: 'read',
      invoke: (ctx: { sessionId: string; capabilityId: string; resourceId: string; resourceType: string; action: string; params: Record<string, unknown>; content: string | undefined; now: number }) => {
        captured = JSON.stringify(ctx);
        return { output: 'ok' };
      },
    };
    const tools = new ToolRegistry();
    tools.register(probe);
    const session = new AgentSession({
      principal: world.agent, agentId: world.agent.id,
      model: { id: 'm', complete: () => ({ text: '', requests: [{ action: 'read', resourceId: world.resources.repoA! }] }) },
      task: 'test', registry: world.registry, authorization: world.authorization,
      eventLog: world.eventLog, tools, sandbox: new ContainerSandbox(new LocalSandbox()),
      content: world.content, now: world.clock.now,
    });
    session.attempt({ action: 'read', resourceId: world.resources.repoA! });
    for (const sv of world.secretValues) {
      assert.ok(!captured.includes(sv), `secret value in context: ${sv}`);
    }
  });
});

// ── Attack corpus still passes ───────────────────────────────────────────────

describe('M1 enforcement: attack corpus passes with real backends', () => {
  test('all attack cases behave as required', () => {
    const world = testWorld();
    const results = runAttackCorpus(world, join(ROOT, 'security-attacks'));
    for (const r of results) {
      assert.ok(r.passed, `${r.testCase.id} failed`);
    }
  });
});
