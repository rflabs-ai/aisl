/**
 * M16 acceptance: sandbox lifecycle management (ADR-021).
 *
 * Create/limit/destroy/attest round trips, sealed attestation payloads with
 * digest-only plaintext metadata, tenant-scoped refusals, PDP-gated execute,
 * and the process-exit sweep. Runs against the real ContainerSandbox (whose
 * honest Docker-or-fallback kind covers the LocalSandbox fallback path).
 */

import { test, describe } from 'node:test';
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { ContainerSandbox, effectiveLimits, resetDockerCache } from '../src/container-sandbox.ts';
import { SandboxRegistry, SANDBOX_EXECUTE_ACTION, UnknownSandboxError } from '../src/sandbox-registry.ts';
import { ResourceRegistry, defineResource } from '../src/registry.ts';
import { EventLog } from '../src/events.ts';
import { createPolicyEngine, BASELINE_POLICY, type PolicyRule } from '../src/policy.ts';
import { AuthorizationService, authorizationRoot } from '../src/pdp.ts';
import { keyIdForTenant, open, type Sealed } from '../src/seal.ts';
import { canonicalJson } from '../src/domain.ts';
import { LocalSandbox, type Tool } from '../src/runtime.ts';
import { testWorld } from '../src/testing.ts';
import { TENANT_A, TENANT_B } from '../src/scenario.ts';

const echoTool: Tool = {
  name: 'sandbox.echo',
  invoke: (ctx) => ({ output: `echo:${ctx.params.msg ?? 'none'}` }),
};

function makeRegistry() {
  const registry = new ResourceRegistry();
  const eventLog = new EventLog();
  const policy = createPolicyEngine(BASELINE_POLICY);
  const authorization = new AuthorizationService(registry, policy, eventLog);
  const sandboxes = new SandboxRegistry({
    registry,
    eventLog,
    authorization,
    actorId: 'user:alice',
    actorKind: 'user',
  });
  return { registry, eventLog, authorization, sandboxes, root: authorizationRoot(TENANT_A) };
}

describe('SandboxRegistry create/destroy round trip', () => {
  test('create registers a tenant-bound resource, records a sealed event, destroy tears down', () => {
    const { registry, eventLog, sandboxes } = makeRegistry();
    const handle = sandboxes.create({ tenantId: TENANT_A, sandboxId: 'task-1' });
    assert.equal(handle.id, `sandbox:${TENANT_A}:task-1`);
    assert.equal(handle.kind, new ContainerSandbox(new LocalSandbox()).kind, 'kind must be honest about Docker-or-fallback');

    const resource = registry.require(handle.id);
    assert.equal(resource.type, 'system');
    assert.equal(resource.tenantId, TENANT_A);
    assert.equal(resource.classification, 'public');

    const createEvent = eventLog.all().filter((e) => e.action === 'sandbox.create').at(-1)!;
    assert.equal(createEvent.resourceId, handle.id);
    assert.equal(createEvent.decision, 'allow');
    assert.ok(createEvent.metadata!.sealed, 'create event carries a sealed payload');
    assert.ok(createEvent.metadata!.limitsDigest, 'create event carries a limit digest');

    assert.equal(sandboxes.get(TENANT_A, 'task-1'), handle);
    sandboxes.destroy(TENANT_A, 'task-1');
    assert.equal(sandboxes.get(TENANT_A, 'task-1'), undefined, 'destroyed sandbox reads as absent');
    assert.deepEqual(sandboxes.list(TENANT_A), []);

    const destroyEvent = eventLog.all().filter((e) => e.action === 'sandbox.destroy').at(-1)!;
    assert.equal(destroyEvent.resourceId, handle.id);
    const payload = JSON.parse(open(destroyEvent.metadata!.sealed as Sealed)!);
    assert.equal(payload.id, handle.id);
    assert.ok(typeof payload.durationMs === 'number');
  });

  test('duplicate create refuses; destroy on unknown id refuses; destroy is idempotent', () => {
    const { sandboxes } = makeRegistry();
    sandboxes.create({ tenantId: TENANT_A, sandboxId: 'dup' });
    assert.throws(() => sandboxes.create({ tenantId: TENANT_A, sandboxId: 'dup' }), /already exists/);
    assert.throws(() => sandboxes.destroy(TENANT_A, 'never-created'), UnknownSandboxError);
    sandboxes.destroy(TENANT_A, 'dup');
    sandboxes.destroy(TENANT_A, 'dup'); // sweep + explicit destroy must not race into a throw
  });
});

describe('SandboxRegistry tenant isolation', () => {
  test('cross-tenant get returns undefined; cross-tenant destroy refuses', () => {
    const { sandboxes } = makeRegistry();
    sandboxes.create({ tenantId: TENANT_A, sandboxId: 'acme-only' });
    assert.equal(sandboxes.get(TENANT_B, 'acme-only'), undefined);
    assert.throws(() => sandboxes.destroy(TENANT_B, 'acme-only'), UnknownSandboxError);
    assert.deepEqual(sandboxes.list(TENANT_B), []);
    assert.deepEqual(sandboxes.list(TENANT_A).map((h) => h.name), ['acme-only']);
  });

  test('the resource registry is the tenant authority: a re-bound resource flips the verdict', () => {
    const { registry, eventLog, sandboxes } = makeRegistry();
    sandboxes.create({ tenantId: TENANT_A, sandboxId: 'binding' });
    registry.add(
      defineResource({ id: `sandbox:${TENANT_A}:binding`, type: 'system', tenantId: TENANT_B, classification: 'public' }),
    );
    assert.throws(() => sandboxes.get(TENANT_A, 'binding'), /belongs to tenant/);
    assert.equal(eventLog.all().filter((e) => e.action === 'sandbox.destroy').length, 0);
  });
});

describe('SandboxRegistry limits + attestation', () => {
  test('limits digest covers declared config; sealed payload carries effective limits', () => {
    const { eventLog, sandboxes } = makeRegistry();
    const limits = { memoryLimit: '64m', pidsLimit: 32 };
    sandboxes.create({ tenantId: TENANT_A, sandboxId: 'limited', limits });

    const createEvent = eventLog.all().filter((e) => e.action === 'sandbox.create').at(-1)!;
    const digest = createEvent.metadata!.limitsDigest as string;
    const expected = createHash('sha256').update(canonicalJson({ limits, kind: createEvent.metadata!.kind })).digest('hex');
    assert.equal(digest, expected);

    const sealed = createEvent.metadata!.sealed as { keyId: string };
    assert.equal(sealed.keyId, keyIdForTenant(TENANT_A, 'public'));
    const payload = JSON.parse(open(sealed as Sealed)!);
    assert.deepEqual(payload.limits, limits, 'declared limits sealed');
    assert.deepEqual(payload.effectiveLimits, effectiveLimits(limits), 'effective limits sealed (defaults included)');
    assert.equal(payload.effectiveLimits.pidsLimit, 32);
  });

  test('attest records sealed current state; plaintext payload never enters the log', () => {
    const { eventLog, sandboxes } = makeRegistry();
    const canary = 'ATTEST-PLAINTEXT-CANARY-4c1d';
    sandboxes.create({ tenantId: TENANT_A, sandboxId: 'attested', limits: { timeoutMs: 1_000 } });
    const { sealed, digest } = sandboxes.attest(TENANT_A, 'attested');

    const attestEvent = eventLog.all().filter((e) => e.action === 'sandbox.attest').at(-1)!;
    assert.equal(attestEvent.resourceId, `sandbox:${TENANT_A}:attested`);
    assert.equal(attestEvent.metadata!.sealed, sealed);
    assert.equal(attestEvent.metadata!.limitsDigest, digest);

    const payload = JSON.parse(open(sealed as Sealed)!);
    assert.ok(payload.uptimeMs >= 0);
    assert.equal(payload.effectiveLimits.timeoutMs, 1_000);
    assert.equal(sealed.keyId, keyIdForTenant(TENANT_A, 'public'));

    assert.throws(() => sandboxes.attest(TENANT_A, 'not-there'), UnknownSandboxError);
    assert.equal(JSON.stringify(eventLog.all()).includes(canary), false, 'no plaintext payload in the event log');
  });
});

describe('SandboxRegistry execute is PDP-gated', () => {
  const allowExecute: PolicyRule = {
    id: 'allow-agent-sandbox-execute',
    effect: 'allow',
    principals: { kinds: ['agent'] },
    actions: [SANDBOX_EXECUTE_ACTION],
    resources: { ids: [`sandbox:${TENANT_A}:runnable`] },
  };

  test('no capability -> no execution', () => {
    const world = testWorld();
    const sandboxes = new SandboxRegistry({
      registry: world.registry,
      eventLog: world.eventLog,
      authorization: world.authorization,
      actorId: world.root.id,
      actorKind: world.root.kind,
    });
    sandboxes.create({ tenantId: TENANT_A, sandboxId: 'gated' });
    const result = sandboxes.execute({ tenantId: TENANT_A, sandboxId: 'gated', principal: world.agent, tool: echoTool });
    assert.equal(result.executed, false);
    assert.match(result.reason, /no capability|not allowlisted|policy/);
    world.eventLog.close();
  });

  test('capability + policy -> tool runs inside the sandbox (Docker or honest fallback)', () => {
    resetDockerCache();
    const world = testWorld({ policies: [allowExecute] });
    const sandboxes = new SandboxRegistry({
      registry: world.registry,
      eventLog: world.eventLog,
      authorization: world.authorization,
      actorId: world.root.id,
      actorKind: world.root.kind,
    });
    sandboxes.create({ tenantId: TENANT_A, sandboxId: 'runnable', limits: { timeoutMs: 5_000 } });
    world.authorization.issue(world.root, {
      subject: world.agent.id,
      tenantId: TENANT_A,
      resourceIds: [`sandbox:${TENANT_A}:runnable`],
      actions: [SANDBOX_EXECUTE_ACTION],
      maxClassification: 'public',
      expiresAt: world.clock.now() + 60_000,
      provenance: { source: 'policy-grant', note: 'M16: sandbox execute' },
    });
    const result = sandboxes.execute({
      tenantId: TENANT_A,
      sandboxId: 'runnable',
      principal: world.agent,
      tool: echoTool,
      params: { msg: 'hi' },
    });
    assert.equal(result.executed, true, `reason: ${result.reason}`);
    assert.equal(result.output, 'echo:hi');
    const decisionEvent = world.eventLog.all().filter((e) => e.action === SANDBOX_EXECUTE_ACTION && e.decision === 'allow').at(-1)!;
    assert.equal(decisionEvent.resourceId, `sandbox:${TENANT_A}:runnable`);
    world.eventLog.close();
  });
});

describe('SandboxRegistry exit sweep', () => {
  test('sweep destroys every active sandbox and records the evidence', () => {
    const { eventLog, sandboxes } = makeRegistry();
    sandboxes.create({ tenantId: TENANT_A, sandboxId: 'sweep-a' });
    sandboxes.create({ tenantId: TENANT_A, sandboxId: 'sweep-b' });
    const swept = sandboxes.sweepExit();
    assert.deepEqual([...swept].sort(), [`sandbox:${TENANT_A}:sweep-a`, `sandbox:${TENANT_A}:sweep-b`]);
    assert.deepEqual(sandboxes.list(TENANT_A), []);
    const destroyEvents = eventLog.all().filter((e) => e.action === 'sandbox.destroy');
    assert.equal(destroyEvents.length, 2);
    assert.equal(sandboxes.sweepExit().length, 0, 'second sweep is a no-op');
  });
});

describe('M16 invariant: no secrets in lifecycle events', () => {
  test('event log shows digest + sealed only; payload opens under the tenant key', () => {
    const { eventLog, sandboxes } = makeRegistry();
    sandboxes.create({ tenantId: TENANT_A, sandboxId: 'seal-scan', limits: { pidsLimit: 8 } });
    sandboxes.attest(TENANT_A, 'seal-scan');
    sandboxes.destroy(TENANT_A, 'seal-scan');
    for (const e of eventLog.all().filter((e) => e.action.startsWith('sandbox.'))) {
      const meta = e.metadata as { sealed?: { ciphertext: string }; limitsDigest?: string };
      assert.ok(meta.sealed, `${e.action} carries a sealed payload`);
      assert.ok(meta.limitsDigest, `${e.action} carries a digest`);
      const plaintext = JSON.parse(open(meta.sealed as Sealed)!) as Record<string, unknown>;
      assert.ok(plaintext.pid, 'sealed payload records the runtime pid');
    }
  });
});

