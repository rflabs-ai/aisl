/**
 * H5 — malicious tool handling (ADR-038).
 *
 * Three failure modes are addressable without a kernel: a tool that expands its
 * own scope through request params, a tool that exhausts resources, and a tool
 * whose result the session cannot trust. Sandbox escape is not among them — the
 * in-process sandbox has no isolation by design (ADR-003), and real containment
 * is Stage 3.
 */

import { test, describe } from 'node:test';
import assert from 'node:assert/strict';
import { AgentSession, LocalSandbox, DEFAULT_TOOL_QUOTA } from '../src/runtime.ts';
import { ScriptedModel } from '../src/model.ts';
import { testWorld } from '../src/testing.ts';
import type { PolicyRule } from '../src/policy.ts';

const writeRule: PolicyRule = {
  id: 'test-allow-agent-write',
  effect: 'allow',
  principals: { kinds: ['agent'] },
  actions: ['write'],
  resources: { maxClassification: 'internal' },
};

function session(world: ReturnType<typeof testWorld>, quota = DEFAULT_TOOL_QUOTA) {
  return new AgentSession({
    principal: world.agent,
    agentId: world.agent.id,
    model: new ScriptedModel('h5-model', []),
    task: 'write',
    registry: world.registry,
    authorization: world.authorization,
    eventLog: world.eventLog,
    tools: world.tools,
    sandbox: new LocalSandbox(),
    content: new Map<string, string>(),
    quota,
    now: world.clock.now,
    guard: null,
  });
}

function grant(world: ReturnType<typeof testWorld>, action: 'write') {
  const targetId = world.resources.internalDoc!;
  world.authorization.issue(world.root, {
    subject: world.agent.id,
    tenantId: 'acme',
    resourceIds: [targetId],
    actions: [action],
    maxClassification: 'internal',
    expiresAt: world.clock.now() + 60_000,
    provenance: { source: 'policy-grant' },
  });
  return targetId;
}

describe('H5: a tool cannot take scope from request params', () => {
  test('a params key naming authority is refused before the tool runs', () => {
    const world = testWorld({ policies: [writeRule] });
    const targetId = grant(world, 'write');
    let invoked = false;
    world.tools.register({ name: 'write', invoke: () => { invoked = true; return { changed: true }; } });

    const step = session(world).attempt({
      action: 'write',
      resourceId: targetId,
      params: { resourceId: 'db:acme-phi-synthetic' },
    });

    assert.equal(step.executed, false);
    assert.match(step.error ?? '', /authority keys: resourceId/);
    assert.equal(invoked, false, 'the tool never ran');
  });

  test('ordinary params are untouched', () => {
    const world = testWorld({ policies: [writeRule] });
    const targetId = grant(world, 'write');
    let seen: unknown;
    world.tools.register({ name: 'write', invoke: (ctx) => { seen = ctx.params; return { changed: true }; } });

    const step = session(world).attempt({ action: 'write', resourceId: targetId, params: { mode: 'append' } });
    assert.equal(step.executed, true);
    assert.deepEqual(seen, { mode: 'append' });
  });
});

describe('H5: resource exhaustion', () => {
  test('an oversized params payload is refused before the tool runs', () => {
    const world = testWorld({ policies: [writeRule] });
    const targetId = grant(world, 'write');
    let invoked = false;
    world.tools.register({ name: 'write', invoke: () => { invoked = true; return { changed: true }; } });

    const step = session(world, { ...DEFAULT_TOOL_QUOTA, maxParamBytes: 64 }).attempt({
      action: 'write',
      resourceId: targetId,
      params: { blob: 'x'.repeat(200) },
    });

    assert.equal(step.executed, false);
    assert.match(step.error ?? '', /params exceed 64 bytes/);
    assert.equal(invoked, false);
  });

  test('an oversized output is detected and recorded as a failed verification', () => {
    const world = testWorld({ policies: [writeRule] });
    const targetId = grant(world, 'write');
    world.tools.register({ name: 'write', invoke: () => ({ output: 'x'.repeat(500), changed: true }) });

    const step = session(world, { ...DEFAULT_TOOL_QUOTA, maxOutputBytes: 128 }).attempt({
      action: 'write',
      resourceId: targetId,
    });

    assert.equal(step.executed, true, 'the tool ran; the breach is detected, not prevented');
    const finding = step.verifications.find((v) => v.test === 'tool-quota');
    assert.ok(finding, 'a quota breach is evidence');
    assert.equal(finding.result, 'fail');
    assert.match(finding.evidence, /output 500 bytes > 128/);

    const events = world.eventLog.all();
    assert.ok(events.some((e) => e.result === 'error'));
  });

  test('a slow tool is detected against the duration budget', () => {
    const world = testWorld({ policies: [writeRule] });
    const targetId = grant(world, 'write');
    let clock = 1000;
    const sessionWithClock = new AgentSession({
      principal: world.agent,
      agentId: world.agent.id,
      model: new ScriptedModel('h5-clock', []),
      task: 'write',
      registry: world.registry,
      authorization: world.authorization,
      eventLog: world.eventLog,
      tools: world.tools,
      sandbox: new LocalSandbox(),
      content: new Map<string, string>(),
      quota: { ...DEFAULT_TOOL_QUOTA, maxDurationMs: 5 },
      now: () => clock,
      guard: null,
    });
    world.tools.register({ name: 'write', invoke: () => { clock += 500; return { changed: true }; } });

    const step = sessionWithClock.attempt({ action: 'write', resourceId: targetId });
    const finding = step.verifications.find((v) => v.test === 'tool-quota');
    assert.ok(finding);
    assert.match(finding.evidence, /duration 500ms > 5ms/);
  });
});
