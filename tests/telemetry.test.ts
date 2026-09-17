/**
 * M13 telemetry tests: structured telemetry is observability, never a control.
 *
 * Guards: JSONL emission shape, swallow-and-count failure semantics, session
 * wiring (ids/counts/durations only), and the dependency direction — the PDP
 * never imports telemetry, and the runtime's TelemetryPort import is type-only.
 */

import { test, describe } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { JsonlTelemetry, denyReasonCounts } from '../src/telemetry.ts';
import { AgentSession, LocalSandbox } from '../src/runtime.ts';
import { ContainerSandbox } from '../src/container-sandbox.ts';
import { ScriptedModel } from '../src/model.ts';
import { testWorld } from '../src/testing.ts';

const ROOT = join(dirname(fileURLToPath(import.meta.url)), '..');

describe('JsonlTelemetry emission', () => {
  test('emits one valid JSON object per line with ts, name, and attrs', () => {
    const lines: string[] = [];
    const t = new JsonlTelemetry((l) => lines.push(l));
    t.emit('test.event', { sessionId: 's1', count: 2 });

    assert.equal(lines.length, 1);
    const parsed = JSON.parse(lines[0]!) as Record<string, unknown>;
    assert.equal(parsed['name'], 'test.event');
    assert.equal(typeof parsed['ts'], 'number');
    assert.equal(parsed['sessionId'], 's1');
    assert.equal(parsed['count'], 2);
  });

  test('emission failure never throws into the caller; dropped counts it', () => {
    const t = new JsonlTelemetry(() => {
      throw new Error('sink down');
    });
    t.emit('a', {});
    t.emit('b', {});
    assert.equal(t.dropped, 2, 'both failed emissions counted');
  });

  test('unserializable attrs are swallowed and counted, caller continues', () => {
    const lines: string[] = [];
    const t = new JsonlTelemetry((l) => lines.push(l));
    const circular: Record<string, unknown> = {};
    circular['self'] = circular;
    t.emit('bad', { circular });
    assert.equal(t.dropped, 1);
    assert.equal(lines.length, 0);
    t.emit('good', { ok: 1 });
    assert.equal(lines.length, 1);
  });
});

describe('denyReasonCounts', () => {
  test('counts deny reasons only for deny decisions', () => {
    assert.deepEqual(
      denyReasonCounts([
        { decision: 'allow' },
        { decision: 'deny', denyReason: 'no-capability' },
        { decision: 'deny', denyReason: 'no-capability' },
        { decision: 'deny', denyReason: 'tenant-mismatch' },
      ]),
      { 'no-capability': 2, 'tenant-mismatch': 1 },
    );
  });

  test('empty input yields empty counts', () => {
    assert.deepEqual(denyReasonCounts([]), {});
  });
});

describe('session telemetry wiring', () => {
  test('session.start, session.end, and pdp.denyReasons carry ids/counts/durations only', async () => {
    const world = testWorld();
    const lines: string[] = [];
    const telemetry = new JsonlTelemetry((l) => lines.push(l));
    const model = new ScriptedModel('scripted-telemetry-v1', [
      {
        text: 'Reading the repository and a foreign document.',
        requests: [
          { action: 'read', resourceId: world.resources.repoA! },
          { action: 'read', resourceId: world.resources.foreignDoc! },
        ],
      },
    ]);
    const session = new AgentSession({
      principal: world.agent,
      agentId: world.agent.id,
      model,
      task: 'Summarize repository A.',
      registry: world.registry,
      authorization: world.authorization,
      eventLog: world.eventLog,
      tools: world.tools,
      sandbox: new ContainerSandbox(new LocalSandbox()),
      content: world.content,
      checks: [],
      canaries: world.secretValues,
      now: world.clock.now,
      telemetry,
    });

    const trace = await session.run([]);
    assert.equal(trace.steps[1]?.decision.decision, 'deny');
    assert.equal(trace.steps[1]?.decision.denyReason, 'tenant-mismatch');

    const parsed = lines.map((l) => JSON.parse(l) as Record<string, unknown>);
    const start = parsed.find((p) => p['name'] === 'session.start');
    const end = parsed.find((p) => p['name'] === 'session.end');
    assert.ok(start, 'session.start line missing');
    assert.equal(start!['sessionId'], session.sessionId);
    assert.equal(start!['principal'], world.agent.id);
    assert.equal(start!['agentId'], world.agent.id);
    assert.equal(start!['model'], model.id);
    assert.ok(end, 'session.end line missing');
    const durationMs = end!['durationMs'] as number;
    assert.ok(typeof durationMs === 'number' && durationMs >= 0, `durationMs=${String(end!['durationMs'])}`);
    assert.equal(end!['allowed'], 1);
    assert.equal(end!['denied'], 1);
    assert.equal(end!['requests'], 2);

    const reasons = parsed.find((p) => p['name'] === 'pdp.denyReasons');
    assert.ok(reasons, 'pdp.denyReasons line missing');
    assert.equal((reasons!['counts'] as Record<string, number>)['tenant-mismatch'], 1);
  });

  test('no emitted line contains canaries, model text, or task text', async () => {
    const world = testWorld();
    const lines: string[] = [];
    const telemetry = new JsonlTelemetry((l) => lines.push(l));
    const canary = world.secretValues[0]!;
    const modelMarker = 'LEAKY-MODEL-TEXT-MARKER-9f2';
    const taskMarker = 'SECRET-TASK-TEXT-MARKER-4c7';
    const model = new ScriptedModel('leaky-model', [
      {
        text: `I found ${canary} and ${modelMarker} in the context.`,
        requests: [{ action: 'read', resourceId: world.resources.repoA! }],
      },
    ]);
    const session = new AgentSession({
      principal: world.agent,
      agentId: world.agent.id,
      model,
      task: `Do ${taskMarker} now.`,
      registry: world.registry,
      authorization: world.authorization,
      eventLog: world.eventLog,
      tools: world.tools,
      sandbox: new ContainerSandbox(new LocalSandbox()),
      content: world.content,
      checks: [],
      canaries: world.secretValues,
      now: world.clock.now,
      telemetry,
    });

    await session.run([]);

    assert.ok(lines.length > 0, 'telemetry should have emitted lines');
    for (const line of lines) {
      assert.ok(!line.includes(canary), 'canary leaked to telemetry');
      assert.ok(!line.includes(modelMarker), 'model text leaked to telemetry');
      assert.ok(!line.includes(taskMarker), 'task text leaked to telemetry');
    }
  });
});

describe('dependency direction (R3 spirit)', () => {
  test('the PDP never reads telemetry', () => {
    const pdpSrc = readFileSync(join(ROOT, 'src', 'pdp.ts'), 'utf8');
    assert.ok(!pdpSrc.includes('./telemetry.ts'), 'pdp.ts must not import telemetry');
  });

  test('runtime imports TelemetryPort type-only from telemetry', () => {
    const runtimeSrc = readFileSync(join(ROOT, 'src', 'runtime.ts'), 'utf8');
    assert.ok(
      runtimeSrc.includes("import { type TelemetryPort } from './telemetry.ts';"),
      'runtime.ts must import TelemetryPort as a type-only import',
    );
  });
});
