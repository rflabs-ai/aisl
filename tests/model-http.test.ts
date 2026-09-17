/**
 * M13: HttpModelAdapter (ADR-005) — egress gate, bounded retry, hostile-output
 * parsing, and the structural invariant that neither the API key nor planted
 * canaries ever reach the event log or an error message.
 */

import { test, describe } from 'node:test';
import assert from 'node:assert/strict';
import { defineResource } from '../src/registry.ts';
import { HttpModelAdapter, ModelEgressDeniedError, ModelProviderError } from '../src/model-http.ts';
import { ModelOutputError } from '../src/model.ts';
import { testWorld } from '../src/testing.ts';
import { TENANT_A, type World } from '../src/scenario.ts';
import type { Classification } from '../src/domain.ts';
import type { PolicyRule } from '../src/policy.ts';

const PROVIDER_RESOURCE = 'model:openai-compat';
const CANARY = 'CANARY-XYZ-PLANTED-MARKER';

/** Capability AND policy both gate egress: the baseline has no model.invoke rule. */
const MODEL_INVOKE_RULE: PolicyRule = {
  id: 'allow-agent-model-invoke',
  description: 'Agents may invoke the model provider resource.',
  effect: 'allow',
  principals: { kinds: ['agent'] },
  actions: ['model.invoke'],
  resources: { types: ['api'] },
};

function modelWorld(): World {
  return testWorld({ policies: [MODEL_INVOKE_RULE] });
}

interface FetchCall {
  readonly url: string;
  readonly headers: Headers;
  readonly init?: RequestInit;
}

/** Recording fetch mock: one factory per call in order; the last one repeats. */
function recordingFetch(responses: readonly (() => Response)[]): { fetch: typeof fetch; calls: FetchCall[] } {
  const calls: FetchCall[] = [];
  let i = 0;
  const f: typeof fetch = async (input, init) => {
    const make = responses[Math.min(i, responses.length - 1)];
    i++;
    if (!make) throw new TypeError('no response scripted');
    calls.push({ url: String(input), headers: new Headers(init?.headers), init });
    return make();
  };
  return { fetch: f, calls };
}

function okResponse(content: unknown, usage?: { prompt_tokens: number; completion_tokens: number }): Response {
  const body: Record<string, unknown> = {
    choices: [{ message: { content: JSON.stringify(content) } }],
  };
  if (usage) body.usage = usage;
  return new Response(JSON.stringify(body), { status: 200, headers: { 'content-type': 'application/json' } });
}

function registerProviderResource(world: ReturnType<typeof testWorld>): void {
  world.registry.add(
    defineResource({ id: PROVIDER_RESOURCE, type: 'api', tenantId: TENANT_A, classification: 'public', attributes: {} }),
  );
}

function modelCallEvents(world: ReturnType<typeof testWorld>) {
  return world.eventLog.all().filter((e) => e.action === 'model.call');
}

function issueModelInvoke(
  world: ReturnType<typeof testWorld>,
  maxClassification: Classification,
): void {
  world.authorization.issue(world.root, {
    subject: world.agent.id,
    tenantId: TENANT_A,
    resourceIds: [PROVIDER_RESOURCE],
    actions: ['model.invoke'],
    maxClassification,
    expiresAt: world.clock.now() + 600_000,
    provenance: { source: 'policy-grant', note: 'M13 provider egress' },
  });
}

interface TestTelemetry {
  readonly calls: { name: string; attrs: Readonly<Record<string, unknown>> }[];
  readonly emit: (name: string, attrs: Readonly<Record<string, unknown>>) => void;
}

function recordingTelemetry(): TestTelemetry {
  const calls: { name: string; attrs: Readonly<Record<string, unknown>> }[] = [];
  return { calls, emit: (name, attrs) => calls.push({ name, attrs }) };
}

function adapter(
  world: ReturnType<typeof testWorld>,
  fetchImpl: typeof fetch,
  overrides: Partial<ConstructorParameters<typeof HttpModelAdapter>[0]> = {},
): HttpModelAdapter {
  const telemetry = recordingTelemetry();
  return new HttpModelAdapter({
    id: 'openai-compat',
    providerModel: 'gpt-4o-mini',
    baseUrl: 'https://api.example.com/v1',
    apiKey: world.secretValues[0]!,
    principal: world.agent,
    authorization: world.authorization,
    registry: world.registry,
    eventLog: world.eventLog,
    ceiling: 'restricted',
    providerResourceId: PROVIDER_RESOURCE,
    content: world.content,
    fetchImpl,
    retryBackoffMs: 1,
    telemetry,
    ...overrides,
  });
}

describe('HttpModelAdapter: allow path', () => {
  test('completes, parses through the whitelist, records success event with usage', async () => {
    const world = modelWorld();
    registerProviderResource(world);
    issueModelInvoke(world, 'restricted');
    const { fetch: fetchImpl, calls } = recordingFetch([
      () => okResponse({ text: 'ok', requests: [] }, { prompt_tokens: 5, completion_tokens: 7 }),
    ]);
    const telemetry = recordingTelemetry();
    const a = adapter(world, fetchImpl, { telemetry });

    const out = await a.complete({ prompt: 'summarize', context: ['repo files'], availableActions: ['read'] });

    assert.deepEqual(out, { text: 'ok', requests: [] });
    assert.equal(calls.length, 1);
    assert.equal(calls[0]!.url, 'https://api.example.com/v1/chat/completions');
    assert.equal(calls[0]!.init?.method, 'POST');
    assert.equal(calls[0]!.headers.get('authorization'), `Bearer ${world.secretValues[0]}`);
    assert.equal(calls[0]!.headers.get('content-type'), 'application/json');

    const body: unknown = JSON.parse(String(calls[0]!.init?.body));
    assert.ok(typeof body === 'object' && body !== null);
    assert.ok('model' in body);
    assert.equal(body.model, 'gpt-4o-mini');

    const events = modelCallEvents(world);
    assert.equal(events.length, 1);
    const ev = events[0]!;
    assert.equal(ev.decision, 'allow');
    assert.equal(ev.result, 'success');
    const meta = ev.metadata ?? {};
    assert.equal(meta.usagePromptTokens, 5);
    assert.equal(meta.usageCompletionTokens, 7);
    assert.equal(meta.egress, 'allow');
    assert.equal(meta.phase, 'model');
    assert.equal(ev.resourceId, PROVIDER_RESOURCE);

    assert.equal(telemetry.calls.length, 1);
    assert.equal(telemetry.calls[0]!.name, 'model.call');
    assert.equal(telemetry.calls[0]!.attrs.result, 'success');
  });
});

describe('HttpModelAdapter: malformed provider output fails closed', () => {
  test('prose content (not JSON) throws, no output returned, error event recorded', async () => {
    const world = modelWorld();
    registerProviderResource(world);
    issueModelInvoke(world, 'restricted');
    const { fetch: fetchImpl, calls } = recordingFetch([
      () => new Response(JSON.stringify({ choices: [{ message: { content: 'This is prose, not JSON.' } }] }), { status: 200 }),
    ]);
    const a = adapter(world, fetchImpl);

    await assert.rejects(a.complete({ prompt: 'task', context: [], availableActions: [] }), ModelOutputError);
    assert.equal(calls.length, 1);
    const events = modelCallEvents(world);
    assert.equal(events.length, 1);
    assert.equal(events[0]!.result, 'error');
    assert.equal((events[0]!.metadata ?? {}).egress, 'parse-error');
  });

  test('HTTP 200 body without choices throws', async () => {
    const world = modelWorld();
    registerProviderResource(world);
    issueModelInvoke(world, 'restricted');
    const { fetch: fetchImpl } = recordingFetch([
      () => new Response(JSON.stringify({ object: 'chat.completion' }), { status: 200 }),
    ]);
    const a = adapter(world, fetchImpl);

    await assert.rejects(a.complete({ prompt: 'task', context: [], availableActions: [] }), ModelOutputError);
    const events = modelCallEvents(world);
    assert.equal(events[0]!.result, 'error');
  });
});

describe('HttpModelAdapter: bounded retry', () => {
  test('HTTP 500 twice then 200 succeeds via retry with fetch called 3x', async () => {
    const world = modelWorld();
    registerProviderResource(world);
    issueModelInvoke(world, 'restricted');
    const { fetch: fetchImpl, calls } = recordingFetch([
      () => new Response('boom', { status: 500 }),
      () => new Response('boom', { status: 500 }),
      () => okResponse({ text: 'recovered', requests: [] }),
    ]);
    const a = adapter(world, fetchImpl);

    const out = await a.complete({ prompt: 'task', context: [], availableActions: [] });
    assert.equal(out.text, 'recovered');
    assert.equal(calls.length, 3);
    const events = modelCallEvents(world);
    assert.equal(events[0]!.result, 'success');
  });

  test('HTTP 500 always throws ModelProviderError after maxRetries+1 attempts', async () => {
    const world = modelWorld();
    registerProviderResource(world);
    issueModelInvoke(world, 'restricted');
    const { fetch: fetchImpl, calls } = recordingFetch([() => new Response('boom', { status: 500 })]);
    const a = adapter(world, fetchImpl, { maxRetries: 2 });

    await assert.rejects(
      a.complete({ prompt: 'task', context: [], availableActions: [] }),
      (error: unknown) =>
        error instanceof ModelProviderError
        && error.message === 'provider call failed after 3 attempt(s): HTTP 500',
    );
    assert.equal(calls.length, 3);
    const events = modelCallEvents(world);
    assert.equal(events[0]!.result, 'error');
    assert.equal((events[0]!.metadata ?? {}).egress, 'provider-error');
  });

  test('fetch rejecting with TypeError is retryable, then fails with network error', async () => {
    const world = modelWorld();
    registerProviderResource(world);
    issueModelInvoke(world, 'restricted');
    const failing: typeof fetch = async () => {
      throw new TypeError('fetch failed');
    };
    const a = adapter(world, failing, { maxRetries: 1 });

    await assert.rejects(
      a.complete({ prompt: 'task', context: [], availableActions: [] }),
      (error: unknown) =>
        error instanceof ModelProviderError
        && error.message === 'provider call failed after 2 attempt(s): network error',
    );
    const events = modelCallEvents(world);
    assert.equal(events[0]!.result, 'error');
    assert.equal((events[0]!.metadata ?? {}).egress, 'provider-error');
  });
});

describe('HttpModelAdapter: egress classification ceiling (default-deny)', () => {
  test('derived classification above ceiling refuses before any fetch', async () => {
    const world = modelWorld();
    registerProviderResource(world);
    const { fetch: fetchImpl, calls } = recordingFetch([() => okResponse({ text: 'should never happen', requests: [] })]);
    const a = adapter(world, fetchImpl, { ceiling: 'internal' });

    await assert.rejects(
      a.complete({
        prompt: 'task',
        context: ['confidential text'],
        availableActions: [],
        contextResourceIds: ['doc:acme-merger'],
      }),
      ModelEgressDeniedError,
    );
    assert.equal(calls.length, 0, 'fetch must not be called when egress is refused at the ceiling');
    const events = modelCallEvents(world);
    assert.equal(events.length, 1);
    const ev = events[0]!;
    assert.equal(ev.decision, 'deny');
    assert.equal(ev.result, 'denied');
    assert.equal(ev.denyReason, 'classification-ceiling');
    assert.equal((ev.metadata ?? {}).egress, 'refused-above-ceiling');
  });
});

describe('HttpModelAdapter: PDP default-deny', () => {
  test('no model.invoke capability: egress denied, fetch not called, both events recorded', async () => {
    const world = modelWorld();
    registerProviderResource(world);
    const { fetch: fetchImpl, calls } = recordingFetch([() => okResponse({ text: 'should never be sent', requests: [] })]);
    const a = adapter(world, fetchImpl);

    await assert.rejects(
      a.complete({ prompt: 'task', context: [], availableActions: [] }),
      ModelEgressDeniedError,
    );
    assert.equal(calls.length, 0, 'fetch must not be called when the PDP denies');

    const events = modelCallEvents(world);
    assert.equal(events.length, 1);
    assert.equal(events[0]!.decision, 'deny');
    assert.equal(events[0]!.result, 'denied');
    assert.equal((events[0]!.metadata ?? {}).egress, 'pdp-denied');
    assert.equal((events[0]!.metadata ?? {}).denyReason, 'no-capability');

    const pdpEvents = world.eventLog.all().filter((e) => e.action === 'model.invoke');
    assert.equal(pdpEvents.length, 1, 'the PDP must append its own deny audit event');
    assert.equal(pdpEvents[0]!.decision, 'deny');
    assert.equal(pdpEvents[0]!.result, 'denied');
  });
});

describe('HttpModelAdapter: no secret or canary reaches events or errors', () => {
  test('event log and thrown errors never contain the api key or planted canary', async () => {
    const world = modelWorld();
    registerProviderResource(world);
    issueModelInvoke(world, 'restricted');

    const collectedErrors: string[] = [];
    const run = async (fetchImpl: typeof fetch, overrides: Partial<ConstructorParameters<typeof HttpModelAdapter>[0]> = {}) => {
      try {
        await adapter(world, fetchImpl, overrides).complete({
          prompt: 'task',
          context: [`Project Halcyon background text with ${CANARY} planted in it.`],
          availableActions: [],
          contextResourceIds: overrides?.ceiling === 'internal' ? ['doc:acme-merger'] : undefined,
        });
      } catch (error) {
        collectedErrors.push(String(error));
      }
    };

    await run(recordingFetch([() => okResponse({ text: 'ok', requests: [] })]).fetch);
    await run(recordingFetch([() => new Response('boom', { status: 500 })]).fetch, { maxRetries: 1 });
    await run(recordingFetch([() => new Response(JSON.stringify({ choices: [{ message: { content: 'prose, not JSON' } }] }), { status: 200 })]).fetch);
    await run(recordingFetch([() => okResponse({ text: 'ok', requests: [] })]).fetch, { ceiling: 'internal' });

    const logStr = JSON.stringify(world.eventLog.all());
    assert.ok(!logStr.includes(world.secretValues[0]!), 'api key leaked into the event log');
    assert.ok(!logStr.includes(CANARY), 'planted canary leaked into the event log');
    for (const message of collectedErrors) {
      assert.ok(!message.includes(world.secretValues[0]!), 'api key leaked into an error message');
      assert.ok(!message.includes(CANARY), 'planted canary leaked into an error message');
    }
    assert.equal(collectedErrors.length, 3, 'three of the four flows must have thrown');
  });
});

describe('HttpModelAdapter: end-to-end through the session', () => {
  test('session.run with the adapter returns provider text and enforced steps', async () => {
    const world = modelWorld();
    registerProviderResource(world);
    issueModelInvoke(world, 'restricted');
    const { fetch: fetchImpl, calls } = recordingFetch([
      () => okResponse({
        text: 'Repository A contains billing and invoice services.',
        requests: [{ action: 'read', resourceId: 'repo:acme/repo-a' }],
      }),
    ]);
    const a = adapter(world, fetchImpl);

    const trace = await world.session(a).run([]);

    assert.equal(trace.modelId, 'openai-compat');
    assert.equal(trace.modelText, 'Repository A contains billing and invoice services.');
    assert.equal(trace.steps.length, 1);
    assert.equal(trace.steps[0]!.request.action, 'read');
    assert.equal(trace.steps[0]!.decision.decision, 'allow');
    assert.equal(trace.steps[0]!.executed, true);
    assert.equal(calls.length, 1);
    assert.equal(modelCallEvents(world).length, 1);
    assert.equal(world.eventLog.verify().valid, true);
  });
});