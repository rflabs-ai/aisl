/**
 * Spend cap (safety ticket 04).
 *
 * A stranger can run this repository. What they must not be able to do is hand
 * a model provider an open-ended loop and a bill. Exhaustion refuses *before*
 * the fetch, so the refusal itself costs nothing.
 */

import { test, describe } from 'node:test';
import assert from 'node:assert/strict';
import { HttpModelAdapter, ModelEgressDeniedError, type ModelBudget } from '../src/model-http.ts';
import { testWorld } from '../src/testing.ts';
import { defineResource } from '../src/registry.ts';

const PROVIDER = 'model-provider:openai';
const DAY_ONE = Date.UTC(2026, 10, 1, 12, 0, 0);
const DAY_TWO = Date.UTC(2026, 10, 2, 12, 0, 0);

const MODEL_RULE = {
  id: 'test-allow-model-invoke',
  effect: 'allow' as const,
  principals: { kinds: ['agent' as const] },
  actions: ['model.invoke' as const],
  resources: { types: ['api' as const] },
};

function providerWorld() {
  const world = testWorld({ policies: [MODEL_RULE] });
  world.registry.add(
    defineResource({ id: PROVIDER, type: 'api', tenantId: 'acme', classification: 'restricted' }),
  );
  world.authorization.issue(world.root, {
    subject: world.agent.id,
    tenantId: 'acme',
    resourceIds: [PROVIDER],
    actions: ['model.invoke'],
    maxClassification: 'restricted',
    expiresAt: world.clock.now() + 600_000,
    provenance: { source: 'policy-grant' },
  });
  return world;
}

function okBody(): string {
  return JSON.stringify({
    choices: [{ message: { content: JSON.stringify({ text: 'ok', requests: [] }) } }],
    usage: { prompt_tokens: 5, completion_tokens: 7 },
  });
}

function adapter(
  world: ReturnType<typeof testWorld>,
  opts: { budget?: ModelBudget; now?: () => number; fetchImpl?: typeof fetch } = {},
) {
  let calls = 0;
  const a = new HttpModelAdapter({
    id: 'openai-compat',
    providerModel: 'gpt-4o-mini',
    baseUrl: 'https://api.example.com/v1',
    apiKey: 'test-key',
    principal: world.agent,
    authorization: world.authorization,
    registry: world.registry,
    eventLog: world.eventLog,
    ceiling: 'restricted',
    providerResourceId: PROVIDER,
    content: world.content,
    retryBackoffMs: 1,
    ...(opts.budget !== undefined ? { budget: opts.budget } : {}),
    ...(opts.now !== undefined ? { now: opts.now } : {}),
    fetchImpl:
      opts.fetchImpl ??
      ((async () => {
        calls += 1;
        return new Response(okBody(), { status: 200, headers: { 'content-type': 'application/json' } });
      }) as unknown as typeof fetch),
  });
  return { adapter: a, fetchCalls: () => calls };
}

const ask = (a: HttpModelAdapter) =>
  a.complete({ prompt: 'summarize', context: ['repo files'], availableActions: ['read'] });

describe('spend cap: the ceiling holds', () => {
  test('under budget the call goes through and is counted', async () => {
    const world = providerWorld();
    const { adapter: a } = adapter(world, { budget: { maxCallsPerDay: 5, maxTokensPerDay: 1000 } });
    const out = await ask(a);
    assert.equal(out.text, 'ok');
    const spend = a.spendSnapshot();
    assert.equal(spend.calls, 1);
    assert.equal(spend.tokens, 12, 'prompt + completion tokens reported by the provider');
  });

  test('the call cap refuses before the fetch — an exhausted budget cannot bill', async () => {
    const world = providerWorld();
    const { adapter: a, fetchCalls } = adapter(world, { budget: { maxCallsPerDay: 1, maxTokensPerDay: 1000 } });

    await ask(a);
    assert.equal(fetchCalls(), 1);

    await assert.rejects(() => ask(a), ModelEgressDeniedError);
    assert.equal(fetchCalls(), 1, 'no second request left the process');
    assert.equal(a.spendSnapshot().calls, 1);
  });

  test('the token cap refuses once the day is spent', async () => {
    const world = providerWorld();
    const { adapter: a, fetchCalls } = adapter(world, { budget: { maxCallsPerDay: 100, maxTokensPerDay: 10 } });

    await ask(a); // charges 12 tokens, over the 10 ceiling
    await assert.rejects(() => ask(a), /daily budget exhausted/);
    assert.equal(fetchCalls(), 1);
  });

  test('the refusal is evidence with a distinct reason', async () => {
    const world = providerWorld();
    const { adapter: a } = adapter(world, { budget: { maxCallsPerDay: 1, maxTokensPerDay: 1000 } });
    await ask(a);
    await assert.rejects(() => ask(a));

    const denied = world.eventLog.all().filter((e) => (e as { denyReason?: string }).denyReason === 'budget-exhausted');
    assert.equal(denied.length, 1);
    assert.ok(!JSON.stringify(denied).includes('test-key'), 'no credential in the refusal');
  });
});

describe('spend cap: the window', () => {
  test('a new day resets the counter', async () => {
    const world = providerWorld();
    let now = DAY_ONE;
    const { adapter: a, fetchCalls } = adapter(world, {
      budget: { maxCallsPerDay: 1, maxTokensPerDay: 1000 },
      now: () => now,
    });

    await ask(a);
    await assert.rejects(() => ask(a));

    now = DAY_TWO;
    const out = await ask(a); // a fresh day, a fresh call
    assert.equal(out.text, 'ok');
    assert.equal(fetchCalls(), 2);
    assert.equal(a.spendSnapshot().calls, 1);
  });

  test('no budget configured means no ceiling (documented default)', async () => {
    const world = providerWorld();
    const { adapter: a } = adapter(world);
    for (let i = 0; i < 3; i++) await ask(a);
    assert.equal(a.spendSnapshot().calls, 0, 'nothing is counted when no budget is set');
  });
});

describe('spend cap: silence cannot bypass it', () => {
  test('a provider that reports no usage still charges an estimate', async () => {
    const world = providerWorld();
    const noUsage = JSON.stringify({
      choices: [{ message: { content: JSON.stringify({ text: 'ok', requests: [] }) } }],
    });
    const { adapter: a } = adapter(world, {
      budget: { maxCallsPerDay: 5, maxTokensPerDay: 1000 },
      fetchImpl: (async () =>
        new Response(noUsage, { status: 200, headers: { 'content-type': 'application/json' } })) as unknown as typeof fetch,
    });

    await ask(a);
    assert.ok(a.spendSnapshot().tokens > 0, 'an unreported usage is estimated, not free');
  });
});
