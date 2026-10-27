/**
 * H7 — content-level egress DLP (ADR-037).
 *
 * The claim is narrow and testable: a canary value does not leave, in any of
 * the cheap encodings, and a refusal never repeats what it caught.
 */

import { test, describe } from 'node:test';
import assert from 'node:assert/strict';
import { inspectEgress, scanForCanaries, tokenEncodings, type Canary } from '../src/dlp.ts';
import { combine, taintFor, UNKNOWN_TAINT } from '../src/taint.ts';
import { testWorld } from '../src/testing.ts';
import { defineResource } from '../src/registry.ts';
import { HttpModelAdapter } from '../src/model-http.ts';
import { EgressProxy } from '../src/egress-proxy.ts';

const CANARY: Canary = { token: 'CANARY-phi-7f3a2b91', classification: 'phi' };
const PUBLIC = combine(taintFor('doc:public', 'public'));

const b64 = (s: string) => Buffer.from(s, 'utf8').toString('base64');

describe('H7: canaries are caught raw and encoded', () => {
  test('the token matches in every cheap encoding', () => {
    const encodings = tokenEncodings(CANARY.token);
    assert.ok(encodings.length >= 5);
    for (const encoded of encodings) {
      const payload = `context: ${encoded} end`;
      assert.equal(scanForCanaries(payload, [CANARY]).length, 1, `missed encoding: ${encoded}`);
    }
  });

  test('a fully base64-encoded body is decoded once before matching', () => {
    const body = b64(`patient_id,diagnosis\n0001,E11.9\n${CANARY.token}\n`);
    assert.equal(scanForCanaries(body, [CANARY]).length, 1);
  });

  test('a fully hex-encoded body is decoded once before matching', () => {
    const body = Buffer.from(`x ${CANARY.token} y`, 'utf8').toString('hex');
    assert.equal(scanForCanaries(body, [CANARY]).length, 1);
  });

  test('a canary nested in JSON is caught', () => {
    const payload = JSON.stringify({ a: { b: [{ note: CANARY.token }] } });
    assert.equal(scanForCanaries(payload, [CANARY]).length, 1);
  });

  test('an unrelated payload is clean, and short tokens are ignored', () => {
    assert.equal(scanForCanaries('{"task":"summarize the invoice"}', [CANARY]).length, 0);
    assert.equal(scanForCanaries('abc', [{ token: 'ab', classification: 'phi' }]).length, 0);
  });
});

describe('H7: a refusal never repeats what it caught', () => {
  test('no reason or detail contains the token, raw or encoded', () => {
    const payload = `leak ${CANARY.token}`;
    const verdict = inspectEgress({ payload, label: PUBLIC, ceiling: 'restricted', canaries: [CANARY] });
    assert.equal(verdict.allow, false);
    const rendered = JSON.stringify(verdict);
    for (const encoded of tokenEncodings(CANARY.token)) {
      assert.ok(!rendered.includes(encoded), `verdict leaked ${encoded}`);
    }
    assert.match(verdict.reason, /^canary:phi$/);
  });
});

describe('H7: the classification check is authoritative', () => {
  test('a payload above the ceiling is refused even with a clean canary scan', () => {
    const verdict = inspectEgress({
      payload: 'nothing suspicious here',
      label: taintFor('doc:phi', 'phi'),
      ceiling: 'internal',
      canaries: [CANARY],
    });
    assert.equal(verdict.allow, false);
    assert.equal(verdict.reason, 'payload:phi');
    assert.equal(verdict.findings[0]!.kind, 'above-ceiling');
  });

  test('an unknown-provenance label cannot leave', () => {
    const verdict = inspectEgress({ payload: 'x', label: UNKNOWN_TAINT, ceiling: 'restricted' });
    assert.equal(verdict.allow, false);
    assert.equal(verdict.reason, 'payload:x-unknown-source');
  });

  test('a clean payload within the ceiling is allowed', () => {
    const verdict = inspectEgress({ payload: 'summarize this', label: PUBLIC, ceiling: 'internal' });
    assert.equal(verdict.allow, true);
    assert.equal(verdict.reason, 'egress-allow');
    assert.deepEqual(verdict.findings, []);
  });
});

describe('H7: the model call is an egress', () => {
  test('a canary in the outbound context is refused before any fetch', async () => {
    const world = testWorld();
    const providerResource = 'model-provider:openai';
    world.registry.add(
      defineResource({ id: providerResource, type: 'api', tenantId: 'acme', classification: 'restricted' }),
    );
    world.authorization.issue(world.root, {
      subject: world.agent.id,
      tenantId: 'acme',
      resourceIds: [providerResource],
      actions: ['model.invoke'],
      maxClassification: 'restricted',
      expiresAt: world.clock.now() + 600_000,
      provenance: { source: 'policy-grant' },
    });

    let fetched = 0;
    const adapter = new HttpModelAdapter({
      id: 'openai-compat',
      providerModel: 'gpt-4o-mini',
      baseUrl: 'https://api.example.com/v1',
      apiKey: 'test-key',
      principal: world.agent,
      authorization: world.authorization,
      registry: world.registry,
      eventLog: world.eventLog,
      ceiling: 'restricted',
      providerResourceId: providerResource,
      content: world.content,
      canaries: [CANARY],
      fetchImpl: (async () => {
        fetched++;
        return new Response('{}', { status: 200 });
      }) as unknown as typeof fetch,
    });

    await assert.rejects(
      () => adapter.complete({ prompt: 'summarize', context: [`meeting notes ${CANARY.token}`], availableActions: ['read'] }),
      /model egress refused: canary:phi/,
    );
    assert.equal(fetched, 0, 'no bytes left the process');

    // The refusal is evidence, and it does not carry the value.
    const events = world.eventLog.all().filter((e) => e.action === 'model.call');
    const denied = events.filter((e) => e.decision === 'deny');
    assert.ok(denied.length >= 1);
    assert.ok(!JSON.stringify(denied).includes(CANARY.token));
  });
});

describe('H7: the HTTP proxy inspects the body it forwards', () => {
  test('an allowlisted destination still cannot receive a canary', async () => {
    const world = testWorld();
    const proxy = new EgressProxy(world.agent, world.authorization, world.registry, world.eventLog, {
      dnsPin: false,
      canaries: [CANARY],
    });
    assert.equal((await proxy.check('api.internal.example.com')).allowed, true, 'the destination is allowed');

    const verdict = proxy.inspectBody(`POST data: ${btoa(CANARY.token)}`);
    assert.equal(verdict.allow, false);
    assert.equal(verdict.reason, 'canary:phi');
    assert.ok(!JSON.stringify(verdict).includes(CANARY.token));
  });

  test('a clean body to an allowlisted host passes inspection', async () => {
    const world = testWorld();
    const proxy = new EgressProxy(world.agent, world.authorization, world.registry, world.eventLog, { dnsPin: false });
    assert.equal(proxy.inspectBody('{"query":"invoice total"}').allow, true);
  });
});

describe('H7: volume', () => {
  test('a payload over the byte cap is refused and the size is reported', () => {
    const verdict = inspectEgress({ payload: 'x'.repeat(2048), label: PUBLIC, ceiling: 'internal', maxBytes: 1024 });
    assert.equal(verdict.allow, false);
    assert.equal(verdict.findings[0]!.kind, 'volume');
    assert.equal(verdict.bytes, 2048);
    assert.match(verdict.reason, /^volume:2048>1024$/);
  });

  test('multi-byte characters count as bytes, not characters', () => {
    const verdict = inspectEgress({ payload: 'é'.repeat(10), label: PUBLIC, ceiling: 'internal', maxBytes: 10 });
    assert.equal(verdict.bytes, 20);
    assert.equal(verdict.allow, false);
  });
});
