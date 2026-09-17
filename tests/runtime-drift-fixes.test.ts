/**
 * M9 drift fixes read back from the event log: `metadata.sealed` is a raw
 * `Sealed` object (drift #2) and `metadata.ladderRung` records the rung that
 * fired (drift #3).
 */

import { test, describe } from 'node:test';
import assert from 'node:assert/strict';
import { ScriptedModel } from '../src/model.ts';
import { testWorld } from '../src/testing.ts';

interface GuardMetadata {
  readonly phase?: string;
  readonly status?: string;
  readonly ladderRung?: string | null;
  readonly sealed?: {
    readonly keyId?: string;
    readonly iv?: string;
    readonly tag?: string;
    readonly ciphertext?: string;
  } | null;
}

function guardEvents(world: ReturnType<typeof testWorld>) {
  return world.eventLog.all().filter((e) => e.action === 'session.guard');
}

function metadataOf(event: { readonly metadata?: Readonly<Record<string, unknown>> }): GuardMetadata {
  return (event.metadata ?? {}) as GuardMetadata;
}

describe('drift: metadata.sealed is a raw Sealed object', () => {
  test('withheld prose-leak run carries a Sealed object with ciphertext', async () => {
    const world = testWorld();
    const canary = world.secretValues[0]!;
    const model = new ScriptedModel('scripted-drift-leaker-v1', [
      { text: `The API key is ${canary}.`, requests: [] },
    ]);
    const trace = await world.session(model).run([]);
    assert.equal(trace.guarded!.status, 'withheld');

    const events = guardEvents(world);
    assert.equal(events.length, 1);
    const sealed = metadataOf(events[0]!).sealed;
    assert.ok(sealed, 'withheld guard event must carry sealed original');
    assert.equal(typeof sealed, 'object');
    assert.equal(typeof sealed.ciphertext, 'string');
    assert.equal(typeof sealed.keyId, 'string');
    assert.equal(typeof sealed.iv, 'string');
    assert.equal(typeof sealed.tag, 'string');
  });
});

describe('drift: metadata.ladderRung records the rung that fired', () => {
  test('withheld non-leak run → abstain or escalate', async () => {
    const world = testWorld();
    const model = new ScriptedModel('scripted-drift-abstain-v1', [{ text: 'I read', requests: [] }]);
    const trace = await world.session(model).run([]);
    assert.equal(trace.guarded!.status, 'withheld');
    assert.ok(['abstain', 'escalate'].includes(trace.guarded!.ladderRung ?? ''));

    const events = guardEvents(world);
    assert.equal(events.length, 1);
    assert.equal(metadataOf(events[0]!).ladderRung, trace.guarded!.ladderRung);
  });

  test('delivered run → null', async () => {
    const world = testWorld();
    const model = new ScriptedModel('scripted-drift-delivered-v1', [
      {
        text: 'Repository A contains billing and invoice services.',
        requests: [{ action: 'read', resourceId: world.resources.repoA! }],
      },
    ]);
    const trace = await world.session(model).run([]);
    assert.equal(trace.guarded!.status, 'delivered');
    assert.equal(trace.guarded!.ladderRung, null);

    const events = guardEvents(world);
    assert.equal(events.length, 1);
    assert.equal(metadataOf(events[0]!).ladderRung, null);
  });
});
