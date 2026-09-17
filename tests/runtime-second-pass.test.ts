/**
 * SESSION-8: per-session classification derivation and the post-execution
 * second-pass guard. Covers the derived-classification Escalate gate and the
 * single-event rule for agreeing verdicts.
 */

import { test, describe } from 'node:test';
import assert from 'node:assert/strict';
import { ScriptedModel } from '../src/model.ts';
import { testWorld } from '../src/testing.ts';
import { deriveClassification } from '../src/runtime.ts';
import { CapabilityRequestService } from '../src/capability-request.ts';

function guardEvents(world: ReturnType<typeof testWorld>) {
  return world.eventLog.all().filter((e) => e.action === 'session.guard');
}

describe('deriveClassification', () => {
  test('all-empty inputs → public', () => {
    const world = testWorld();
    assert.equal(
      deriveClassification({
        capabilities: [],
        registry: world.registry,
        requestedResourceIds: [],
      }),
      'public',
    );
  });

  test('content keys lift classification from the registry', () => {
    const world = testWorld();
    assert.equal(
      deriveClassification({
        capabilities: [],
        content: new Map([[world.resources.repoA!, 'x']]),
        registry: world.registry,
        requestedResourceIds: [],
      }),
      'internal',
    );
  });

  test('capability ceilings count', () => {
    const world = testWorld();
    assert.equal(
      deriveClassification({
        capabilities: [{ maxClassification: 'confidential' }],
        registry: world.registry,
        requestedResourceIds: [],
      }),
      'confidential',
    );
  });

  test('requested resource ids count; unknown ids are ignored', () => {
    const world = testWorld();
    assert.equal(
      deriveClassification({
        capabilities: [],
        registry: world.registry,
        requestedResourceIds: ['doc:not-in-registry', world.resources.phi!],
      }),
      'phi',
    );
  });

  test('unknown label wins over restricted (fail-closed rank 100)', () => {
    const world = testWorld();
    assert.equal(
      deriveClassification({
        capabilities: [{ maxClassification: 'restricted' }, { maxClassification: 'x-acme-top-secret' }],
        registry: world.registry,
        requestedResourceIds: [],
      }),
      'x-acme-top-secret',
    );
  });
});

describe('second-pass guard', () => {
  test('first and second pass agree → exactly one session.guard event', () => {
    const world = testWorld();
    const model = new ScriptedModel('scripted-summarizer-v1', [
      {
        text: 'Repository A contains billing and invoice services.',
        requests: [{ action: 'read', resourceId: world.resources.repoA! }],
      },
    ]);
    const trace = world.session(model).run([]);

    const events = guardEvents(world);
    assert.equal(events.length, 1);
    assert.equal(events[0]!.metadata?.phase, 'guard');
    assert.equal(trace.guarded!.status, 'delivered');
  });

  test('second pass clears a first-pass action-claim-mismatch', () => {
    const world = testWorld();
    const model = new ScriptedModel('scripted-read-claim-v1', [
      {
        // The claim must be unrepairable (repair empties the text) so the first-pass
        // flag is recorded on the withheld event; a successful repair clears flags
        // before the response reaches the log.
        text: 'I read',
        requests: [{ action: 'read', resourceId: world.resources.repoA! }],
      },
    ]);
    const trace = world.session(model).run([]);

    const events = guardEvents(world);
    assert.equal(events.length, 2);
    assert.equal(events[0]!.metadata?.status, 'withheld');
    const firstFlags = events[0]!.metadata?.flags as readonly { reason: string }[];
    assert.ok(firstFlags.some((f) => f.reason === 'action-claim-mismatch'));
    assert.equal(events[1]!.metadata?.phase, 'guard-second-pass');
    assert.equal(trace.guarded!.status, 'delivered');
  });

  test('second pass does not double-queue an escalate request', () => {
    const world = testWorld();
    const service = new CapabilityRequestService(world.eventLog, world.authorization, world.root);
    const model = new ScriptedModel('scripted-false-delete-v1', [
      {
        text: 'I deleted',
        requests: [{ action: 'read', resourceId: world.resources.repoA! }],
      },
    ]);
    const trace = world.session(model, { capabilityRequestService: service }).run([]);

    assert.equal(service.all().length, 1);
    const events = world.eventLog.all();
    assert.equal(events.filter((e) => e.action === 'capability.request').length, 1);

    const guardEvts = guardEvents(world);
    assert.equal(guardEvts.length, 1);
    assert.equal(guardEvts[0]!.metadata?.status, 'withheld');
    // Derived classification reached the Escalate rung, so the request text is shown.
    assert.equal(trace.guarded!.status, 'withheld');
    assert.ok(trace.guarded!.text.includes('awaiting human review'));
  });
});
