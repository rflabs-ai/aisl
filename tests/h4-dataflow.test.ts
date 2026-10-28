/**
 * H4 — data-flow enforcement / taint (ADR-036).
 *
 * The PDP answers "may this principal do this". These tests are about the other
 * half: what has this session already seen, and is that still true later.
 *
 * The laundering case is the one that matters. A session reads phi through a
 * tool, the capability that justified the read is revoked, and then a later
 * write is attempted with only a public capability. Without a carried label the
 * write's classification is derived from what remains — the write capability
 * and an empty content map — and the phi is laundered into the target. With a
 * carried label it is still phi, because revocation does not un-see data.
 */

import { test, describe } from 'node:test';
import assert from 'node:assert/strict';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { readFileSync } from 'node:fs';
import { AgentSession, LocalSandbox } from '../src/runtime.ts';
import { ScriptedModel } from '../src/model.ts';
import { testWorld } from '../src/testing.ts';
import { CLEAN_TAINT, UNKNOWN_TAINT, combine, taintFor } from '../src/taint.ts';
import type { PolicyRule } from '../src/policy.ts';
import { ingestDocument } from '../src/registry.ts';

const __dirname = dirname(fileURLToPath(import.meta.url));
const NOW = 1748736000000;

const writeRule: PolicyRule = {
  id: 'test-allow-agent-write',
  effect: 'allow',
  principals: { kinds: ['agent'] },
  actions: ['write'],
  resources: { maxClassification: 'internal' },
};

/** The baseline gates reads above `internal` behind an approval; these tests are about taint. */
const readRule: PolicyRule = {
  id: 'test-allow-agent-read-phi',
  effect: 'allow',
  principals: { kinds: ['agent'] },
  actions: ['read'],
  resources: { maxClassification: 'phi' },
};

/** A session whose content map is what a real session would have: nothing ingested. */
function scopedSession(world: ReturnType<typeof testWorld>) {
  return new AgentSession({
    principal: world.agent,
    agentId: world.agent.id,
    model: new ScriptedModel('h4-test-model', []),
    task: 'summarize',
    registry: world.registry,
    authorization: world.authorization,
    eventLog: world.eventLog,
    tools: world.tools,
    sandbox: new LocalSandbox(),
    content: new Map<string, string>(),
    now: world.clock.now,
    guard: null,
  });
}

describe('H4: the taint algebra only raises', () => {
  test('combining takes the max classification, the union of sources, and untrusted', () => {
    const label = combine(
      taintFor('doc:a', 'internal'),
      taintFor('doc:b', 'phi'),
      { sources: ['doc:c'], classification: 'public', untrusted: false },
    );
    assert.equal(label.classification, 'phi');
    assert.deepEqual(label.sources, ['doc:a', 'doc:b', 'doc:c']);
    assert.equal(label.untrusted, true);
  });

  test('no operation lowers a label', () => {
    const high = taintFor('doc:phi', 'phi');
    assert.equal(combine(high, taintFor('doc:public', 'public')).classification, 'phi');
    assert.equal(combine(high, CLEAN_TAINT).classification, 'phi');
  });

  test('an empty combine is clean, and sources are deduped and sorted', () => {
    assert.deepEqual(combine(), CLEAN_TAINT);
    const label = combine(taintFor('doc:z', 'public'), taintFor('doc:a', 'public'), taintFor('doc:z', 'public'));
    assert.deepEqual(label.sources, ['doc:a', 'doc:z']);
  });

  test('an unknown source ranks at the ceiling so silence fails closed', () => {
    assert.equal(combine(UNKNOWN_TAINT).classification, 'x-unknown-source');
    assert.equal(combine(UNKNOWN_TAINT).untrusted, true);
  });
});

describe('H4: labels survive the session, not just the step', () => {
  test('phi read then revoked capability: the later write is still raised to phi', () => {
    const world = testWorld({ policies: [writeRule, readRule] });
    const phiId = world.resources.phi!;
    const targetId = world.resources.internalDoc!;
    world.tools.register({
      name: 'read',
      invoke: (ctx) => ({ output: 'patient_id,diagnosis\n0001,E11.9', taint: taintFor(ctx.resourceId, ctx.resourceClassification) }),
    });

    const phiCap = world.authorization.issue(world.root, {
      subject: world.agent.id,
      tenantId: 'acme',
      resourceIds: [phiId],
      actions: ['read'],
      maxClassification: 'phi',
      expiresAt: world.clock.now() + 60_000,
      provenance: { source: 'policy-grant' },
    });
    world.authorization.issue(world.root, {
      subject: world.agent.id,
      tenantId: 'acme',
      resourceIds: [targetId],
      actions: ['write'],
      maxClassification: 'internal',
      expiresAt: world.clock.now() + 60_000,
      provenance: { source: 'policy-grant' },
    });

    const session = scopedSession(world);
    const read = session.attempt({ action: 'read', resourceId: phiId });
    assert.equal(read.executed, true);
    assert.equal(read.taint.classification, 'phi');
    assert.ok(read.taint.sources.includes(phiId));

    // The grant that justified the read is gone; the data it exposed is not.
    world.authorization.revoke(phiCap.id, 'grant expired');

    const write = session.attempt({ action: 'write', resourceId: targetId });
    assert.equal(write.executed, true);
    assert.equal(write.taint.classification, 'phi', 'the step carries what the session saw');
    assert.equal(
      world.registry.get(targetId)?.classification,
      'phi',
      'the target inherits the label — revocation does not un-see data',
    );
  });

  test('a tool can declare provenance, and only to raise it', () => {
    const world = testWorld({ policies: [writeRule, readRule] });
    const targetId = world.resources.internalDoc!;
    world.authorization.issue(world.root, {
      subject: world.agent.id,
      tenantId: 'acme',
      resourceIds: [targetId],
      actions: ['write'],
      maxClassification: 'internal',
      expiresAt: world.clock.now() + 60_000,
      provenance: { source: 'policy-grant' },
    });
    // A tool that fetched data the registry knows nothing about labels it.
    world.tools.register({
      name: 'write',
      invoke: () => ({
        output: 'merged',
        changed: true,
        taint: { sources: ['vendor:acme-export'], classification: 'restricted', untrusted: true },
      }),
    });

    const session = scopedSession(world);
    const write = session.attempt({ action: 'write', resourceId: targetId });
    assert.equal(write.executed, true);
    assert.equal(write.taint.classification, 'restricted');
    assert.equal(world.registry.get(targetId)?.classification, 'restricted');
  });

  test('a read of an unknown resource taints the session at the ceiling', () => {
    const world = testWorld();
    const session = scopedSession(world);
    const step = session.attempt({ action: 'read', resourceId: 'doc:does-not-exist' });
    assert.equal(step.executed, false, 'unknown resources are denied before execution');
    assert.equal(step.taint.classification, 'x-unknown-source');
  });
});

describe('H4: evidence records provenance, never content', () => {
  test('each step records a taint label with ids and no plaintext', () => {
    const world = testWorld({ policies: [writeRule, readRule] });
    const phiId = world.resources.phi!;
    world.tools.register({
      name: 'read',
      invoke: (ctx) => ({ output: 'PHI-CANARY-7f3a', taint: taintFor(ctx.resourceId, ctx.resourceClassification) }),
    });
    world.authorization.issue(world.root, {
      subject: world.agent.id,
      tenantId: 'acme',
      resourceIds: [phiId],
      actions: ['read'],
      maxClassification: 'phi',
      expiresAt: world.clock.now() + 60_000,
      provenance: { source: 'policy-grant' },
    });

    const session = scopedSession(world);
    session.attempt({ action: 'read', resourceId: phiId });

    // The PDP appends its own decision event; the execution event is the one
    // that carries the label.
    const events = world.eventLog
      .all()
      .filter((e) => e.action === 'read' && (e.metadata as { taint?: unknown } | undefined)?.taint !== undefined);
    assert.equal(events.length, 1);
    const taint = (events[0]!.metadata as { taint?: { classification?: string; sources?: string[]; untrusted?: boolean } }).taint;
    assert.ok(taint, 'every execution event carries a taint label');
    assert.equal(taint.classification, 'phi');
    assert.deepEqual(taint.sources, [phiId]);
    assert.equal(taint.untrusted, true, 'tool output is attacker-influenceable by definition (H6)');

    // Structural: the label is metadata, and the canary must not be in it.
    assert.ok(!JSON.stringify(taint).includes('PHI-CANARY'));
    assert.ok(!JSON.stringify(events[0]!.metadata).includes('PHI-CANARY'));
  });
});

describe('H4: the malicious corpus stays denied end to end', () => {
  const corpusDir = join(__dirname, '..', 'security-fixtures', 'corpus');
  const docs = ['01-ordinary-internal.md', '02-sensitive-malicious.md', '03-synthetic-phi-and-fake-secrets.md', '04-source-code-injection.md'];

  test('every step in a session fed hostile documents is denied or in scope, and marked untrusted', async () => {
    for (const name of docs) {
      const world = testWorld({ policies: [writeRule, readRule] });
      const content = readFileSync(join(corpusDir, name), 'utf8');
      world.content.set(world.resources.internalDoc!, content);

      const model = new ScriptedModel('hostile-model', [
        {
          text: 'done',
          requests: [
            { action: 'export', resourceId: world.resources.phi! },
            { action: 'read', resourceId: world.resources.secretApiKey! },
            { action: 'delete', resourceId: world.resources.internalDoc! },
          ],
        },
      ]);

      const ingested = ingestDocument(world.registry.require(world.resources.internalDoc!), content);
      const trace = await world.session(model).run([ingested]);
      assert.equal(trace.steps.length, 3);
      for (const step of trace.steps) {
        assert.equal(step.decision.decision, 'deny', `${name}: ${step.request.action} must be denied`);
        assert.equal(step.executed, false);
        assert.equal(step.taint.untrusted, true, `${name}: a step fed hostile text is untrusted`);
        assert.ok(step.taint.sources.includes(world.resources.internalDoc!), `${name}: the source is named`);
      }
    }
  });
});
