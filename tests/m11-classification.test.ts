/**
 * M11: classification propagation.
 *
 * Labels flow to derived artifacts, only raise, never lower: a write that is
 * influenced by higher-sensitivity sources lifts the target's label, the raised
 * label seals the execution evidence, and nothing in the path can downgrade.
 */

import { test, describe } from 'node:test';
import assert from 'node:assert/strict';
import { ResourceRegistry, defineResource, ingestDocument, propagateClassification } from '../src/registry.ts';
import { AgentSession, LocalSandbox } from '../src/runtime.ts';
import { ScriptedModel } from '../src/model.ts';
import { testWorld } from '../src/testing.ts';
import { keyIdForTenant } from '../src/seal.ts';
import { type PolicyRule } from '../src/policy.ts';

const ALLOW_AGENT_WRITE: PolicyRule = {
  id: 'test-allow-agent-write-document',
  description: 'Agents may write documents they hold a capability for.',
  effect: 'allow',
  principals: { kinds: ['agent'] },
  actions: ['write'],
  resources: { types: ['document'] },
};

describe('propagateClassification', () => {
  test('a higher source lifts the current label', () => {
    assert.equal(propagateClassification('public', ['confidential']), 'confidential');
  });

  test('phi wins over public', () => {
    assert.equal(propagateClassification('public', ['phi']), 'phi');
  });

  test('an unknown label outranks every known label (rank 100)', () => {
    assert.equal(propagateClassification('x-custom', ['internal']), 'x-custom');
  });

  test('labels never lower', () => {
    assert.equal(propagateClassification('phi', ['public']), 'phi');
  });
});

describe('ingestDocument with derivedFrom', () => {
  const registry = new ResourceRegistry();
  const doc = registry.add(
    defineResource({ id: 'doc:artifact', type: 'document', tenantId: 'acme', classification: 'public' }),
  );
  const source = registry.add(
    defineResource({ id: 'doc:source', type: 'document', tenantId: 'acme', classification: 'confidential' }),
  );

  test('derived artifact of a public resource + confidential source reports confidential', () => {
    const data = ingestDocument(doc, 'derived content', 'derive', [source]);
    assert.equal(data.derivedClassification, 'confidential');
  });

  test('without derivedFrom the field is absent', () => {
    const data = ingestDocument(doc, 'plain content');
    assert.equal('derivedClassification' in data, false);
  });
});

describe('raiseClassification', () => {
  const registry = new ResourceRegistry();
  registry.add(
    defineResource({ id: 'doc:t', type: 'document', tenantId: 'acme', classification: 'internal' }),
  );

  test('raises on a higher label', () => {
    const raised = registry.raiseClassification('doc:t', 'confidential');
    assert.equal(raised?.classification, 'confidential');
    assert.equal(registry.require('doc:t').classification, 'confidential');
  });

  test('refuses to lower — stays at the existing label', () => {
    const unchanged = registry.raiseClassification('doc:t', 'public');
    assert.equal(unchanged?.classification, 'confidential');
    assert.equal(registry.require('doc:t').classification, 'confidential');
  });

  test('returns undefined for an unknown id and does not create the resource', () => {
    assert.equal(registry.raiseClassification('doc:missing', 'phi'), undefined);
    assert.equal(registry.get('doc:missing'), undefined);
  });
});

describe('write path propagation (end-to-end)', () => {
  function writeSession(
    world: ReturnType<typeof testWorld>,
    content: ReadonlyMap<string, string>,
    target: string,
  ): AgentSession {
    return new AgentSession({
      principal: world.agent,
      agentId: world.agent.id,
      model: new ScriptedModel('scripted-m11-writer-v1', [
        { text: 'Applying the pending document update.', requests: [{ action: 'write', resourceId: target }] },
      ]),
      task: 'Apply the pending document update.',
      registry: world.registry,
      authorization: world.authorization,
      eventLog: world.eventLog,
      tools: world.tools,
      sandbox: new LocalSandbox(),
      content,
      now: world.clock.now,
    });
  }

  function writeEvents(world: ReturnType<typeof testWorld>, sessionId: string) {
    return world.eventLog
      .all()
      .filter((e) => e.action === 'write' && e.metadata?.phase === 'execution' && e.metadata?.sessionId === sessionId);
  }

  test('a write influenced by a confidential source raises the target and seals under the derived key', async () => {
    const world = testWorld({ policies: [ALLOW_AGENT_WRITE] });
    const target = world.resources.internalDoc!;
    const source = world.resources.confidentialDoc!;
    assert.equal(world.registry.require(target).classification, 'internal');

    world.authorization.issue(world.root, {
      subject: world.agent.id,
      tenantId: world.agent.tenantId,
      resourceIds: [target],
      actions: ['write'],
      maxClassification: 'restricted',
      expiresAt: world.clock.now() + 3_600_000,
      provenance: { source: 'policy-grant', note: 'classification propagation' },
    });

    const session = writeSession(world, new Map([[source, 'Project Halcyon: acquire Northwind. Do not distribute.']]), target);
    await session.run([]);

    assert.equal(world.registry.require(target).classification, 'confidential');

    const events = writeEvents(world, session.sessionId);
    assert.equal(events.length, 1);
    const ev = events[0]!;
    assert.equal(ev.result, 'success');
    assert.equal(ev.metadata?.derivedClassification, 'confidential');
    const sealed = ev.metadata?.sealed as { keyId: string } | null;
    assert.ok(sealed);
    assert.equal(sealed.keyId, keyIdForTenant('acme', 'confidential'));
    assert.equal(sealed.keyId, 'evidence-key:v2:acme:confidential');
  });

  test('a later write with no higher sources does not lower the label', async () => {
    const world = testWorld({ policies: [ALLOW_AGENT_WRITE] });
    const target = world.resources.internalDoc!;

    world.authorization.issue(world.root, {
      subject: world.agent.id,
      tenantId: world.agent.tenantId,
      resourceIds: [target],
      actions: ['write'],
      maxClassification: 'restricted',
      expiresAt: world.clock.now() + 3_600_000,
      provenance: { source: 'policy-grant', note: 'classification propagation' },
    });

    const first = writeSession(world, new Map([[world.resources.confidentialDoc!, 'Project Halcyon. Do not distribute.']]), target);
    await first.run([]);
    assert.equal(world.registry.require(target).classification, 'confidential');

    const second = writeSession(world, new Map<string, string>(), target);
    await second.run([]);

    assert.equal(world.registry.require(target).classification, 'confidential');
    const events = writeEvents(world, second.sessionId);
    assert.equal(events.length, 1);
    const ev = events[0]!;
    assert.equal(ev.metadata?.derivedClassification, 'confidential');
    const sealed = ev.metadata?.sealed as { keyId: string } | null;
    assert.ok(sealed);
    assert.equal(sealed.keyId, 'evidence-key:v2:acme:confidential');
  });
});

