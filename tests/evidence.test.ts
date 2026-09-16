/**
 * Evidence content policy.
 *
 * Every execution is provenanced by digest. Content is inlined only when it is
 * below the configured ceiling AND contains no registered secret value — the
 * evidence store must never become the easiest place to steal a secret from.
 */

import { test, describe } from 'node:test';
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { canonicalJson } from '../src/domain.ts';
import { type Approval } from '../src/policy.ts';
import { testWorld } from '../src/testing.ts';
import { TENANT_A } from '../src/scenario.ts';

interface ExecutionMetadata {
  outputDigest: string | null;
  output: string | null;
  outputWithheld: string | null;
  phase: string;
}

function lastExecution(world: ReturnType<typeof testWorld>): ExecutionMetadata {
  const event = [...world.eventLog.all()].reverse().find((e) => (e.metadata as { phase?: string } | undefined)?.phase === 'execution');
  assert.ok(event, 'expected an execution event');
  return event!.metadata as unknown as ExecutionMetadata;
}

describe('evidence content', () => {
  test('internal output is inlined and its digest verifies', () => {
    const world = testWorld();
    const step = world
      .session({ id: 'm', complete: () => ({ text: '', requests: [] }) })
      .attempt({ action: 'read', resourceId: world.resources.repoA! });
    assert.equal(step.executed, true);

    const meta = lastExecution(world);
    const expected = createHash('sha256').update(String(step.output)).digest('hex');
    assert.equal(meta.outputDigest, expected);
    assert.equal(meta.output, step.output);
    assert.equal(meta.outputWithheld, null);
  });

  test('output above the ceiling is digest-only', () => {
    const world = testWorld();
    const approval: Approval = {
      id: 'ap-evidence',
      approvedBy: world.user.id,
      principalId: world.agent.id,
      action: 'read',
      resourceId: world.resources.confidentialDoc!,
      expiresAt: world.clock.now() + 600_000,
    };
    world.authorization.issue(world.root, {
      subject: world.agent.id,
      tenantId: TENANT_A,
      resourceIds: [world.resources.confidentialDoc!],
      actions: ['read'],
      maxClassification: 'confidential',
      expiresAt: world.clock.now() + 600_000,
      provenance: { source: 'human-approval', approvedBy: world.user.id },
    });

    const step = world
      .session({ id: 'm', complete: () => ({ text: '', requests: [] }) }, { approvals: [approval] })
      .attempt({ action: 'read', resourceId: world.resources.confidentialDoc! });
    assert.equal(step.decision.decision, 'allow');

    const meta = lastExecution(world);
    assert.equal(meta.output, null);
    assert.equal(meta.outputWithheld, 'classification-ceiling');
    assert.equal(meta.outputDigest, createHash('sha256').update(String(step.output)).digest('hex'));
  });

  test('output containing a registered secret is never written to the store', () => {
    const world = testWorld();
    const secret = world.secretValues[0]!;
    world.content.set(world.resources.internalDoc!, `harmless note: ${secret}`);

    const step = world
      .session({ id: 'm', complete: () => ({ text: '', requests: [] }) })
      .attempt({ action: 'read', resourceId: world.resources.internalDoc! });
    assert.equal(step.executed, true);
    assert.ok(String(step.output).includes(secret), 'the tool really did return the secret');

    const meta = lastExecution(world);
    assert.equal(meta.output, null, 'secret value must not reach the evidence store');
    assert.equal(meta.outputWithheld, 'secret-value');
    assert.notEqual(meta.outputDigest, null);

    const serialized = world.eventLog.bundle();
    assert.equal(serialized.includes(secret), false, 'no event anywhere may contain the secret');
  });

  test('lowering the ceiling stops inlining below it', () => {
    const previous = process.env.EVIDENCE_INLINE_CEILING;
    process.env.EVIDENCE_INLINE_CEILING = 'public';
    try {
      const world = testWorld();
      const step = world
        .session({ id: 'm', complete: () => ({ text: '', requests: [] }) })
        .attempt({ action: 'read', resourceId: world.resources.repoA! });
      assert.equal(step.executed, true);
      const meta = lastExecution(world);
      assert.equal(meta.output, null);
      assert.equal(meta.outputWithheld, 'classification-ceiling');
      assert.equal(meta.outputDigest, createHash('sha256').update(String(step.output)).digest('hex'));
    } finally {
      if (previous === undefined) delete process.env.EVIDENCE_INLINE_CEILING;
      else process.env.EVIDENCE_INLINE_CEILING = previous;
    }
  });
});
