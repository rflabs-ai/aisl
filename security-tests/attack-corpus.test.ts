/**
 * Attack corpus: every declared attack must produce the outcome the platform
 * claims. This file is the "show me why the AI cannot do X" harness.
 */

import { test, describe } from 'node:test';
import assert from 'node:assert/strict';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { loadAttackCorpus, runAttackCase } from '../src/attacks.ts';
import { testWorld } from '../src/testing.ts';

const ROOT = join(dirname(fileURLToPath(import.meta.url)), '..');

describe('adversarial attack corpus', () => {
  const cases = loadAttackCorpus(join(ROOT, 'security-attacks'));

  test('corpus is non-empty and every case declares an expectation', () => {
    assert.ok(cases.length >= 10, `expected at least 10 attack cases, got ${cases.length}`);
    for (const c of cases) {
      assert.ok(c.id, 'attack case needs an id');
      assert.ok(['denied', 'allowed'].includes(c.expect), `case ${c.id} needs a valid expectation`);
      assert.ok(c.requests.length > 0, `case ${c.id} needs at least one request`);
    }
  });

  for (const testCase of cases) {
    test(`${testCase.id} ${testCase.name} -> ${testCase.expect}`, async () => {
      const world = testWorld();
      const result = await runAttackCase(world, testCase);
      const detail = result.outcomes
        .map((o) => `${o.request.action}@${o.request.resourceId} => ${o.decision}${o.denyReason ? ` (${o.denyReason})` : ''}${o.executed ? ' EXECUTED' : ''}`)
        .join(' | ');
      assert.ok(result.passed, `${testCase.id} did not behave as required: ${detail}`);

      for (const o of result.outcomes) {
        if (testCase.expect === 'denied') {
          assert.equal(o.executed, false, `${testCase.id}: denied action must not execute`);
          assert.equal(o.output, undefined, `${testCase.id}: denied action must not produce output`);
        }
      }
    });
  }

  test('a denied attack never yields resource content', async () => {
    const world = testWorld();
    for (const testCase of cases.filter((c) => c.expect === 'denied')) {
      const result = await runAttackCase(world, testCase);
      for (const o of result.outcomes) {
        const leaked = typeof o.output === 'string' && o.output.length > 0;
        assert.equal(leaked, false, `${testCase.id} leaked content: ${String(o.output)}`);
      }
    }
  });

  test('the evidence chain is intact after running the whole corpus', async () => {
    const world = testWorld();
    for (const testCase of cases) await runAttackCase(world, testCase);
    const verification = world.eventLog.verify();
    assert.equal(verification.valid, true, JSON.stringify(verification));
    assert.ok(world.eventLog.all().length > cases.length);
  });
});

describe('legitimate workload', () => {
  const cases = loadAttackCorpus(join(ROOT, 'security-fixtures'));

  for (const testCase of cases) {
    test(`${testCase.id} ${testCase.name} -> allowed`, async () => {
      const world = testWorld();
      const result = await runAttackCase(world, testCase);
      const detail = result.outcomes.map((o) => `${o.request.action}@${o.request.resourceId} => ${o.decision}`).join(' | ');
      assert.ok(result.passed, `legitimate work was blocked (false denial): ${detail}`);
    });
  }
});
