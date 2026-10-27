/**
 * H14 — mutation lane (ADR-035).
 *
 * The lane's claim is not "the policy is correct"; it is "the golden set can
 * tell a mutated policy from the real one". Two things are tested: the mutants
 * themselves (deterministic, no no-ops, every kind reachable) and the lane's
 * teeth (an incomplete oracle produces survivors, so a weakened golden cannot
 * pass silently).
 */

import { test, describe } from 'node:test';
import assert from 'node:assert/strict';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import type { PolicyRule } from '../src/policy.ts';
import { goldenHash, loadGolden, type Golden } from '../src/policy-testing.ts';
import { evaluateMutants, mutateRules, summarize } from '../src/mutation.ts';
import { mutationLane } from '../src/adversarial.ts';

const __dirname = dirname(fileURLToPath(import.meta.url));
const GOLDEN = join(__dirname, 'fixtures', 'policy', 'goldens', 'baseline-decisions.json');
const NOW = 1748736000000;

const agent = { id: 'agent:a', kind: 'agent' as const, tenantId: 'acme', roles: [], attributes: {} };
const user = { id: 'user:u', kind: 'user' as const, tenantId: 'acme', roles: [], attributes: {} };
const doc = { id: 'd', type: 'document' as const, tenantId: 'acme', classification: 'internal' as const, attributes: {} };

const allowRead: PolicyRule = {
  id: 'allow-read',
  effect: 'allow',
  principals: { kinds: ['agent'] },
  actions: ['read'],
  resources: {},
};

/** A tiny oracle that is complete for a single-rule policy. */
function tinyGolden(overrides: Partial<Golden> = {}): Golden {
  const rules = [allowRead];
  return {
    id: 'tiny',
    name: 'tiny',
    version: 1,
    policyId: 'tiny',
    policyHash: goldenHash(rules),
    rules,
    scenarios: [
      { principal: agent, resource: doc, action: 'read', now: NOW },
      { principal: agent, resource: doc, action: 'delete', now: NOW },
      { principal: user, resource: doc, action: 'read', now: NOW },
    ],
    expected: [
      { effect: 'allow', ruleId: 'allow-read' },
      { effect: 'deny' },
      { effect: 'deny' },
    ],
    ...overrides,
  };
}

describe('H14 mutation: mutant generation', () => {
  test('emits drop-rule plus every applicable mutation kind', () => {
    const kinds = new Set(mutateRules([allowRead]).map((m) => m.kind));
    assert.deepEqual([...kinds].sort(), ['drop-rule', 'flip-effect', 'widen-actions', 'widen-principals']);
  });

  test('a rich rule reaches every kind except the inapplicable ones', () => {
    const rich: PolicyRule = {
      ...allowRead,
      maxClassification: 'internal',
      requiresApproval: true,
      conditions: [{ kind: 'param-equals', key: 'mode', value: 'readonly' }],
    };
    const ids = mutateRules([rich]).map((m) => m.id);
    for (const expected of [
      'allow-read:drop-rule',
      'allow-read:flip-effect',
      'allow-read:widen-actions',
      'allow-read:drop-ceiling',
      'allow-read:widen-ceiling',
      'allow-read:drop-approval',
      'allow-read:drop-condition[0]',
      'allow-read:widen-principals',
    ]) {
      assert.ok(ids.includes(expected), `missing ${expected}`);
    }
  });

  test('no mutation is emitted when it would change nothing', () => {
    const top: PolicyRule = { ...allowRead, maxClassification: 'restricted' };
    assert.ok(!mutateRules([top]).some((m) => m.kind === 'widen-ceiling'), 'restricted cannot widen further');

    const open: PolicyRule = { ...allowRead, principals: {}, actions: ['*'] };
    const kinds = mutateRules([open]).map((m) => m.kind);
    assert.ok(!kinds.includes('widen-actions'));
    assert.ok(!kinds.includes('widen-principals'));
  });

  test('every mutant differs from the original policy', () => {
    const rules = [allowRead, { ...allowRead, id: 'allow-read-2', maxClassification: 'internal' as const }];
    for (const m of mutateRules(rules)) {
      assert.notDeepEqual(m.rules, rules, `${m.id} is a no-op`);
    }
  });

  test('drop-rule removes exactly one rule and leaves the rest in order', () => {
    const second: PolicyRule = { ...allowRead, id: 'allow-read-2' };
    const m = mutateRules([allowRead, second]).find((x) => x.id === 'allow-read:drop-rule')!;
    assert.deepEqual(m.rules.map((r) => r.id), ['allow-read-2']);
  });
});

describe('H14 mutation: the lane kills what a complete oracle can see', () => {
  test('a complete tiny oracle kills all four mutants', () => {
    const golden = tinyGolden();
    const summary = summarize(evaluateMutants(mutateRules(golden.rules), golden));
    assert.equal(summary.total, 4);
    assert.equal(summary.killed, 4);
    assert.deepEqual(summary.unexpected, []);
  });

  test('an oracle missing the cross-principal case lets a mutant survive', () => {
    const golden = tinyGolden();
    const weakened: Golden = {
      ...golden,
      scenarios: golden.scenarios.slice(0, 2),
      expected: golden.expected.slice(0, 2),
    };
    const summary = summarize(evaluateMutants(mutateRules(weakened.rules), weakened));
    assert.deepEqual(
      summary.unexpected.map((r) => r.mutant.id),
      ['allow-read:widen-principals'],
    );
  });

  test('an oracle missing the other-action case lets a mutant survive', () => {
    const golden = tinyGolden();
    const weakened: Golden = {
      ...golden,
      scenarios: [golden.scenarios[0]!, golden.scenarios[2]!],
      expected: [golden.expected[0]!, golden.expected[2]!],
    };
    const summary = summarize(evaluateMutants(mutateRules(weakened.rules), weakened));
    assert.deepEqual(
      summary.unexpected.map((r) => r.mutant.id),
      ['allow-read:widen-actions'],
    );
  });
});

describe('H14 mutation: the committed baseline policy', () => {
  test('every mutant of BASELINE_POLICY is killed by the golden set', () => {
    const golden = loadGolden(GOLDEN);
    const summary = summarize(evaluateMutants(mutateRules(golden.rules), golden), golden.mutationAllowlist ?? []);
    assert.ok(summary.total >= 15, `only ${summary.total} mutants generated`);
    assert.deepEqual(
      summary.unexpected.map((r) => r.mutant.id),
      [],
      'surviving mutants mean the golden set has a coverage hole',
    );
    assert.equal(summary.killed, summary.total);
  });

  test('the committed golden carries no allowlist entries (no known equivalents)', () => {
    const golden = loadGolden(GOLDEN);
    assert.equal(golden.mutationAllowlist, undefined);
  });
});

describe('H14 mutation: lane semantics', () => {
  test('all killed passes', () => {
    assert.equal(mutationLane(17, 17, []).passed, true);
  });

  test('a survivor fails the lane and names it', () => {
    const lane = mutationLane(17, 16, ['allow-user-approve:widen-actions']);
    assert.equal(lane.passed, false);
    assert.match(lane.detail, /allow-user-approve:widen-actions/);
  });

  test('an allowlisted survivor does not fail the lane but is reported', () => {
    const lane = mutationLane(17, 16, [], 1);
    assert.equal(lane.passed, true);
    assert.match(lane.detail, /1 allowlisted/);
  });

  test('generating no mutants fails closed', () => {
    const lane = mutationLane(0, 0, []);
    assert.equal(lane.passed, false);
    assert.match(lane.detail, /no mutants/);
  });
});
