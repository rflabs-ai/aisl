/**
 * Policy testing harness tests.
 *
 * Asserts each of the three primitives (simulate, diffDecisions, loadFixtures)
 * and runs the three migrated fixtures against the unmodified BASELINE_POLICY
 * plus a one-line overlay that flips a baseline decision.
 */

import { test, describe } from 'node:test';
import assert from 'node:assert/strict';
import { mkdirSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { mockAuth } from '../src/testing.ts';
import { BASELINE_POLICY, createPolicyEngine, type PolicyRule } from '../src/policy.ts';
import {
  diffDecisions,
  loadFixtures,
  simulate,
  type Scenario,
} from '../src/policy-testing.ts';

const __dirname = dirname(fileURLToPath(import.meta.url));

const agentAuth = mockAuth({ subject: 'agent:a' });
const agent = {
  id: 'agent:a', kind: 'agent' as const, tenantId: 'acme', roles: [], attributes: {}, auth: agentAuth,
};
const doc = (id: string, classification: string, tenantId = 'acme') => ({
  id, type: 'document' as const, tenantId, classification, attributes: {},
});

function baselineEngine() {
  return createPolicyEngine(BASELINE_POLICY, 'baseline');
}

describe('policy-testing: simulate', () => {
  test('returns one decision per scenario, in input order, with typed reason', () => {
    const engine = createPolicyEngine(BASELINE_POLICY);
    const scenarios: readonly Scenario[] = [
      { principal: agent, resource: doc('r', 'internal'), action: 'read', now: 1 },
      { principal: agent, resource: doc('phi', 'phi'), action: 'export', now: 1 },
      { principal: agent, resource: doc('phi', 'phi'), action: 'read', now: 1 },
    ];
    const decisions = simulate(engine, scenarios);
    assert.equal(decisions.length, 3);
    assert.equal(decisions[0]!.effect, 'allow');
    assert.equal(decisions[0]!.ruleId, 'allow-agent-read-low');
    assert.equal(decisions[1]!.effect, 'deny');
    assert.equal(decisions[1]!.ruleId, 'deny-export-restricted');
    assert.equal(decisions[1]!.reason, 'denied by rule deny-export-restricted');
    // phi read without an approval is default-deny (approval-gated allow does not match).
    assert.equal(decisions[2]!.effect, 'deny');
    assert.equal(decisions[2]!.reason, 'no matching allow rule; default deny');
  });

  test('deny reasons are preserved as strings in the typed Decision', () => {
    const engine = createPolicyEngine([]);
    const [d] = simulate(engine, [{ principal: agent, resource: doc('r', 'public'), action: 'read', now: 1 }]);
    assert.equal(d!.effect, 'deny');
    assert.equal(d!.ruleId, undefined);
    assert.equal(d!.reason, 'no matching allow rule; default deny');
  });
});

describe('policy-testing: diffDecisions', () => {
  test('surfaces effect, ruleId, and reason changes separately', () => {
    const before = createPolicyEngine([
      { id: 'allow-all', effect: 'allow', principals: {}, actions: ['read'], resources: {} },
    ]);
    const after = createPolicyEngine([
      { id: 'allow-renamed', effect: 'allow', principals: {}, actions: ['read'], resources: {} },
    ]);
    const scenarios: readonly Scenario[] = [
      { principal: agent, resource: doc('r', 'public'), action: 'read', now: 1 },
    ];
    const diffs = diffDecisions(before, after, scenarios);
    assert.equal(diffs.length, 1);
    assert.equal(diffs[0]!.before.ruleId, 'allow-all');
    assert.equal(diffs[0]!.after.ruleId, 'allow-renamed');
    assert.equal(diffs[0]!.before.effect, 'allow');
    assert.equal(diffs[0]!.after.effect, 'allow');
  });

  test('adding a no-op allow rule produces zero diff entries', () => {
    const allowAll: PolicyRule = {
      id: 'allow-all',
      effect: 'allow',
      principals: {},
      actions: ['*'],
      resources: {},
    };
    const before = createPolicyEngine([allowAll]);
    const noopRule: PolicyRule = {
      id: 'allow-everything-redundant',
      effect: 'allow',
      principals: { kinds: ['agent'] },
      actions: ['read'],
      resources: { ids: ['r'] },
    };
    const after = createPolicyEngine([allowAll, noopRule]);
    const scenarios: readonly Scenario[] = [
      { principal: agent, resource: doc('r', 'public'), action: 'read', now: 1 },
    ];
    const diffs = diffDecisions(before, after, scenarios);
    assert.equal(diffs.length, 0, 'allow-all already matches; a second matching allow is a no-op');
  });

  test('cross-engine: adding a deny rule surfaces effect change', () => {
    const before = createPolicyEngine([
      { id: 'allow-read', effect: 'allow', principals: {}, actions: ['read'], resources: {} },
    ]);
    const after = createPolicyEngine([
      { id: 'allow-read', effect: 'allow', principals: {}, actions: ['read'], resources: {} },
      { id: 'deny-read', effect: 'deny', principals: {}, actions: ['read'], resources: {} },
    ]);
    const scenarios: readonly Scenario[] = [
      { principal: agent, resource: doc('r', 'public'), action: 'read', now: 1 },
    ];
    const diffs = diffDecisions(before, after, scenarios);
    assert.equal(diffs.length, 1);
    assert.equal(diffs[0]!.before.effect, 'allow');
    assert.equal(diffs[0]!.after.effect, 'deny');
    assert.equal(diffs[0]!.after.ruleId, 'deny-read');
  });
});

describe('policy-testing: loadFixtures', () => {
  test('rejects malformed JSON with a file-named error', () => {
    const dir = join(tmpdir(), `pt-malformed-${Date.now()}`);
    mkdirSync(dir, { recursive: true });
    writeFileSync(join(dir, 'bad.json'), '{not json');
    assert.throws(() => loadFixtures(dir), /bad\.json: malformed JSON/);
    rmSync(dir, { recursive: true, force: true });
  });

  test('rejects missing required fields', () => {
    const dir = join(tmpdir(), `pt-missing-${Date.now()}`);
    mkdirSync(dir, { recursive: true });
    writeFileSync(join(dir, 'bad.json'), JSON.stringify({ id: 'x' }));
    assert.throws(() => loadFixtures(dir), /"name" must be a non-empty string/);
    rmSync(dir, { recursive: true, force: true });
  });

  test('rejects action outside domain.ts vocabulary', () => {
    const dir = join(tmpdir(), `pt-action-${Date.now()}`);
    mkdirSync(dir, { recursive: true });
    writeFileSync(join(dir, 'bad.json'), JSON.stringify({
      id: 'x', name: 'x', rules: [],
      scenarios: [{
        principal: { id: 'a', kind: 'agent', tenantId: 't', roles: [], attributes: {} },
        resource: { id: 'r', type: 'document', tenantId: 't', classification: 'public', attributes: {} },
        action: 'has spaces and is invalid',
      }],
      expected: [{ effect: 'deny' }],
    }));
    assert.throws(() => loadFixtures(dir), /action/);
    rmSync(dir, { recursive: true, force: true });
  });

  test('rejects cross-tenant scenario', () => {
    const dir = join(tmpdir(), `pt-cross-${Date.now()}`);
    mkdirSync(dir, { recursive: true });
    writeFileSync(join(dir, 'bad.json'), JSON.stringify({
      id: 'x', name: 'x', rules: [],
      scenarios: [{
        principal: { id: 'a', kind: 'agent', tenantId: 'acme', roles: [], attributes: {} },
        resource: { id: 'r', type: 'document', tenantId: 'globex', classification: 'public', attributes: {} },
        action: 'read',
      }],
      expected: [{ effect: 'deny' }],
    }));
    assert.throws(() => loadFixtures(dir), /cross-tenant/);
    rmSync(dir, { recursive: true, force: true });
  });
});

describe('policy-testing: migrated fixtures', () => {
  test('three migrated fixtures load and pass against their own rules', () => {
    const fixtures = loadFixtures(join(__dirname, 'fixtures', 'policy'));
    assert.equal(fixtures.length, 3);
    const byId = Object.fromEntries(fixtures.map((f) => [f.id, f]));
    for (const f of fixtures) {
      const engine = createPolicyEngine(f.rules, `fixture:${f.id}`);
      const decisions = simulate(engine, f.scenarios);
      assert.equal(decisions.length, f.expected.length, `${f.id}: scenario/decision count`);
      for (let i = 0; i < f.expected.length; i++) {
        const exp = f.expected[i]!;
        const got = decisions[i]!;
        assert.equal(got.effect, exp.effect, `${f.id}[${i}] effect`);
        if (exp.ruleId !== undefined) assert.equal(got.ruleId, exp.ruleId, `${f.id}[${i}] ruleId`);
        if (exp.reason !== undefined) assert.equal(got.reason, exp.reason, `${f.id}[${i}] reason`);
      }
    }
    assert.ok(byId['default-deny-empty']);
    assert.ok(byId['deny-overrides-allow']);
    assert.ok(byId['classification-ceiling']);
  });

  test('one-line overlay on BASELINE_POLICY produces a non-empty diff', () => {
    const baseline = baselineEngine();
    const overlayRules: readonly PolicyRule[] = [
      ...BASELINE_POLICY,
      {
        id: 'deny-agent-read-all-overlay',
        effect: 'deny',
        principals: { kinds: ['agent'] },
        actions: ['read'],
        resources: {},
      },
    ];
    const overlay = createPolicyEngine(overlayRules, 'overlay');
    const scenarios: readonly Scenario[] = [
      { principal: agent, resource: doc('repo-a', 'internal'), action: 'read', now: 1 },
      { principal: agent, resource: doc('repo-b', 'public'), action: 'read', now: 1 },
    ];
    const diffs = diffDecisions(baseline, overlay, scenarios);
    assert.ok(diffs.length > 0, 'overlay must flip at least one baseline decision');
    const flipped = diffs[0]!;
    assert.equal(flipped.before.effect, 'allow');
    assert.equal(flipped.after.effect, 'deny');
    assert.equal(flipped.after.ruleId, 'deny-agent-read-all-overlay');
  });

  test('fixtures still pass when a one-line no-op overlay is added to BASELINE_POLICY', () => {
    const fixtures = loadFixtures(join(__dirname, 'fixtures', 'policy'));
    const baseline = baselineEngine();
    const overlayRules: readonly PolicyRule[] = [
      ...BASELINE_POLICY,
      {
        id: 'allow-user-approve-extra',
        effect: 'allow',
        principals: { kinds: ['user'] },
        actions: ['task.approve'],
        resources: {},
      },
    ];
    const overlay = createPolicyEngine(overlayRules, 'overlay-noop');
    for (const f of fixtures) {
      const scenarios: readonly Scenario[] = f.scenarios;
      const diffs = diffDecisions(baseline, overlay, scenarios);
      assert.equal(diffs.length, 0, `no-op overlay must not change fixture ${f.id}`);
    }
  });
});
