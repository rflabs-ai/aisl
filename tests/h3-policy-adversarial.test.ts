/**
 * H3 — policy evaluation under adversarial conditions (ADR-034).
 *
 * Four properties, each mapped to a ROADMAP failure mode:
 *   determinism          same input, same decision, across engines and processes
 *   order-invariance     the *effect* does not depend on rule declaration order
 *   conflict detection   dead rules, shadowed allows, ambiguous allows
 *   performance bounds   evaluation cost stays bounded as the rule set grows
 *
 * Plus the golden decision set: the versioned oracle that H14's mutation lane
 * consumes. Its teeth are tested here — every single-rule mutation of the
 * baseline must be caught, or the oracle is decoration.
 */

import { test, describe } from 'node:test';
import assert from 'node:assert/strict';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { BASELINE_POLICY, createPolicyEngine, type PolicyRule } from '../src/policy.ts';
import type { Action, Classification, PrincipalKind } from '../src/domain.ts';
import { KNOWN_ACTIONS, KNOWN_CLASSIFICATIONS } from '../src/domain.ts';
import { analyzePolicy } from '../src/policy-analysis.ts';
import { goldenHash, loadGolden, simulate, verifyGolden, type Golden } from '../src/policy-testing.ts';
import { policyBundleHash, loadPolicyBundle, type PolicyBundle } from '../src/policy-config.ts';

const __dirname = dirname(fileURLToPath(import.meta.url));
const GOLDEN = join(__dirname, 'fixtures', 'policy', 'goldens', 'baseline-decisions.json');
const NOW = 1748736000000;

/** Deterministic PRNG — a fuzz test that cannot be replayed is a rumour. */
function mulberry32(seed: number): () => number {
  let a = seed >>> 0;
  return () => {
    a = (a + 0x6d2b79f5) >>> 0;
    let t = a;
    t = Math.imul(t ^ (t >>> 15), t | 1);
    t ^= t + Math.imul(t ^ (t >>> 7), t | 61);
    return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
  };
}

const pick = <T,>(rand: () => number, xs: readonly T[]): T => xs[Math.floor(rand() * xs.length)]!;

const KINDS: readonly PrincipalKind[] = ['user', 'agent', 'service'];

function randomContext(rand: () => number) {
  return {
    principal: {
      id: `${pick(rand, KINDS)}:fuzz-${Math.floor(rand() * 5)}`,
      kind: pick(rand, KINDS),
      tenantId: 'acme',
      roles: rand() < 0.5 ? [] : ['worker'],
      attributes: {},
    },
    resource: {
      id: `doc:fuzz-${Math.floor(rand() * 5)}`,
      type: 'document' as const,
      tenantId: 'acme',
      classification: pick(rand, KNOWN_CLASSIFICATIONS) as Classification,
      attributes: {},
    },
    action: pick(rand, KNOWN_ACTIONS) as Action,
    now: NOW,
  };
}

const rule = (id: string, effect: 'allow' | 'deny', over: Partial<PolicyRule> = {}): PolicyRule => ({
  id,
  effect,
  principals: { kinds: ['agent'] },
  actions: ['read'],
  resources: {},
  ...over,
});

describe('H3: determinism', () => {
  test('500 random contexts: two independent engines decide identically', () => {
    const rand = mulberry32(0x5eed);
    const a = createPolicyEngine(BASELINE_POLICY, 'a');
    const b = createPolicyEngine(BASELINE_POLICY, 'b');
    for (let i = 0; i < 500; i++) {
      const ctx = randomContext(rand);
      assert.deepEqual(a.evaluate(ctx), b.evaluate(ctx), `context ${i}`);
    }
  });

  test('the same engine returns identical results on repeat evaluation', () => {
    const rand = mulberry32(0xbeef);
    const engine = createPolicyEngine(BASELINE_POLICY);
    for (let i = 0; i < 200; i++) {
      const ctx = randomContext(rand);
      assert.deepEqual(engine.evaluate(ctx), engine.evaluate(ctx), `context ${i}`);
    }
  });

  test('no state leaks between decisions: a denial does not change the next answer', () => {
    const engine = createPolicyEngine(BASELINE_POLICY);
    const allow = {
      principal: { id: 'agent:a', kind: 'agent' as const, tenantId: 'acme', roles: [], attributes: {} },
      resource: { id: 'd', type: 'document' as const, tenantId: 'acme', classification: 'internal' as const, attributes: {} },
      action: 'read' as const,
      now: NOW,
    };
    const before = engine.evaluate(allow);
    engine.evaluate({ ...allow, resource: { ...allow.resource, classification: 'phi' } });
    assert.deepEqual(engine.evaluate(allow), before);
  });
});

describe('H3: rule declaration order', () => {
  test('the EFFECT is order-invariant under permutation (deny-overrides, default deny)', () => {
    const rand = mulberry32(0x1234);
    const forward = createPolicyEngine(BASELINE_POLICY, 'forward');
    const reversed = createPolicyEngine([...BASELINE_POLICY].reverse(), 'reversed');
    for (let i = 0; i < 200; i++) {
      const ctx = randomContext(rand);
      assert.equal(forward.evaluate(ctx).effect, reversed.evaluate(ctx).effect, `context ${i}`);
    }
  });

  test('attribution is NOT order-invariant when allows overlap — the named limitation', () => {
    // Both rules allow an agent read of internal material; which one is credited
    // depends on declaration order. ADR-034 detects this (ambiguous-allow)
    // rather than changing audit semantics here.
    const a = rule('rule-a', 'allow');
    const b = rule('rule-b', 'allow');
    const ctx = {
      principal: { id: 'agent:x', kind: 'agent' as const, tenantId: 'acme', roles: [], attributes: {} },
      resource: { id: 'd', type: 'document' as const, tenantId: 'acme', classification: 'internal' as const, attributes: {} },
      action: 'read' as const,
      now: NOW,
    };
    const first = createPolicyEngine([a, b]).evaluate(ctx);
    const second = createPolicyEngine([b, a]).evaluate(ctx);
    assert.equal(first.effect, 'allow');
    assert.equal(second.effect, 'allow');
    assert.equal(first.ruleId, 'rule-a');
    assert.equal(second.ruleId, 'rule-b');
    // And the analyzer says so.
    const analysis = analyzePolicy([a, b]);
    assert.equal(analysis.errors, 0);
    assert.equal(analysis.warnings, 1);
    assert.equal(analysis.findings[0]!.kind, 'ambiguous-allow');
  });
});

describe('H3: conflict detection', () => {
  test('BASELINE_POLICY has no dead or shadowed rules (error-free)', () => {
    const analysis = analyzePolicy(BASELINE_POLICY);
    assert.equal(analysis.errors, 0, JSON.stringify(analysis.findings, null, 2));
    assert.ok(analysis.points > 0);
    // The one known ambiguity is the overlapping read allows, and it is reported.
    assert.equal(analysis.warnings, 1);
    assert.deepEqual([...analysis.findings[0]!.rules].sort(), [
      'allow-agent-read-low',
      'allow-agent-read-sensitive-with-approval',
    ]);
  });

  test('an allow covered by a deny is reported as shadowed (error)', () => {
    const analysis = analyzePolicy([rule('allow-x', 'allow'), rule('deny-all', 'deny')]);
    assert.equal(analysis.errors, 1);
    assert.equal(analysis.findings[0]!.kind, 'shadowed');
    assert.deepEqual(analysis.findings[0]!.rules, ['allow-x']);
  });

  test('a deny shadowing only part of an allow is not an error', () => {
    const analysis = analyzePolicy([
      rule('allow-read', 'allow'),
      rule('deny-phi', 'deny', { resources: { maxClassification: 'internal' } }),
    ]);
    // The allow still fires above `internal`, so it is not entombed.
    assert.equal(analysis.errors, 0);
  });

  test('a rule naming an action outside the vocabulary is a warning', () => {
    const analysis = analyzePolicy([rule('typo', 'allow', { actions: ['raed'] })]);
    assert.equal(analysis.findings[0]!.kind, 'unknown-action');
    assert.equal(analysis.findings[0]!.severity, 'warn');
    assert.match(analysis.findings[0]!.detail, /raed/);
  });

  test('a clean single-rule policy reports nothing', () => {
    const analysis = analyzePolicy([rule('only', 'allow')]);
    assert.deepEqual(analysis.findings, []);
  });

  test('analysis agrees with the engine about idPatterns (no second matcher)', () => {
    const ctx = (id: string) => ({
      principal: { id: 'agent:a', kind: 'agent' as const, tenantId: 'acme', roles: [], attributes: {} },
      resource: { id, type: 'document' as const, tenantId: 'acme', classification: 'internal' as const, attributes: {} },
      action: 'read' as const,
      now: NOW,
    });

    // A deny covering only `acme/secret/...` leaves the pattern allow alive.
    const partial = [
      rule('allow-acme', 'allow', { resources: { idPatterns: ['acme/...'] } }),
      rule('deny-acme-secret', 'deny', { resources: { idPatterns: ['acme/secret/...'] } }),
    ];
    assert.equal(createPolicyEngine(partial).evaluate(ctx('acme/other')).effect, 'allow');
    assert.equal(analyzePolicy(partial).errors, 0);

    // The same pattern on both rules entombs the allow — the analyzer must say
    // so, which it can only do if it compiles patterns exactly like the engine.
    const total = [
      rule('allow-acme2', 'allow', { resources: { idPatterns: ['acme/...'] } }),
      rule('deny-acme-all', 'deny', { resources: { idPatterns: ['acme/...'] } }),
    ];
    assert.equal(createPolicyEngine(total).evaluate(ctx('acme/other')).effect, 'deny');
    const analysis = analyzePolicy(total);
    assert.equal(analysis.errors, 1);
    assert.equal(analysis.findings[0]!.kind, 'shadowed');
  });
});

describe('H3: conflict detection on load', () => {
  const bundle = (rules: readonly PolicyRule[]): PolicyBundle => {
    const partial = {
      id: 'test-bundle',
      version: 1,
      provenance: { source: 'test' },
      rules,
    };
    return { ...partial, hash: policyBundleHash(partial) } as PolicyBundle;
  };

  test('a hash-verified bundle with a dead allow is refused before an engine exists', () => {
    const b = bundle([rule('allow-x', 'allow'), rule('deny-all', 'deny')]);
    assert.throws(() => loadPolicyBundle(b), /refused: 1 dead or shadowed rule/);
  });

  test('a clean bundle loads', () => {
    assert.doesNotThrow(() => loadPolicyBundle(bundle([rule('allow-a', 'allow')])));
  });

  test('a malformed rule is refused with a bundle error, not a TypeError', () => {
    const b = bundle([{ id: 'broken' } as unknown as PolicyRule]);
    assert.throws(() => loadPolicyBundle(b), /rules\[0\] "effect"/);
  });

  test('the hash is verified before analysis runs', () => {
    const b = bundle([rule('allow-x', 'allow')]);
    assert.throws(() => loadPolicyBundle({ ...b, hash: 'deadbeef' }), /hash mismatch/);
  });
});

describe('H3: performance bounds', () => {
  const bigRules: PolicyRule[] = Array.from({ length: 2000 }, (_, i) =>
    rule(`r${i}`, 'allow', {
      principals: { kinds: ['agent'], ids: [`agent:${i}`] },
      resources: { ids: [`doc:${i}`] },
    }),
  );

  test('2000 rules x 2000 decisions stay inside the bound', () => {
    const engine = createPolicyEngine(bigRules, 'big');
    const ctx = {
      principal: { id: 'agent:1999', kind: 'agent' as const, tenantId: 'acme', roles: [], attributes: {} },
      resource: { id: 'doc:1999', type: 'document' as const, tenantId: 'acme', classification: 'internal' as const, attributes: {} },
      action: 'read' as const,
      now: NOW,
    };
    const started = performance.now();
    for (let i = 0; i < 2000; i++) engine.evaluate(ctx);
    const elapsed = performance.now() - started;
    // Generous on purpose: this catches an order-of-magnitude regression or an
    // accidental per-decision compile, not micro-noise on shared hardware.
    assert.ok(elapsed < 5000, `2000x2000 took ${elapsed.toFixed(0)}ms`);
    assert.equal(engine.evaluate(ctx).effect, 'allow');
  });

  test('the compile cache does not grow on the decision path', () => {
    const engine = createPolicyEngine(
      [rule('pattern', 'allow', { resources: { idPatterns: ['acme/...'] } })],
      'cache',
    );
    const before = engine._compileCacheSize();
    for (let i = 0; i < 1000; i++) {
      engine.evaluate({
        principal: { id: 'agent:a', kind: 'agent', tenantId: 'acme', roles: [], attributes: {} },
        resource: { id: `acme/x/${i}`, type: 'document', tenantId: 'acme', classification: 'internal', attributes: {} },
        action: 'read',
        now: NOW,
      });
    }
    assert.equal(engine._compileCacheSize(), before);
  });

  test('a deeply nested id is evaluated in bounded time (no catastrophic backtracking)', () => {
    const engine = createPolicyEngine([rule('deep', 'allow', { resources: { idPatterns: ['acme/...'] } })]);
    const deep = `acme/${Array.from({ length: 500 }, (_, i) => `seg${i}`).join('/')}`;
    const started = performance.now();
    const result = engine.evaluate({
      principal: { id: 'agent:a', kind: 'agent', tenantId: 'acme', roles: [], attributes: {} },
      resource: { id: deep, type: 'document', tenantId: 'acme', classification: 'internal', attributes: {} },
      action: 'read',
      now: NOW,
    });
    assert.ok(performance.now() - started < 50, 'deep id evaluation is bounded');
    assert.equal(result.effect, 'allow');
  });
});

describe('H3: versioned golden decision set', () => {
  test('the committed golden matches the engine exactly', () => {
    const golden: Golden = loadGolden(GOLDEN);
    assert.equal(golden.version, 1);
    assert.equal(golden.policyId, 'baseline');
    assert.equal(golden.policyHash, goldenHash(BASELINE_POLICY));
    const verification = verifyGolden(golden);
    assert.equal(verification.hashMatches, true);
    assert.deepEqual(verification.mismatches, []);
    assert.ok(golden.expected.length >= 8);
  });

  test('the golden is bound to its rule set: a re-hashed policy is not the same golden', () => {
    const golden = loadGolden(GOLDEN);
    const tampered: Golden = { ...golden, rules: [...golden.rules, rule('injected', 'deny', { actions: ['*'] })] };
    assert.equal(verifyGolden(tampered).hashMatches, false);
  });

  test('the golden catches every single-rule mutation — the oracle has teeth', () => {
    const golden = loadGolden(GOLDEN);
    for (let i = 0; i < golden.rules.length; i++) {
      const original = golden.rules[i]!;
      const flipped: PolicyRule = { ...original, effect: original.effect === 'allow' ? 'deny' : 'allow' };
      const mutated: Golden = { ...golden, rules: golden.rules.map((r, j) => (j === i ? flipped : r)) };
      assert.ok(
        verifyGolden(mutated).mismatches.length > 0,
        `flipping ${original.id} was not caught by the golden set`,
      );

      const dropped: Golden = { ...golden, rules: golden.rules.filter((_, j) => j !== i) };
      assert.ok(
        verifyGolden(dropped).mismatches.length > 0,
        `deleting ${original.id} was not caught by the golden set`,
      );
    }
  });
});
