/**
 * M5 — Hierarchical resource matching.
 *
 * The grammar:
 *   `tenant/...`  recursive — any id strictly under `tenant/` (slash is the boundary)
 *   `prefix*`     single-segment glob — `*` matches a run of non-slash characters
 *   `prefix?`     single-character wildcard — `?` matches one non-slash character
 *   literal       exact match
 *
 * Reuses the existing `NO_MATCH` default-deny flow. The new matcher widens
 * which rules *apply*; it does not widen which resources a *capability* may
 * reach (capability `resourceIds` still list explicit ids).
 */

import { test, describe } from 'node:test';
import assert from 'node:assert/strict';
import {
  compileIdPattern,
  createPolicyEngine,
  matchesIdPattern,
  PolicyCompilationError,
  type PolicyRule,
} from '../src/policy.ts';
import { type Principal, type Resource } from '../src/domain.ts';
import { mockAuth } from '../src/testing.ts';

const agentAuth = mockAuth({ subject: 'agent:a' });
const agent: Principal = {
  id: 'agent:a',
  kind: 'agent',
  tenantId: 'acme',
  roles: [],
  attributes: {},
  auth: agentAuth,
};

function res(id: string, type: 'document' | 'repository' = 'document', tenantId = 'acme'): Resource {
  return { id, type, tenantId, classification: 'internal', attributes: {} };
}

const NOW = Date.UTC(2026, 0, 1);

type EngineWithDebug = ReturnType<typeof createPolicyEngine> & { _compileCacheSize(): number };

describe('matchesIdPattern: grammar', () => {
  test('recursive tenant/... matches any id strictly under tenant/', () => {
    const m = compileIdPattern('acme/...');
    assert.equal(matchesIdPattern('acme/foo', m), true);
    assert.equal(matchesIdPattern('acme/foo/bar', m), true);
    assert.equal(matchesIdPattern('acme/foo/bar/baz', m), true);
  });

  test('recursive tenant/... does not cross the / boundary', () => {
    const m = compileIdPattern('acme/...');
    assert.equal(matchesIdPattern('acme-other', m), false);
    assert.equal(matchesIdPattern('acmefoo', m), false);
    assert.equal(matchesIdPattern('acme', m), false);
    assert.equal(matchesIdPattern('acme/', m), false);
    assert.equal(matchesIdPattern('other/acme/foo', m), false);
  });

  test('single-segment glob tenant/* matches one segment only', () => {
    const m = compileIdPattern('acme/*');
    assert.equal(matchesIdPattern('acme/foo', m), true);
    assert.equal(matchesIdPattern('acme/foo/bar', m), false);
    assert.equal(matchesIdPattern('acme/foo/bar/baz', m), false);
    assert.equal(matchesIdPattern('acme-thing', m), false, 'wildcard does not cross boundary');
  });

  test('literal pattern is exact match', () => {
    const m = compileIdPattern('foo');
    assert.equal(matchesIdPattern('foo', m), true);
    assert.equal(matchesIdPattern('foobar', m), false);
    assert.equal(matchesIdPattern('barfoo', m), false);
  });

  test('? wildcard matches exactly one non-slash character', () => {
    const m = compileIdPattern('foo?');
    assert.equal(matchesIdPattern('foo1', m), true);
    assert.equal(matchesIdPattern('foo!', m), true);
    assert.equal(matchesIdPattern('foo12', m), false);
    assert.equal(matchesIdPattern('foo/', m), false);
  });
});

describe('compileIdPattern: rejection', () => {
  test('patterns longer than 64 characters throw PolicyCompilationError', () => {
    assert.throws(() => compileIdPattern('a'.repeat(65)), PolicyCompilationError);
  });

  test('nested wildcards ** throw', () => {
    assert.throws(() => compileIdPattern('**/foo'), PolicyCompilationError);
    assert.throws(() => compileIdPattern('foo/**/bar'), PolicyCompilationError);
    assert.throws(() => compileIdPattern('foo**bar'), PolicyCompilationError);
  });

  test('unsupported characters throw', () => {
    assert.throws(() => compileIdPattern('foo[bar]'), PolicyCompilationError);
    assert.throws(() => compileIdPattern('foo$'), PolicyCompilationError);
    assert.throws(() => compileIdPattern('foo|bar'), PolicyCompilationError);
    assert.throws(() => compileIdPattern('foo(bar)'), PolicyCompilationError);
    assert.throws(() => compileIdPattern('foo+bar'), PolicyCompilationError);
  });

  test('recursive pattern without the / boundary throws', () => {
    assert.throws(() => compileIdPattern('acme...'), PolicyCompilationError);
    assert.throws(() => compileIdPattern('acme.foo...'), PolicyCompilationError);
  });
});

describe('createPolicyEngine with idPatterns', () => {
  test('accepts a rule with idPatterns and compiles it', () => {
    const engine = createPolicyEngine([
      { id: 'allow-acme', effect: 'allow', principals: {}, actions: ['read'], resources: { idPatterns: ['acme/...'] } },
    ]) as EngineWithDebug;
    assert.equal(engine._compileCacheSize(), 1);
  });

  test('compile-time rejection: pathological pattern throws PolicyCompilationError', () => {
    assert.throws(
      () =>
        createPolicyEngine([
          {
            id: 'allow-bad',
            effect: 'allow',
            principals: {},
            actions: ['read'],
            resources: { idPatterns: ['a'.repeat(65)] },
          },
        ]),
      PolicyCompilationError,
    );
  });

  test('recursive idPatterns allow deeply nested ids and reject the boundary', () => {
    const rules: PolicyRule[] = [
      { id: 'allow-acme', effect: 'allow', principals: {}, actions: ['read'], resources: { idPatterns: ['acme/...'] } },
    ];
    const engine = createPolicyEngine(rules);
    assert.equal(engine.evaluate({ principal: agent, resource: res('acme/foo'), action: 'read', now: NOW }).effect, 'allow');
    assert.equal(engine.evaluate({ principal: agent, resource: res('acme/foo/bar'), action: 'read', now: NOW }).effect, 'allow');
    assert.equal(engine.evaluate({ principal: agent, resource: res('acme-other'), action: 'read', now: NOW }).effect, 'deny');
    assert.equal(engine.evaluate({ principal: agent, resource: res('acmefoo'), action: 'read', now: NOW }).effect, 'deny');
  });

  test('single-segment glob allows one segment and denies nested', () => {
    const rules: PolicyRule[] = [
      { id: 'allow-acme-single', effect: 'allow', principals: {}, actions: ['read'], resources: { idPatterns: ['acme/*'] } },
    ];
    const engine = createPolicyEngine(rules);
    assert.equal(engine.evaluate({ principal: agent, resource: res('acme/foo'), action: 'read', now: NOW }).effect, 'allow');
    assert.equal(engine.evaluate({ principal: agent, resource: res('acme/foo/bar'), action: 'read', now: NOW }).effect, 'deny');
  });

  test('type filter combines with idPatterns', () => {
    const rules: PolicyRule[] = [
      {
        id: 'allow-repo-acme',
        effect: 'allow',
        principals: {},
        actions: ['read'],
        resources: { types: ['repository'], idPatterns: ['acme/...'] },
      },
    ];
    const engine = createPolicyEngine(rules);
    assert.equal(
      engine.evaluate({ principal: agent, resource: res('acme/foo', 'repository'), action: 'read', now: NOW }).effect,
      'allow',
    );
    assert.equal(
      engine.evaluate({ principal: agent, resource: res('acme/foo', 'document'), action: 'read', now: NOW }).effect,
      'deny',
      'type filter rejects documents even when id matches',
    );
  });

  test('ids and idPatterns are OR-combined within one rule', () => {
    const rules: PolicyRule[] = [
      {
        id: 'allow-mixed',
        effect: 'allow',
        principals: {},
        actions: ['read'],
        resources: { ids: ['literal-id'], idPatterns: ['acme/...'] },
      },
    ];
    const engine = createPolicyEngine(rules);
    assert.equal(engine.evaluate({ principal: agent, resource: res('literal-id'), action: 'read', now: NOW }).effect, 'allow');
    assert.equal(engine.evaluate({ principal: agent, resource: res('acme/foo'), action: 'read', now: NOW }).effect, 'allow');
    assert.equal(engine.evaluate({ principal: agent, resource: res('other-id'), action: 'read', now: NOW }).effect, 'deny');
  });

  test('a rule with only idPatterns matches only by pattern (no ids fallback)', () => {
    const rules: PolicyRule[] = [
      { id: 'allow-patterns-only', effect: 'allow', principals: {}, actions: ['read'], resources: { idPatterns: ['acme/...'] } },
    ];
    const engine = createPolicyEngine(rules);
    assert.equal(engine.evaluate({ principal: agent, resource: res('acme/x'), action: 'read', now: NOW }).effect, 'allow');
    assert.equal(engine.evaluate({ principal: agent, resource: res('literal-only'), action: 'read', now: NOW }).effect, 'deny');
  });

  test('hot-path: evaluate() does not grow the compile cache', () => {
    const engine = createPolicyEngine([
      { id: 'allow-acme', effect: 'allow', principals: {}, actions: ['read'], resources: { idPatterns: ['acme/...'] } },
    ]) as EngineWithDebug;
    const sizeBefore = engine._compileCacheSize();
    for (let i = 0; i < 100; i++) {
      engine.evaluate({ principal: agent, resource: res('acme/foo'), action: 'read', now: NOW });
      engine.evaluate({ principal: agent, resource: res('acme/foo/bar/baz'), action: 'read', now: NOW });
      engine.evaluate({ principal: agent, resource: res('acme-other'), action: 'read', now: NOW });
    }
    assert.equal(engine._compileCacheSize(), sizeBefore, 'cache size must be stable across evaluations');
  });

  test('deny rule with idPatterns still denies', () => {
    const rules: PolicyRule[] = [
      { id: 'allow-all', effect: 'allow', principals: {}, actions: ['read'], resources: {} },
      { id: 'deny-acme-other', effect: 'deny', principals: {}, actions: ['read'], resources: { idPatterns: ['acme-other...'] } },
    ];
    assert.throws(() => createPolicyEngine(rules), PolicyCompilationError, 'malformed recursive pattern is caught at compile time');
  });

  test('a properly formed deny rule with idPatterns still denies', () => {
    const rules: PolicyRule[] = [
      { id: 'allow-all', effect: 'allow', principals: {}, actions: ['read'], resources: {} },
      { id: 'deny-acme-other', effect: 'deny', principals: {}, actions: ['read'], resources: { idPatterns: ['acme-other/...'] } },
    ];
    const engine = createPolicyEngine(rules);
    assert.equal(engine.evaluate({ principal: agent, resource: res('acme-other/foo'), action: 'read', now: NOW }).effect, 'deny');
    assert.equal(engine.evaluate({ principal: agent, resource: res('acme/foo'), action: 'read', now: NOW }).effect, 'allow');
  });
});
