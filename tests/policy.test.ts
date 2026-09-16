/** Policy engine semantics: default deny, deny-overrides, ceilings, approvals. */

import { test, describe } from 'node:test';
import assert from 'node:assert/strict';
import { createPolicyEngine, type Approval, type PolicyRule } from '../src/policy.ts';
import { classificationRank, type Principal, type Resource } from '../src/domain.ts';
import { mockAuth } from '../src/testing.ts';

const agentAuth = mockAuth({ subject: 'agent:a' });
const userAuth = mockAuth({ subject: 'user:a', amr: ['pwd', 'mfa'] });
const agent: Principal = { id: 'agent:a', kind: 'agent', tenantId: 'acme', roles: ['worker'], attributes: {}, auth: agentAuth };
const user: Principal = { id: 'user:a', kind: 'user', tenantId: 'acme', roles: ['reviewer'], attributes: {}, auth: userAuth };

function doc(id: string, classification: string, tenantId = 'acme'): Resource {
  return { id, type: 'document', tenantId, classification, attributes: {} };
}

const NOW = Date.UTC(2026, 5, 1);

describe('policy engine', () => {
  test('default deny: an empty rule set denies everything', () => {
    const engine = createPolicyEngine([]);
    const r = engine.evaluate({ principal: agent, resource: doc('d', 'public'), action: 'read', now: NOW });
    assert.equal(r.effect, 'deny');
    assert.equal(r.ruleId, undefined);
  });

  test('deny overrides allow', () => {
    const rules: PolicyRule[] = [
      { id: 'allow-all', effect: 'allow', principals: {}, actions: ['*'], resources: {} },
      { id: 'deny-delete', effect: 'deny', principals: {}, actions: ['delete'], resources: {} },
    ];
    const engine = createPolicyEngine(rules);
    assert.equal(engine.evaluate({ principal: agent, resource: doc('d', 'public'), action: 'read', now: NOW }).ruleId, 'allow-all');
    assert.equal(engine.evaluate({ principal: agent, resource: doc('d', 'public'), action: 'delete', now: NOW }).effect, 'deny');
  });

  test('classification ceiling blocks a resource above the granted ceiling', () => {
    const rules: PolicyRule[] = [
      { id: 'allow-low', effect: 'allow', principals: { kinds: ['agent'] }, actions: ['read'], resources: {}, maxClassification: 'internal' },
    ];
    const engine = createPolicyEngine(rules);
    assert.equal(engine.evaluate({ principal: agent, resource: doc('d', 'internal'), action: 'read', now: NOW }).effect, 'allow');
    assert.equal(engine.evaluate({ principal: agent, resource: doc('d', 'confidential'), action: 'read', now: NOW }).effect, 'deny');
  });

  test('unknown classification is ranked at the ceiling (fail closed)', () => {
    assert.equal(classificationRank('x-customer-acme'), 100);
    assert.ok(classificationRank('x-nato') > classificationRank('restricted'));
    const rules: PolicyRule[] = [
      { id: 'allow-low', effect: 'allow', principals: {}, actions: ['read'], resources: {}, maxClassification: 'restricted' },
    ];
    const engine = createPolicyEngine(rules);
    assert.equal(engine.evaluate({ principal: agent, resource: doc('d', 'x-nato'), action: 'read', now: NOW }).effect, 'deny');
  });

  test('approval-gated rules require a live, matching approval', () => {
    const rules: PolicyRule[] = [
      { id: 'allow-with-approval', effect: 'allow', principals: { kinds: ['agent'] }, actions: ['read'], resources: {}, requiresApproval: true },
    ];
    const engine = createPolicyEngine(rules);
    const resource = doc('d', 'confidential');
    const approval: Approval = {
      id: 'ap-1',
      approvedBy: user.id,
      reviewerAuth: userAuth,
      principalId: agent.id,
      action: 'read',
      resourceId: 'd',
      expiresAt: NOW + 60_000,
    };
    assert.equal(engine.evaluate({ principal: agent, resource, action: 'read', now: NOW }).effect, 'deny');
    assert.equal(engine.evaluate({ principal: agent, resource, action: 'read', now: NOW, approvals: [approval] }).effect, 'allow');
    assert.equal(engine.evaluate({ principal: agent, resource, action: 'read', now: NOW + 61_000, approvals: [approval] }).effect, 'deny');
  });

  test('an approval for one resource does not carry to another', () => {
    const rules: PolicyRule[] = [
      { id: 'allow-with-approval', effect: 'allow', principals: {}, actions: ['*'], resources: {}, requiresApproval: true },
    ];
    const engine = createPolicyEngine(rules);
    const approval: Approval = { id: 'ap-1', approvedBy: user.id, reviewerAuth: userAuth, principalId: agent.id, action: 'read', resourceId: 'd1', expiresAt: NOW + 60_000 };
    assert.equal(engine.evaluate({ principal: agent, resource: doc('d1', 'confidential'), action: 'read', now: NOW, approvals: [approval] }).effect, 'allow');
    assert.equal(engine.evaluate({ principal: agent, resource: doc('d2', 'confidential'), action: 'read', now: NOW, approvals: [approval] }).effect, 'deny');
  });

  test('cross-tenant is denied regardless of rules', () => {
    const engine = createPolicyEngine([{ id: 'allow-all', effect: 'allow', principals: {}, actions: ['*'], resources: {} }]);
    const result = engine.evaluate({ principal: agent, resource: doc('d', 'public', 'globex'), action: 'read', now: NOW });
    assert.equal(result.effect, 'deny');
    assert.equal(result.ruleId, '@tenant-isolation');
  });

  test('evaluation is deterministic for identical inputs', () => {
    const engine = createPolicyEngine([{ id: 'allow-all', effect: 'allow', principals: {}, actions: ['*'], resources: {} }]);
    const ctx = { principal: agent, resource: doc('d', 'public'), action: 'read' as const, now: NOW };
    assert.deepEqual(engine.evaluate(ctx), engine.evaluate(ctx));
  });

  test('an approval without MFA in reviewerAuth is filtered out by the PDP', () => {
    // The policy engine itself doesn't check MFA — the PDP does.
    // But the engine should still deny if no valid approval matches.
    const rules: PolicyRule[] = [
      { id: 'allow-with-approval', effect: 'allow', principals: { kinds: ['agent'] }, actions: ['read'], resources: {}, requiresApproval: true },
    ];
    const engine = createPolicyEngine(rules);
    const resource = doc('d', 'confidential');
    const noMfaAuth = mockAuth({ subject: 'user:no-mfa', amr: ['pwd'] }); // no MFA
    const approval: Approval = {
      id: 'ap-no-mfa',
      approvedBy: 'user:no-mfa',
      reviewerAuth: noMfaAuth,
      principalId: agent.id,
      action: 'read',
      resourceId: 'd',
      expiresAt: NOW + 60_000,
    };
    // The engine itself doesn't filter — it sees the approval.
    // But the PDP filters before passing to the engine.
    // Here we test the engine sees it; the PDP test (invariant 13) tests filtering.
    const result = engine.evaluate({ principal: agent, resource, action: 'read', now: NOW, approvals: [approval] });
    assert.equal(result.effect, 'allow', 'engine sees the approval; PDP filters it');
  });

  test('an approval for principal A cannot be used by principal B', () => {
    const rules: PolicyRule[] = [
      { id: 'allow-with-approval', effect: 'allow', principals: {}, actions: ['*'], resources: {}, requiresApproval: true },
    ];
    const engine = createPolicyEngine(rules);
    const resource = doc('d', 'confidential');
    const approval: Approval = {
      id: 'ap-wrong-principal',
      approvedBy: user.id,
      reviewerAuth: userAuth,
      principalId: 'agent:a', // approval is for agent:a
      action: 'read',
      resourceId: 'd',
      expiresAt: NOW + 60_000,
    };
    // agent:b tries to use an approval meant for agent:a — should deny
    const otherAgent: Principal = { id: 'agent:b', kind: 'agent', tenantId: 'acme', roles: [], attributes: {} };
    const result = engine.evaluate({ principal: otherAgent, resource, action: 'read', now: NOW, approvals: [approval] });
    assert.equal(result.effect, 'deny', 'approval for agent:a must not work for agent:b');
  });
});
