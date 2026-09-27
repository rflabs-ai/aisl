/** M11 Granular RBAC: roles bound issuance, policy cross-validates against them. */

import { test, describe } from 'node:test';
import assert from 'node:assert/strict';
import {
  BASELINE_ROLES,
  PolicyCompilationError,
  createPolicyEngine,
  type PolicyRule,
} from '../src/policy.ts';
import {
  CapabilityIssuanceError,
  issueRequestForRole,
  verifyCapability,
} from '../src/capability.ts';
import { type Principal, classificationRank } from '../src/domain.ts';
import { testWorld } from '../src/testing.ts';

describe('M11: role-templated issuance', () => {
  test('role caps issuance: omitted classification mints at the role ceiling, narrower requests win', () => {
    const world = testWorld();
    const at = world.clock.now();
    const capped = world.authorization.issueForRole(
      world.root,
      'worker',
      world.agent.id,
      [world.resources.repoA!],
      { actions: ['read'], expiresAt: at + 60_000, provenance: { source: 'policy-grant' } },
    );
    assert.equal(capped.maxClassification, 'internal');

    const narrower = world.authorization.issueForRole(
      world.root,
      'worker',
      world.agent.id,
      [world.resources.repoA!],
      {
        actions: ['read'],
        maxClassification: 'public',
        expiresAt: at + 60_000,
        provenance: { source: 'policy-grant' },
      },
    );
    assert.equal(narrower.maxClassification, 'public');
  });

  test('over-privileged issuance throws: action outside the role, classification above the ceiling', () => {
    const world = testWorld();
    const at = world.clock.now();
    const opts = {
      actions: ['read'] as const,
      expiresAt: at + 60_000,
      provenance: { source: 'policy-grant' as const },
    };

    assert.throws(
      () =>
        world.authorization.issueForRole(
      world.root, 'worker', world.agent.id, [world.resources.repoA!], {
          ...opts,
          actions: ['read', 'export'],
        }),
      CapabilityIssuanceError,
    );
    assert.throws(
      () =>
        world.authorization.issueForRole(
      world.root, 'worker', world.agent.id, [world.resources.repoA!], {
          ...opts,
          maxClassification: 'phi',
        }),
      CapabilityIssuanceError,
    );
  });

  test('unknown role fails closed', () => {
    const world = testWorld();
    assert.throws(
      () =>
        world.authorization.issueForRole(
      world.root,
          'role:does-not-exist',
          world.agent.id,
          [world.resources.repoA!],
          { actions: ['read'], expiresAt: world.clock.now() + 60_000, provenance: { source: 'policy-grant' } },
        ),
      CapabilityIssuanceError,
    );
  });

  test('roles are tenant-scoped: a role bound to another tenant is not visible', () => {
    const roles = [
      { id: 'globex-only', tenantId: 'globex', actions: ['read'] as const, maxClassification: 'internal' as const },
    ];
    const acmeIssuer: Principal = { id: 'user:acme-1', kind: 'user', tenantId: 'acme', roles: [], attributes: {} };
    const globexIssuer: Principal = { id: 'user:globex-1', kind: 'user', tenantId: 'globex', roles: [], attributes: {} };
    const opts = { actions: ['read'] as const, expiresAt: Date.now() + 60_000, provenance: { source: 'policy-grant' as const } };

    assert.throws(
      () => issueRequestForRole(roles, acmeIssuer, 'globex-only', 'agent:x', ['r:x'], opts),
      CapabilityIssuanceError,
    );
    const req = issueRequestForRole(roles, globexIssuer, 'globex-only', 'agent:x', ['r:x'], opts);
    assert.equal(req.tenantId, 'globex');
  });

  test('roles never mint: issuer-kind and attenuation checks apply unchanged', () => {
    const world = testWorld();
    const at = world.clock.now();
    const opts = {
      actions: ['read'] as const,
      expiresAt: at + 60_000,
      provenance: { source: 'policy-grant' as const },
    };

    assert.throws(
      () => world.authorization.issueForRole(world.agent, 'worker', world.agent.id, [world.resources.repoA!], opts),
      (e: unknown) => e instanceof CapabilityIssuanceError && /may not issue/.test(e.message),
    );

    const service: Principal = { id: 'svc:ci', kind: 'service', tenantId: 'acme', roles: ['worker'], attributes: {} };
    assert.throws(
      () => world.authorization.issueForRole(service, 'worker', world.agent.id, [world.resources.repoA!], opts),
      (e: unknown) => e instanceof CapabilityIssuanceError && /must present its own authority/.test(e.message),
    );
    // H1 (ADR-023): the issuer attenuates against its own signed capability.
    // The parent holds 'write' but not 'read', so a role request for 'read'
    // overreaches — proven against a signed artifact, not a declared object.
    const weakParent = world.authorization.issue(world.root, {
      subject: service.id,
      tenantId: 'acme',
      resourceIds: [world.resources.repoA!],
      actions: ['write'],
      maxClassification: 'internal',
      expiresAt: at + 60_000,
      provenance: { source: 'policy-grant' },
    });
    assert.throws(
      () =>
        world.authorization.issueForRole(service, 'worker', world.agent.id, [world.resources.repoA!], opts, weakParent),
      (e: unknown) => e instanceof CapabilityIssuanceError && /exceeds issuer authority/.test(e.message),
    );
  });
});

describe('M11: policy cross-validation', () => {
  const base = (over: Partial<PolicyRule>): PolicyRule => ({
    id: 'r',
    effect: 'allow',
    principals: { roles: ['worker'] },
    actions: ['read'],
    resources: {},
    ...over,
  });

  test('an allow rule granting an action outside the role is rejected at construction', () => {
    assert.throws(
      () => createPolicyEngine([base({ id: 'r-widen-action', actions: ['export'] })]),
      (e: unknown) =>
        e instanceof PolicyCompilationError &&
        e.pattern === 'worker' &&
        /r-widen-action/.test(e.message) &&
        /worker/.test(e.message),
    );
  });

  test('an allow rule granting classification above the role ceiling is rejected', () => {
    assert.throws(
      () => createPolicyEngine([base({ id: 'r-widen-class', maxClassification: 'phi' })]),
      (e: unknown) => e instanceof PolicyCompilationError && /r-widen-class/.test(e.message),
    );
  });

  test('a wildcard allow rule for a role is rejected', () => {
    assert.throws(
      () => createPolicyEngine([base({ id: 'r-wildcard', actions: ['*'] })]),
      (e: unknown) => e instanceof PolicyCompilationError && /r-wildcard/.test(e.message),
    );
  });

  test('deny rules and roles not in the table are not validated', () => {
    assert.doesNotThrow(() =>
      createPolicyEngine([
        base({ id: 'r-deny-beyond', effect: 'deny', actions: ['export', 'secret.use'], maxClassification: 'phi' }),
        base({ id: 'r-org-role', principals: { roles: ['org-defined-elsewhere'] }, actions: ['secret.use'] }),
      ]),
    );
  });
});

describe('M11: no bypass of capability verification', () => {
  test('tampering a role-minted capability fails the signature check', () => {
    const world = testWorld();
    const at = world.clock.now();
    const cap = world.authorization.issueForRole(
      world.root, 'worker', world.agent.id, [world.resources.phi!], {
      actions: ['read'],
      expiresAt: at + 60_000,
      provenance: { source: 'policy-grant' },
    });
    assert.equal(cap.maxClassification, 'internal');

    const tampered = { ...cap, maxClassification: 'phi' as const };
    const r = verifyCapability(tampered, {
      subject: world.agent.id,
      tenantId: 'acme',
      action: 'read',
      resourceId: world.resources.phi!,
      classification: 'phi',
      now: at,
    });
    assert.equal(r.ok, false);
    if (!r.ok) assert.equal(r.reason, 'capability-signature-invalid');
  });

  test('a role-minted capability used above its ceiling denies with classification-ceiling', () => {
    const world = testWorld();
    const at = world.clock.now();
    world.authorization.issueForRole(
      world.root, 'worker', world.agent.id, [world.resources.phi!], {
      actions: ['read'],
      expiresAt: at + 60_000,
      provenance: { source: 'policy-grant' },
    });
    const decision = world.authorization.authorize({
      principal: world.agent,
      action: 'read',
      resourceId: world.resources.phi!,
    });
    assert.equal(decision.decision, 'deny');
    assert.equal(decision.denyReason, 'classification-ceiling');
  });
});

describe('M11: structural invariant — capabilities never exceed the role', () => {
  test('every baseline role mints only its own actions at or below its own ceiling', () => {
    const world = testWorld();
    const at = world.clock.now();
    for (const role of BASELINE_ROLES) {
      const cap = world.authorization.issueForRole(world.root, role.id, 'agent:x', ['res:x'], {
        actions: [...role.actions],
        expiresAt: at + 60_000,
        provenance: { source: 'policy-grant' },
      });
      for (const a of cap.actions) {
        assert.ok(role.actions.includes(a), `capability action ${a} is outside role ${role.id}`);
      }
      assert.ok(
        classificationRank(cap.maxClassification) <= classificationRank(role.maxClassification),
        `capability ceiling ${cap.maxClassification} exceeds role ${role.id} ceiling ${role.maxClassification}`,
      );
    }
  });
});
