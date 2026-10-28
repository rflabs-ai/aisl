/**
 * Machine-checked PDP invariants (ADR-042).
 *
 * The hand-written suites assert one example per invariant. This runs the real
 * authorization service over an enumerated state space — principals x resources
 * x actions x capability sets — and asserts that no reachable state violates any
 * property. Bounded model checking, not a proof: exhaustive over what it
 * enumerates, blind to what it does not.
 */

import { test, describe } from 'node:test';
import assert from 'node:assert/strict';
import { testWorld } from '../src/testing.ts';
import { checkAll, checkState, INVARIANTS, type InvariantState } from '../src/invariants.ts';
import type { Action, Principal } from '../src/domain.ts';

interface CapSpec {
  readonly id: string;
  readonly caps: readonly {
    readonly actions: readonly Action[];
    readonly maxClassification: 'public' | 'internal' | 'confidential' | 'restricted';
    readonly expired?: boolean;
  }[];
}

const CAP_SPECS: readonly CapSpec[] = [
  { id: 'none', caps: [] },
  { id: 'read-internal', caps: [{ actions: ['read'], maxClassification: 'internal' }] },
  { id: 'read-confidential', caps: [{ actions: ['read'], maxClassification: 'confidential' }] },
  { id: 'write-internal', caps: [{ actions: ['write'], maxClassification: 'internal' }] },
  {
    id: 'read+write',
    caps: [
      { actions: ['read'], maxClassification: 'internal' },
      { actions: ['write'], maxClassification: 'internal' },
    ],
  },
];

const ACTIONS: readonly Action[] = ['read', 'write', 'delete', 'export', 'network.egress'];

function enumerate(): readonly InvariantState[] {
  const states: InvariantState[] = [];

  for (const spec of CAP_SPECS) {
    const world = testWorld();
    const now = world.clock.now();
    const resources = [
      world.resources.repoA!,
      world.resources.internalDoc!,
      world.resources.confidentialDoc!,
      world.resources.phi!,
      world.resources.foreignDoc!,
    ];
    const principals: readonly Principal[] = [world.agent, world.user, world.foreignAgent];

    for (const principal of principals) {
      if (principal.tenantId !== 'acme') continue; // issuing across tenants is refused
      for (const cap of spec.caps) {
        world.authorization.issue(world.root, {
          subject: principal.id,
          tenantId: 'acme',
          resourceIds: [...resources],
          actions: [...cap.actions],
          maxClassification: cap.maxClassification,
          expiresAt: now + 600_000,
          provenance: { source: 'policy-grant' },
        });
      }
    }

    for (const principal of principals) {
      const held = world.authorization.capabilitiesFor(principal.id);
      for (const resourceId of resources) {
        const resource = world.registry.require(resourceId);
        for (const action of ACTIONS) {
          const decision = world.authorization.authorize({ principal, action, resourceId });
          states.push({
            label: `${spec.id}|${principal.id}|${action}|${resourceId}`,
            principal,
            resource,
            action,
            held,
            now,
            decision,
          });
        }
      }
    }
  }
  return states;
}

describe('stage 3: machine-checked invariants', () => {
  const states = enumerate();

  test('the enumeration is non-trivial', () => {
    assert.ok(states.length >= 350, `only ${states.length} states`);
    assert.ok(states.some((s) => s.decision.decision === 'allow'), 'no allow states — the model proves nothing');
    assert.ok(states.some((s) => s.decision.decision === 'deny'), 'no deny states');
  });

  test('no reachable state violates any invariant', () => {
    const violations = checkAll(states);
    assert.equal(
      violations.length,
      0,
      `${violations.length} violation(s): ${JSON.stringify(violations.slice(0, 5), null, 2)}`,
    );
  });

  test('a forged allow is caught — the model has teeth', () => {
    const forged: InvariantState = {
      ...states[0]!,
      held: [],
      decision: { ...states[0]!.decision, decision: 'allow', capabilityId: undefined },
    };
    const violations = checkState(forged);
    const fired = new Set(violations.map((v) => v.invariant));
    assert.ok(fired.has('no-authority-without-capability'), JSON.stringify(violations));
    assert.ok(fired.has('empty-capability-set-denies'));
  });

  test('the invariant set is the seven documented properties', () => {
    assert.deepEqual(INVARIANTS.map((i) => i.id).sort(), [
      'classification-ceiling-respected',
      'cross-tenant-never-allowed',
      'deny-carries-no-authority',
      'empty-capability-set-denies',
      'expired-capability-never-authorizes',
      'foreign-capability-never-authorizes',
      'no-authority-without-capability',
    ]);
  });

  test('decisions are deterministic across repeated evaluation', () => {
    const world = testWorld();
    const resourceId = world.resources.internalDoc!;
    const a = world.authorization.authorize({ principal: world.agent, action: 'read', resourceId });
    const b = world.authorization.authorize({ principal: world.agent, action: 'read', resourceId });
    assert.deepEqual(a, b);
  });
});
