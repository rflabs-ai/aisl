/** Capability model: signatures, scope, expiry, single use, constraints. */

import { test, describe } from 'node:test';
import assert from 'node:assert/strict';
import { issueCapability, markUsed, verifyCapability } from '../src/capability.ts';
import { type Principal } from '../src/domain.ts';
import { testWorld } from '../src/testing.ts';

const root: Principal = { id: 'authz-root:acme', kind: 'authorization', tenantId: 'acme', roles: [], attributes: {} };

describe('capability integrity', () => {
  test('a tampered capability fails signature verification', () => {
    const world = testWorld();
    const cap = world.authorization.issue(world.root, {
      subject: world.agent.id,
      tenantId: 'acme',
      resourceIds: [world.resources.repoA!],
      actions: ['read'],
      maxClassification: 'internal',
      expiresAt: world.clock.now() + 60_000,
      provenance: { source: 'policy-grant' },
    });

    const escalated = { ...cap, maxClassification: 'restricted' as const };
    assert.equal(verifyCapability(escalated, base(world)).ok, false);

    const widened = { ...cap, resourceIds: [world.resources.phi!] };
    const r = verifyCapability(widened, { ...base(world), resourceId: world.resources.phi!, classification: 'phi' });
    assert.equal(r.ok, false);
    if (!r.ok) assert.equal(r.reason, 'capability-signature-invalid');
  });

  test('a capability is bound to its subject', () => {
    const world = testWorld();
    const cap = world.authorization.issue(world.root, {
      subject: world.agent.id,
      tenantId: 'acme',
      resourceIds: [world.resources.repoA!],
      actions: ['read'],
      maxClassification: 'internal',
      expiresAt: world.clock.now() + 60_000,
      provenance: { source: 'policy-grant' },
    });
    const r = verifyCapability(cap, { ...base(world), subject: 'agent:someone-else' });
    assert.equal(r.ok, false);
    if (!r.ok) assert.equal(r.reason, 'capability-scope');
  });

  test('single-use capabilities are consumed exactly once', () => {
    const world = testWorld();
    const cap = world.authorization.issue(world.root, {
      subject: world.agent.id,
      tenantId: 'acme',
      resourceIds: [world.resources.repoA!],
      actions: ['read'],
      maxClassification: 'internal',
      expiresAt: world.clock.now() + 60_000,
      singleUse: true,
      provenance: { source: 'human-approval', approvedBy: world.user.id },
    });
    assert.equal(verifyCapability(cap, base(world)).ok, true);
    const used = markUsed(cap, world.clock.now());
    assert.equal(verifyCapability(used, base(world)).ok, false);
  });

  test('network constraints bind a capability to specific hosts', () => {
    const world = testWorld();
    const cap = issueCapability(
      root,
      {
        subject: 'agent:x',
        tenantId: 'acme',
        resourceIds: ['net:a.example.com'],
        actions: ['network.egress'],
        maxClassification: 'restricted',
        expiresAt: Date.now() + 60_000,
        constraints: [{ kind: 'network-host', hosts: ['a.example.com'] }],
        provenance: { source: 'policy-grant' },
      },
      Date.now(),
    );
    const ctx = {
      subject: 'agent:x',
      tenantId: 'acme',
      action: 'network.egress' as const,
      resourceId: 'net:a.example.com',
      classification: 'restricted' as const,
      now: Date.now(),
    };
    assert.equal(verifyCapability(cap, { ...ctx, networkHost: 'a.example.com' }).ok, true);
    assert.equal(verifyCapability(cap, { ...ctx, networkHost: 'b.example.com' }).ok, false);
    assert.equal(verifyCapability(cap, ctx).ok, false);
  });

  test('classification ceiling is enforced at the capability layer', () => {
    const world = testWorld();
    const cap = world.authorization.issue(world.root, {
      subject: world.agent.id,
      tenantId: 'acme',
      resourceIds: [world.resources.phi!],
      actions: ['read'],
      maxClassification: 'internal',
      expiresAt: world.clock.now() + 60_000,
      provenance: { source: 'policy-grant' },
    });
    const r = verifyCapability(cap, { ...base(world), resourceId: world.resources.phi!, classification: 'phi' });
    assert.equal(r.ok, false);
    if (!r.ok) assert.equal(r.reason, 'classification-ceiling');
  });
});

function base(world: ReturnType<typeof testWorld>) {
  return {
    subject: world.agent.id,
    tenantId: 'acme',
    action: 'read' as const,
    resourceId: world.resources.repoA!,
    classification: 'internal' as const,
    now: world.clock.now(),
  };
}
