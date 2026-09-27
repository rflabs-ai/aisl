/**
 * H1 — signed delegation (ADR-023).
 *
 * The declared `issuerAuthority` seam is gone: a non-root issuer attenuates
 * against its own SIGNED capability, presented as the parent. Every bypass
 * the old seam allowed is refused here, and the chain link is recorded in the
 * child's provenance under the child's own signature.
 */
import { describe, test } from 'node:test';
import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import { fileURLToPath } from 'node:url';
import {
  CapabilityIssuanceError,
  issueCapability,
  markUsed,
  verifyCapability,
  type Capability,
  type IssueRequest,
} from '../src/capability.ts';
import type { Principal } from '../src/domain.ts';
import { testWorld } from '../src/testing.ts';

const svcPrincipal = (id = 'svc:orchestrator'): Principal => ({
  id,
  kind: 'service',
  tenantId: 'acme',
  roles: [],
  attributes: {},
});

const globexRoot: Principal = {
  id: 'authz-root:globex',
  kind: 'authorization',
  tenantId: 'globex',
  roles: [],
  attributes: {},
};

function parentFor(
  world: ReturnType<typeof testWorld>,
  subject = 'svc:orchestrator',
): Capability {
  return world.authorization.issue(world.root, {
    subject,
    tenantId: 'acme',
    resourceIds: [world.resources.repoA!],
    actions: ['read'],
    maxClassification: 'internal',
    expiresAt: world.clock.now() + 60_000,
    provenance: { source: 'policy-grant' },
  });
}

function childRequest(
  world: ReturnType<typeof testWorld>,
  over: Partial<IssueRequest> = {},
): IssueRequest {
  return {
    subject: world.agent.id,
    tenantId: 'acme',
    resourceIds: [world.resources.repoA!],
    actions: ['read'],
    maxClassification: 'public',
    expiresAt: world.clock.now() + 60_000,
    provenance: { source: 'delegation' },
    ...over,
  };
}

describe('H1: delegation requires the issuer own signed capability', () => {
  test('delegation without a parent is refused', () => {
    const world = testWorld();
    assert.throws(
      () => issueCapability(svcPrincipal(), childRequest(world), world.clock.now()),
      /must present its own authority/,
    );
  });

  test('a tampered parent is refused even though its fields would allow the child', () => {
    const world = testWorld();
    const parent = parentFor(world);
    const widened: Capability = {
      ...parent,
      resourceIds: [world.resources.repoA!, world.resources.customerB!],
      maxClassification: 'confidential',
    };
    assert.throws(
      () => issueCapability(svcPrincipal(), childRequest(world, {
        resourceIds: [world.resources.repoA!, world.resources.customerB!],
        maxClassification: 'confidential',
      }), world.clock.now(), widened),
      /parent capability signature/,
    );
  });

  test('a forged parent signature is refused', () => {
    const world = testWorld();
    const parent = parentFor(world);
    const last = parent.signature.slice(-1);
    const forged: Capability = {
      ...parent,
      signature: parent.signature.slice(0, -1) + (last === 'a' ? 'b' : 'a'),
    };
    assert.throws(
      () => issueCapability(svcPrincipal(), childRequest(world), world.clock.now(), forged),
      /parent capability signature/,
    );
  });

  test('a parent held by ANOTHER subject is refused (the declared-object bypass)', () => {
    const world = testWorld();
    const strongParent = parentFor(world, 'svc:other');
    assert.throws(
      () =>
        issueCapability(svcPrincipal('svc:weak'), childRequest(world), world.clock.now(), strongParent),
      /held by/,
    );
  });

  test('a cross-tenant parent is refused', () => {
    const world = testWorld();
    const foreignParent = issueCapability(
      globexRoot,
      {
        // Same subject as the issuing principal — so the TENANT check is what fires.
        subject: 'svc:orchestrator',
        tenantId: 'globex',
        resourceIds: ['r:globex'],
        actions: ['read'],
        maxClassification: 'internal',
        expiresAt: world.clock.now() + 60_000,
        provenance: { source: 'policy-grant' },
      },
      world.clock.now(),
    );
    assert.throws(
      () => issueCapability(svcPrincipal(), childRequest(world), world.clock.now(), foreignParent),
      /parent capability is bound to another tenant/,
    );
  });

  test('an expired parent is refused', () => {
    const world = testWorld();
    const parent = parentFor(world);
    const later = world.clock.now() + 120_000;
    assert.throws(
      () =>
        issueCapability(svcPrincipal(), childRequest(world, { expiresAt: later + 60_000 }), later, parent),
      /parent capability .+ is expired/,
    );
  });

  test('a consumed single-use parent is refused', () => {
    const world = testWorld();
    const parent = world.authorization.issue(world.root, {
      subject: 'svc:orchestrator',
      tenantId: 'acme',
      resourceIds: [world.resources.repoA!],
      actions: ['read'],
      maxClassification: 'internal',
      expiresAt: world.clock.now() + 60_000,
      singleUse: true,
      provenance: { source: 'policy-grant' },
    });
    const spent = markUsed(parent, world.clock.now());
    assert.throws(
      () => issueCapability(svcPrincipal(), childRequest(world), world.clock.now(), spent),
      /consumed/,
    );
  });
});

describe('H1: service-level custody of the parent', () => {
  test('a revoked parent is refused', () => {
    const world = testWorld();
    const parent = parentFor(world);
    world.authorization.revoke(parent.id, 'test-revocation');
    assert.throws(
      () => world.authorization.issue(svcPrincipal(), childRequest(world), parent),
      /revoked/,
    );
  });

  test('an unregistered parent is refused even with a valid signature', () => {
    const world = testWorld();
    const ghost = issueCapability(world.root, {
      subject: 'svc:orchestrator',
      tenantId: 'acme',
      resourceIds: [world.resources.repoA!],
      actions: ['read'],
      maxClassification: 'internal',
      expiresAt: world.clock.now() + 60_000,
      provenance: { source: 'policy-grant' },
    }, world.clock.now());
    assert.throws(
      () => world.authorization.issue(svcPrincipal(), childRequest(world), ghost),
      /not registered/,
    );
  });
});

describe('H1: the chain is recorded and traceable', () => {
  test('attenuated delegation succeeds and the child carries the parent signature', () => {
    const world = testWorld();
    const parent = parentFor(world);
    const child = world.authorization.issue(
      svcPrincipal(),
      childRequest(world, { provenance: { source: 'delegation' } }),
      parent,
    );
    assert.equal(child.maxClassification, 'public');
    assert.equal(child.provenance.delegatedFrom?.id, parent.id);
    assert.equal(child.provenance.delegatedFrom?.signature, parent.signature);
  });

  test('a caller-supplied delegatedFrom is overridden, never trusted', () => {
    const world = testWorld();
    const parent = parentFor(world);
    const child = world.authorization.issue(
      svcPrincipal(),
      childRequest(world, {
        provenance: { source: 'delegation', delegatedFrom: { id: 'cap:fake', signature: 'fake' } },
      }),
      parent,
    );
    assert.equal(child.provenance.delegatedFrom?.id, parent.id);
    assert.equal(child.provenance.delegatedFrom?.signature, parent.signature);
  });

  test('a two-hop chain stays attenuated and every hop is traceable', () => {
    const world = testWorld();
    const p1 = parentFor(world, 'svc:orchestrator');
    const c1 = world.authorization.issue(
      svcPrincipal(),
      childRequest(world, { subject: 'svc:sub', maxClassification: 'internal', provenance: { source: 'delegation' } }),
      p1,
    );
    const c2 = world.authorization.issue(
      svcPrincipal('svc:sub'),
      childRequest(world, { provenance: { source: 'delegation' } }),
      c1,
    );
    assert.equal(c2.provenance.delegatedFrom?.id, c1.id);
    assert.equal(c2.provenance.delegatedFrom?.signature, c1.signature);
    const verdict = verifyCapability(c2, {
      subject: world.agent.id,
      tenantId: 'acme',
      action: 'read',
      resourceId: world.resources.repoA!,
      classification: 'public',
      now: world.clock.now(),
    });
    assert.equal(verdict.ok, true);
  });
});

describe('H1: issuance fuzzing — every field extreme refuses', () => {
  const world = testWorld();
  const parent = parentFor(world);
  const now = world.clock.now();

  const extremes: readonly [string, Partial<IssueRequest>][] = [
    ['wildcard resources', { resourceIds: ['*'] }],
    ['unknown resource', { resourceIds: ['repo:does-not-exist'] }],
    ['wildcard actions', { actions: ['*'] as IssueRequest['actions'] }],
    ['escalated action', { actions: ['delete'] }],
    ['classification above ceiling', { maxClassification: 'restricted' }],
    ['unknown classification', { maxClassification: 'top-secret' as IssueRequest['maxClassification'] }],
    ['expiry beyond the parent', { expiresAt: now + 120_000 }],
    ['expiry in the past', { expiresAt: now - 1 }],
    ['empty resources', { resourceIds: [] }],
    ['empty actions', { actions: [] as IssueRequest['actions'] }],
    ['cross-tenant child', { tenantId: 'globex' }],
  ];

  for (const [name, over] of extremes) {
    test(`extreme: ${name} refuses`, () => {
      assert.throws(
        () => issueCapability(svcPrincipal(), childRequest(world, over), now, parent),
        CapabilityIssuanceError,
      );
    });
  }
});

describe('H1: structural invariant — no declared-authority seam remains', () => {
  test('src/capability.ts and src/pdp.ts carry no issuerAuthority/IsherAuthority symbol', async () => {
    const here = fileURLToPath(new URL('.', import.meta.url));
    const capabilitySrc = await readFile(`${here}../src/capability.ts`, 'utf8');
    const pdpSrc = await readFile(`${here}../src/pdp.ts`, 'utf8');
    assert.equal(/issuerAuthority|IssuerAuthority/.test(capabilitySrc), false);
    assert.equal(/issuerAuthority|IssuerAuthority/.test(pdpSrc), false);
  });
});
