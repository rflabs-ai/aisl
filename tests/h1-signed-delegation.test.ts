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
import { readFile, readdir } from 'node:fs/promises';
import { join } from 'node:path';
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
  test('a revoked parent is refused AND the refusal is audited', () => {
    const world = testWorld();
    const parent = parentFor(world);
    world.authorization.revoke(parent.id, 'test-revocation');
    const before = world.eventLog.all().length;
    assert.throws(
      () => world.authorization.issue(svcPrincipal(), childRequest(world), parent),
      /revoked/,
    );
    const refusal = world.eventLog
      .all()
      .slice(before)
      .find((e) => e.action === 'capability.issue' && e.decision === 'deny');
    assert.ok(refusal, 'a delegation attempt from a revoked parent must be audited');
    assert.equal(refusal.result, 'denied');
    assert.equal(refusal.capabilityId, parent.id);
  });

  test('an unregistered parent is refused even with a valid signature AND the refusal is audited', () => {
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
    const before = world.eventLog.all().length;
    assert.throws(
      () => world.authorization.issue(svcPrincipal(), childRequest(world), ghost),
      /not registered/,
    );
    const refusal = world.eventLog
      .all()
      .slice(before)
      .find((e) => e.action === 'capability.issue' && e.decision === 'deny');
    assert.ok(refusal, 'a delegation attempt from an unregistered parent must be audited');
    assert.equal(refusal.result, 'denied');
    assert.equal(refusal.capabilityId, ghost.id);
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

describe('H1: the constraint and single-use dimensions attenuate too (audit 01)', () => {
  const world = testWorld();
  const at = world.clock.now();

  const constrainedParent = world.authorization.issue(world.root, {
    subject: 'svc:orchestrator',
    tenantId: 'acme',
    resourceIds: [world.resources.repoA!],
    actions: ['read'],
    maxClassification: 'internal',
    expiresAt: at + 60_000,
    constraints: [
      { kind: 'network-host', hosts: ['a.example.com', 'b.example.com'] },
      { kind: 'param-equals', key: 'env', value: 'prod' },
    ],
    provenance: { source: 'policy-grant' },
  });

  const singleUseParent = world.authorization.issue(world.root, {
    subject: 'svc:orchestrator',
    tenantId: 'acme',
    resourceIds: [world.resources.repoA!],
    actions: ['read'],
    maxClassification: 'internal',
    expiresAt: at + 60_000,
    singleUse: true,
    provenance: { source: 'policy-grant' },
  });

  test('a child that DROPS the network constraint refuses', () => {
    assert.throws(
      () => issueCapability(svcPrincipal(), childRequest(world, { expiresAt: at + 60_000 }), at, constrainedParent),
      /network constraint not held by issuer/,
    );
  });

  test('a child that keeps the param but drops the network constraint refuses', () => {
    assert.throws(
      () =>
        issueCapability(
          svcPrincipal(),
          childRequest(world, {
            expiresAt: at + 60_000,
            constraints: [{ kind: 'param-equals', key: 'env', value: 'prod' }],
          }),
          at,
          constrainedParent,
        ),
      /network constraint not held by issuer/,
    );
  });

  test('a child that keeps the network constraint but drops the param refuses', () => {
    assert.throws(
      () =>
        issueCapability(
          svcPrincipal(),
          childRequest(world, {
            expiresAt: at + 60_000,
            constraints: [{ kind: 'network-host', hosts: ['a.example.com'] }],
          }),
          at,
          constrainedParent,
        ),
      /constraint env not held by issuer/,
    );
  });

  test('a child carrying every parent constraint succeeds', () => {
    const child = issueCapability(
      svcPrincipal(),
      childRequest(world, {
        expiresAt: at + 60_000,
        constraints: [
          { kind: 'network-host', hosts: ['a.example.com', 'b.example.com'] },
          { kind: 'param-equals', key: 'env', value: 'prod' },
        ],
      }),
      at,
      constrainedParent,
    );
    assert.equal(child.constraints.length, 2);
  });

  test('a child that NARROWS the hosts stays legitimate (no false denial)', () => {
    const child = issueCapability(
      svcPrincipal(),
      childRequest(world, {
        expiresAt: at + 60_000,
        constraints: [
          { kind: 'network-host', hosts: ['a.example.com'] },
          { kind: 'param-equals', key: 'env', value: 'prod' },
        ],
      }),
      at,
      constrainedParent,
    );
    const nh = child.constraints[0];
    assert.ok(nh !== undefined && nh.kind === 'network-host');
    assert.deepEqual([...nh.hosts], ['a.example.com']);
  });

  test('a single-use parent cannot delegate at all', () => {
    assert.throws(
      () => issueCapability(svcPrincipal(), childRequest(world, { expiresAt: at + 60_000 }), at, singleUseParent),
      /single-use capability cannot delegate/,
    );
  });
});

describe('H1: root presents a parent too (audit 02)', () => {
  test('root refuses an invalid parent instead of recording a bogus chain link', () => {
    const world = testWorld();
    const parent = parentFor(world);
    const forged: Capability = {
      ...parent,
      signature: parent.signature.slice(0, -1) + (parent.signature.slice(-1) === 'a' ? 'b' : 'a'),
    };
    assert.throws(
      () => issueCapability(world.root, childRequest(world), world.clock.now(), forged),
      /parent capability signature/,
    );
  });

  test('root with a valid parent records a real chain link', () => {
    const world = testWorld();
    const selfParent = world.authorization.issue(world.root, {
      subject: world.root.id,
      tenantId: 'acme',
      resourceIds: [world.resources.repoA!],
      actions: ['read'],
      maxClassification: 'internal',
      expiresAt: world.clock.now() + 60_000,
      provenance: { source: 'policy-grant' },
    });
    const child = issueCapability(world.root, childRequest(world), world.clock.now(), selfParent);
    assert.equal(child.provenance.delegatedFrom?.id, selfParent.id);
    assert.equal(child.provenance.delegatedFrom?.signature, selfParent.signature);
  });
});

describe('H1: issuance fuzzing, every IssueRequest field has an extreme case', () => {
  const world = testWorld();
  const now = world.clock.now();
  const parent = parentFor(world);

  // The constraint extremes need a parent that HOLDS constraints, otherwise
  // there is nothing for a child to widen or drop.
  const constrainedParent = world.authorization.issue(world.root, {
    subject: 'svc:orchestrator',
    tenantId: 'acme',
    resourceIds: [world.resources.repoA!],
    actions: ['read'],
    maxClassification: 'internal',
    expiresAt: now + 60_000,
    constraints: [
      { kind: 'network-host', hosts: ['a.example.com'] },
      { kind: 'param-equals', key: 'env', value: 'prod' },
    ],
    provenance: { source: 'policy-grant' },
  });

  const singleUseParent = world.authorization.issue(world.root, {
    subject: 'svc:orchestrator',
    tenantId: 'acme',
    resourceIds: [world.resources.repoA!],
    actions: ['read'],
    maxClassification: 'internal',
    expiresAt: now + 60_000,
    singleUse: true,
    provenance: { source: 'policy-grant' },
  });

  interface Extreme {
    /** Compile-time guard that every entry names a real IssueRequest key. */
    readonly field: keyof IssueRequest;
    readonly name: string;
    readonly over: Partial<IssueRequest>;
    /** Parent to present; defaults to the unconstrained one. */
    readonly parent?: Capability;
  }

  const extremes: readonly Extreme[] = [
    { field: 'subject', name: 'empty subject', over: { subject: '' } },
    { field: 'tenantId', name: 'cross-tenant child', over: { tenantId: 'globex' } },
    { field: 'resourceIds', name: 'wildcard resources', over: { resourceIds: ['*'] } },
    {
      field: 'resourceIds',
      name: 'unknown resource',
      over: { resourceIds: ['repo:does-not-exist'] },
    },
    { field: 'resourceIds', name: 'empty resources', over: { resourceIds: [] } },
    {
      field: 'actions',
      name: 'wildcard actions',
      over: { actions: ['*'] as IssueRequest['actions'] },
    },
    { field: 'actions', name: 'escalated action', over: { actions: ['delete'] } },
    {
      field: 'actions',
      name: 'empty actions',
      over: { actions: [] as IssueRequest['actions'] },
    },
    {
      field: 'maxClassification',
      name: 'classification above ceiling',
      over: { maxClassification: 'restricted' },
    },
    {
      field: 'maxClassification',
      name: 'unknown classification',
      over: { maxClassification: 'top-secret' as IssueRequest['maxClassification'] },
    },
    {
      field: 'expiresAt',
      name: 'expiry beyond the parent',
      over: { expiresAt: now + 120_000 },
    },
    { field: 'expiresAt', name: 'expiry in the past', over: { expiresAt: now - 1 } },
    {
      field: 'singleUse',
      name: 'non-boolean singleUse',
      over: { singleUse: 'yes' as unknown as boolean },
    },
    {
      field: 'singleUse',
      name: 'child flips a single-use parent to non-single-use',
      over: { singleUse: false },
      parent: singleUseParent,
    },
    {
      field: 'constraints',
      name: 'unknown constraint kind',
      over: {
        constraints: [{ kind: 'file-path', pattern: '**' }] as unknown as IssueRequest['constraints'],
      },
    },
    {
      field: 'constraints',
      name: 'child widens the parent network hosts',
      over: { constraints: [{ kind: 'network-host', hosts: ['a.example.com', 'evil.example.com'] }] },
      parent: constrainedParent,
    },
    {
      field: 'constraints',
      name: 'empty constraint list',
      over: { constraints: [] },
      parent: constrainedParent,
    },
    {
      field: 'provenance',
      name: 'unknown provenance source',
      over: { provenance: { source: 'bogus' as IssueRequest['provenance']['source'] } },
    },
  ];

  for (const e of extremes) {
    test(`extreme: ${e.name} refuses`, () => {
      assert.throws(
        () => issueCapability(svcPrincipal(), childRequest(world, e.over), now, e.parent ?? parent),
        CapabilityIssuanceError,
      );
    });
  }

  test('structural: every IssueRequest key has a row in the extremes table', async () => {
    const source = await readFile(
      fileURLToPath(new URL('../src/capability.ts', import.meta.url)),
      'utf8',
    );
    // The interface is a flat list of `readonly name?: type` lines, so a
    // line-anchored scan is enough; the floor below catches a stale parse.
    const body = /export interface IssueRequest \{([\s\S]*?)\n\}/.exec(source)?.[1];
    assert.ok(body, 'IssueRequest interface not found in src/capability.ts');
    const keys = [...body.matchAll(/^\s*(?:readonly\s+)?([A-Za-z_$][\w$]*)\??:/gm)].map((m) => m[1]!);
    assert.ok(keys.length >= 9, `parsed only ${keys.length} IssueRequest keys; update the parser`);
    const covered = new Set<string>(extremes.map((e) => e.field));
    const missing = keys.filter((k) => !covered.has(k));
    assert.deepEqual(missing, [], `no extreme case for IssueRequest.${missing.join(', IssueRequest.')}`);
  });
});

describe('H1: structural invariant — no declared-authority seam remains', () => {
  test('no file under src/ carries the issuerAuthority/IssuerAuthority symbol', async () => {
    const srcDir = fileURLToPath(new URL('../src', import.meta.url));
    const files = (await readdir(srcDir)).filter((f) => f.endsWith('.ts'));
    assert.ok(files.length >= 30, `expected the real src tree, found ${files.length} .ts files`);
    for (const f of files) {
      const text = await readFile(join(srcDir, f), 'utf8');
      assert.equal(
        /issuerAuthority|IssuerAuthority/.test(text),
        false,
        `${f} reintroduces the declared-authority seam`,
      );
    }
  });
});
