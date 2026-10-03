/**
 * Evidence confidentiality: content is sealed before it reaches the store, and
 * reading it back requires `evidence.decrypt` authority for that classification.
 *
 * Property under test: someone holding the evidence file learns nothing; a
 * reviewer cleared for that level learns everything; both facts are audited.
 */

import { test, describe } from 'node:test';
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { type Principal } from '../src/domain.ts';
import { type PolicyRule } from '../src/policy.ts';
import { keyIdFor, keyIdForTenant, open, sealFor, type Sealed } from '../src/seal.ts';
import { TENANT_A, TENANT_B } from '../src/scenario.ts';
import { testWorld, mockAuth } from '../src/testing.ts';

const auditorAuth = mockAuth({ subject: 'user:auditor', amr: ['pwd', 'mfa'] });
const AUDITOR: Principal = {
  id: 'user:auditor',
  kind: 'user',
  tenantId: TENANT_A,
  roles: ['auditor'],
  attributes: {},
  auth: auditorAuth,
};

const EVIDENCE_RULE: PolicyRule = {
  id: 'allow-auditor-evidence-decrypt',
  effect: 'allow',
  principals: { roles: ['auditor'] },
  actions: ['evidence.decrypt'],
  resources: { types: ['system'] },
};

function lastExecution(w: ReturnType<typeof testWorld>) {
  const event = [...w.eventLog.all()]
    .reverse()
    .find((e) => (e.metadata as { phase?: string } | undefined)?.phase === 'execution');
  assert.ok(event, 'expected an execution event');
  return event!;
}

function readInternalDoc(w: ReturnType<typeof testWorld>): string {
  const step = w
    .session({ id: 'm', complete: () => ({ text: '', requests: [] }) })
    .attempt({ action: 'read', resourceId: w.resources.repoA! });
  assert.equal(step.executed, true);
  return String(step.output);
}

describe('evidence sealing', () => {
  test('content is sealed: plaintext never reaches the store', () => {
    const w = testWorld();
    const secret = w.secretValues[0]!;
    w.content.set(w.resources.internalDoc!, `harmless note: ${secret}`);

    const step = w
      .session({ id: 'm', complete: () => ({ text: '', requests: [] }) })
      .attempt({ action: 'read', resourceId: w.resources.internalDoc! });
    assert.equal(step.executed, true);

    const event = lastExecution(w);
    const meta = event.metadata as { outputDigest: string | null; sealed: Sealed | null };
    assert.equal(meta.outputDigest, createHash('sha256').update(String(step.output)).digest('hex'));
    assert.ok(meta.sealed, 'content must be sealed, not dropped');

    const everything = w.eventLog.bundle();
    assert.equal(everything.includes(secret), false, 'secret must not appear in the store');
    assert.equal(everything.includes(String(step.output)), false, 'plaintext output must not appear');
  });

  test('the digest is verifiable without any clearance', () => {
    const w = testWorld();
    const content = readInternalDoc(w);
    const meta = lastExecution(w).metadata as { outputDigest: string };
    assert.equal(meta.outputDigest, createHash('sha256').update(content).digest('hex'));
  });

  test('an unauthorized principal gets nothing, and the attempt is audited', () => {
    const w = testWorld({ policies: [EVIDENCE_RULE] });
    readInternalDoc(w);
    const event = lastExecution(w);

    assert.equal(w.authorization.revealEvidence(w.agent, event), undefined);

    const denial = w.eventLog.all().at(-1)!;
    assert.equal(denial.action, 'evidence.decrypt');
    assert.equal(denial.decision, 'deny');
    assert.equal(denial.denyReason, 'no-capability');
  });

  test('a reviewer cleared for the level decrypts the exact content', () => {
    const w = testWorld({ policies: [EVIDENCE_RULE] });
    const content = readInternalDoc(w);
    const event = lastExecution(w);

    w.authorization.issue(w.root, {
      subject: AUDITOR.id,
      tenantId: TENANT_A,
      resourceIds: [keyIdForTenant(TENANT_A, 'internal')],
      actions: ['evidence.decrypt'],
      maxClassification: 'internal',
      expiresAt: w.clock.now() + 600_000,
      provenance: { source: 'policy-grant', note: 'audit review' },
    });

    assert.equal(w.authorization.revealEvidence(AUDITOR, event), content);
    assert.equal(w.eventLog.all().at(-1)!.decision, 'allow');
  });

  test('clearance for one level does not open another', () => {
    const w = testWorld({ policies: [EVIDENCE_RULE] });
    readInternalDoc(w);
    const event = lastExecution(w);

    w.authorization.issue(w.root, {
      subject: AUDITOR.id,
      tenantId: TENANT_A,
      resourceIds: [keyIdForTenant(TENANT_A, 'confidential')],
      actions: ['evidence.decrypt'],
      maxClassification: 'confidential',
      expiresAt: w.clock.now() + 600_000,
      provenance: { source: 'policy-grant' },
    });

    assert.equal(w.authorization.revealEvidence(AUDITOR, event), undefined);
  });

  test('clearance minted for another tenant\'s v2 key does not decrypt ours', () => {
    const w = testWorld({ policies: [EVIDENCE_RULE] });
    readInternalDoc(w);
    const event = lastExecution(w);

    w.authorization.issue(w.root, {
      subject: AUDITOR.id,
      tenantId: TENANT_A,
      resourceIds: [keyIdForTenant('other-tenant', 'internal')],
      actions: ['evidence.decrypt'],
      maxClassification: 'internal',
      expiresAt: w.clock.now() + 600_000,
      provenance: { source: 'policy-grant' },
    });

    // The capability names another tenant's key id; it never matches the
    // seal's key resource, so the reveal is denied (no-capability). The
    // event-level key/tenant binding is covered by the H8 case below.
    assert.equal(w.authorization.revealEvidence(AUDITOR, event), undefined);
  });

  test("a clearance for the sealed key's tenant cannot decrypt another tenant's event (H8/ADR-030)", () => {
    const w = testWorld({ policies: [EVIDENCE_RULE] });
    const foreignKeyId = keyIdForTenant(TENANT_B, 'internal');
    const sealed = sealFor(TENANT_B, 'globex-only-content', 'internal');
    const event = w.eventLog.append({
      tenantId: TENANT_B,
      principal: 'agent:globex',
      actor: 'agent:globex',
      actorKind: 'agent',
      action: 'write',
      resourceId: 'doc:globex-strategy',
      result: 'success',
      metadata: { sealed },
    });

    // Tenant A holds a capability naming tenant B's key id — resource ids are
    // opaque strings, so the mint is legal. The key binding must refuse before
    // any registry registration or authorization.
    w.authorization.issue(w.root, {
      subject: AUDITOR.id,
      tenantId: TENANT_A,
      resourceIds: [foreignKeyId],
      actions: ['evidence.decrypt'],
      maxClassification: 'internal',
      expiresAt: w.clock.now() + 600_000,
      provenance: { source: 'policy-grant' },
    });

    assert.equal(w.authorization.revealEvidence(AUDITOR, event), undefined);
    assert.notEqual(w.registry.get(foreignKeyId)?.tenantId, TENANT_A, 'the foreign key must not bind to the caller tenant');

    const denial = w.eventLog.all().at(-1)!;
    assert.equal(denial.action, 'evidence.decrypt');
    assert.equal(denial.decision, 'deny');
    assert.equal(denial.denyReason, 'tenant-mismatch');
    assert.equal(denial.tenantId, TENANT_A);
    assert.equal(
      JSON.stringify(denial).includes(foreignKeyId),
      false,
      'the refusal must not copy the foreign key id into acme evidence',
    );
  });

  test('tampered ciphertext yields nothing', () => {
    const sealed: Sealed = {
      keyId: keyIdFor('internal'),
      iv: Buffer.alloc(12, 1).toString('base64'),
      tag: Buffer.alloc(16, 2).toString('base64'),
      ciphertext: Buffer.from('tampered').toString('base64'),
    };
    assert.equal(open(sealed), undefined);
  });
});
