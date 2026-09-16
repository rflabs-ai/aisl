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
import { keyIdFor, open, type Sealed } from '../src/seal.ts';
import { TENANT_A } from '../src/scenario.ts';
import { testWorld } from '../src/testing.ts';

const AUDITOR: Principal = {
  id: 'user:auditor',
  kind: 'user',
  tenantId: TENANT_A,
  roles: ['auditor'],
  attributes: {},
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
      resourceIds: [keyIdFor('internal')],
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
      resourceIds: [keyIdFor('confidential')],
      actions: ['evidence.decrypt'],
      maxClassification: 'confidential',
      expiresAt: w.clock.now() + 600_000,
      provenance: { source: 'policy-grant' },
    });

    assert.equal(w.authorization.revealEvidence(AUDITOR, event), undefined);
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
