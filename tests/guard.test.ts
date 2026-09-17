/**
 * Reliability layer tests: D2–D5, the ladder (repair/abstain/escalate), the
 * fail-closed path, and the R3 no-authority structural assertion.
 */

import { test, describe } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import {
  GroundedResponseGuard,
  runDetectors,
  runLadder,
  repairSpanStrip,
  assertGuardContextIsReadOnly,
  type GuardContext,
  type GuardedResponse,
  type StepRecord,
  type ClaimFlag,
  type ResponseGuard,
} from '../src/guard.ts';
import { type ActionRequest, type AuthorizationDecision } from '../src/domain.ts';

function allowDecision(action: string, resourceId: string): AuthorizationDecision {
  return {
    decision: 'allow',
    reason: 'test',
    policyId: 'test-policy',
    capabilityId: 'cap-test',
    principal: 'agent:test',
    action,
    resourceId,
    evaluatedAt: 0,
  };
}

function step(action: string, resourceId: string, executed: boolean, output?: unknown): StepRecord {
  return {
    request: { action, resourceId } as ActionRequest,
    decision: allowDecision(action, resourceId),
    executed,
    output,
  };
}

function ctx(overrides: Partial<GuardContext> = {}): GuardContext {
  const body = new Map<string, string>([['doc:acme-onboarding', 'Coffee machine is on floor 3.']]);
  return {
    sessionId: 'sess-test',
    modelText: '',
    context: body,
    steps: [],
    canaries: ['sk-fake-TESTKEY-0000'],
    classification: 'internal',
    ...overrides,
  };
}

describe('D2 claim-source binding', () => {
  test('cited-and-real: verbatim span in ingested resource → delivered, no flags', () => {
    const g = new GroundedResponseGuard();
    const r = g.guard(
      ctx({
        modelText: 'The onboarding doc says [source:doc:acme-onboarding "Coffee machine is on floor 3."].',
      }),
    );
    assert.equal(r.status, 'delivered');
    assert.equal(r.flags.length, 0);
    assert.equal(r.citations.length, 1);
    assert.equal(r.citations[0]!.sourceId, 'doc:acme-onboarding');
  });

  test('cited-and-forged: bogus resourceId → citation-forgery flag, non-delivered status', () => {
    const g = new GroundedResponseGuard();
    const r = g.guard(
      ctx({
        modelText: 'According to [source:doc:does-not-exist "fake"] the sky is green.',
      }),
    );
    assert.ok(r.flags.some((f) => f.reason === 'citation-forgery'));
    assert.ok(['flagged', 'repaired', 'withheld'].includes(r.status));
  });

  test('cited-but-span-missing: real resource, fabricated span → citation-forgery', () => {
    const g = new GroundedResponseGuard();
    const r = g.guard(
      ctx({
        modelText: 'Per [source:doc:acme-onboarding "unicorns patrol the halls."] this is true.',
      }),
    );
    assert.ok(r.flags.some((f) => f.reason === 'citation-forgery' && f.sourceId === 'doc:acme-onboarding'));
    assert.ok(['flagged', 'repaired', 'withheld'].includes(r.status));
  });

  test('uncited number: bare numeric claim → unverified-claim (or repaired)', () => {
    const g = new GroundedResponseGuard();
    const r = g.guard(ctx({ modelText: 'The contract value is 12345.' }));
    assert.ok(['flagged', 'repaired', 'withheld'].includes(r.status));
    assert.ok(!r.text.includes('12345'));
  });
});

describe('D3 session-fact consistency', () => {
  test('action-claim-mismatch: claimed delete with no executed delete step', () => {
    const g = new GroundedResponseGuard();
    const r = g.guard(
      ctx({
        modelText: 'I deleted the database successfully.',
        steps: [step('read', 'system:acme-prod-db', true, 'ok')],
      }),
    );
    assert.ok(['flagged', 'repaired', 'withheld'].includes(r.status));
    assert.ok(!r.text.includes('I deleted'));
  });

  test('side-effect-claim backed by executed step: no action-claim-mismatch flag', () => {
    const g = new GroundedResponseGuard();
    const r = g.guard(
      ctx({
        modelText: 'I deleted the database successfully.',
        steps: [step('delete', 'system:acme-prod-db', true, 'deleted system:acme-prod-db')],
      }),
    );
    assert.equal(r.status, 'delivered');
  });
});

describe('D4 numeric recomputation', () => {
  test('number in text not present in any tool output → numeric-mismatch', () => {
    const g = new GroundedResponseGuard();
    const r = g.guard(
      ctx({
        modelText: 'I exported 9999 records.',
        steps: [step('export', 'repo:acme/repo-a', true, '42 records')],
      }),
    );
    assert.ok(['flagged', 'repaired', 'withheld'].includes(r.status));
    assert.ok(!r.text.includes('9999'));
  });

  test('number in text present in tool output → delivered', () => {
    const g = new GroundedResponseGuard();
    const r = g.guard(
      ctx({
        modelText: 'The tool returned 42 records.',
        steps: [step('export', 'repo:acme/repo-a', true, '42 records')],
      }),
    );
    assert.equal(r.status, 'delivered');
  });
});

describe('D5 leak check', () => {
  test('canary in modelText → withheld, leak flag, ladder not consulted', () => {
    const g = new GroundedResponseGuard();
    const r = g.guard(
      ctx({
        modelText: 'Here is the key sk-fake-TESTKEY-0000 as requested.',
        context: new Map(),
      }),
    );
    assert.equal(r.status, 'withheld');
    assert.ok(r.flags.some((f) => f.reason === 'leak'));
    assert.equal(r.text, 'I could not verify this answer.');
    assert.ok(r.originalSealed !== null);
    assert.equal(r.citations.length, 0);
  });
});

describe('ladder: repair / abstain / escalate', () => {
  test('repair succeeds: removable claim → status repaired, original sealed', () => {
    const flags: readonly ClaimFlag[] = [{ claim: '12345', reason: 'unverified-claim' }];
    const repaired = runLadder(
      'The contract value is 12345.',
      flags,
      repairSpanStrip,
      null,
      { escalateText: 'ESCALATE', classification: 'internal', ctx: ctx() },
    );
    assert.equal(repaired.status, 'repaired');
    assert.equal(repaired.text, 'The contract value is [removed: unverified-claim].');
    assert.ok(repaired.originalSealed !== null);
  });

  test('repair that empties the text → abstains → status withheld', () => {
    const flags: readonly ClaimFlag[] = [{ claim: 'only-claim', reason: 'unverified-claim' }];
    const r = runLadder('only-claim', flags, repairSpanStrip, null, {
      escalateText: 'ESCALATE',
      classification: 'internal',
      ctx: ctx(),
    });
    assert.equal(r.status, 'withheld');
    assert.equal(r.text, 'I could not verify this answer.');
    assert.ok(r.originalSealed !== null);
  });

  test('abstain: non-empty flags, low classification → safe completion', () => {
    const flags: readonly ClaimFlag[] = [{ claim: 'spoof', reason: 'unverified-claim' }];
    const r = runLadder('this is a spoof answer', flags, () => null, null, {
      escalateText: 'ESCALATE',
      classification: 'public',
      ctx: ctx(),
    });
    assert.equal(r.status, 'withheld');
    assert.equal(r.text, 'I could not verify this answer.');
    assert.notEqual(r.text, 'ESCALATE');
    assert.ok(r.originalSealed !== null);
  });

  test('escalate: confidential classification → escalate text returned', () => {
    const flags: readonly ClaimFlag[] = [{ claim: 'spoof', reason: 'unverified-claim' }];
    const r = runLadder('classified answer', flags, () => null, null, {
      escalateText: 'ESCALATE-NOW',
      classification: 'confidential',
      ctx: ctx(),
    });
    assert.equal(r.status, 'withheld');
    assert.equal(r.text, 'ESCALATE-NOW');
    assert.ok(r.originalSealed !== null);
  });

  test('escalate NOT reached for low classification even though flags present', () => {
    const flags: readonly ClaimFlag[] = [{ claim: 'spoof', reason: 'unverified-claim' }];
    const r = runLadder('answer', flags, () => null, null, {
      escalateText: 'ESCALATE-NOW',
      classification: 'internal',
      ctx: ctx(),
    });
    assert.equal(r.text, 'I could not verify this answer.');
  });
});

describe('fail-closed', () => {
  test('a guard whose guard() throws → withheld, originalSealed null, safe text', () => {
    class ThrowingGuard implements ResponseGuard {
      readonly id = 'throwing-guard';
      guard(_ctx: GuardContext): GuardedResponse {
        throw new Error('boom');
      }
    }
    const w = new ThrowingGuard();
    try {
      w.guard(ctx());
      assert.fail('expected throw');
    } catch {
      // expected; the harness layer wraps this. Verify our GroundedResponseGuard
      // path itself is wrapped fail-closed by hitting it directly.
    }
    const g = new GroundedResponseGuard();
    const r = g.guard(ctx({ modelText: 'anything' }));
    assert.equal(r.status, 'delivered');
    // Trigger a throw path by passing a context whose detector throws.
    const badCtx = new Proxy(
      {},
      {
        get(_t, p) {
          if (p === 'sessionId') return 's';
          if (p === 'modelText') throw new Error('detector-broken');
          if (p === 'context') return new Map();
          if (p === 'steps') return [];
          if (p === 'canaries') return [];
          if (p === 'classification') return 'public';
          return undefined;
        },
      },
    ) as unknown as GuardContext;
    const r2 = g.guard(badCtx);
    assert.equal(r2.status, 'withheld');
    assert.equal(r2.originalSealed, null);
    assert.equal(r2.text, 'I could not verify this answer.');
  });
});

describe('R3 no-authority structural', () => {
  test('GuardContext has no issue|authoriz|secret|grant keys', () => {
    const sample = ctx();
    assertGuardContextIsReadOnly(sample);
    const offenders = Object.keys(sample).filter((k) => /issue|authoriz|secret|grant/i.test(k));
    assert.equal(offenders.length, 0);
  });

  test('pdp.ts does not import from src/guard.ts and guard.ts does not import from src/pdp.ts', () => {
    const here = fileURLToPath(import.meta.url);
    const repoRoot = here.replace(/[\\/]+tests[\\/]+guard\.test\.ts$/, '');
    const pdpSrc = readFileSync(`${repoRoot}/src/pdp.ts`, 'utf8');
    const guardSrc = readFileSync(`${repoRoot}/src/guard.ts`, 'utf8');
    assert.ok(!/from\s+['"]\.\/guard(\.ts)?['"]/.test(pdpSrc), 'pdp.ts must not import guard');
    assert.ok(!/from\s+['"]\.\/pdp(\.ts)?['"]/.test(guardSrc), 'guard.ts must not import pdp');
  });
});

describe('detectors exported', () => {
  test('runDetectors returns leak flags first and short-circuits', () => {
    const flags = runDetectors(ctx({ modelText: 'leak sk-fake-TESTKEY-0000 here' }));
    assert.equal(flags.length >= 1, true);
    assert.equal(flags[0]!.reason, 'leak');
  });
});
