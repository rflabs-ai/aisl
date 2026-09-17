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
import { type ActionRequest, type AuthorizationDecision, type Principal } from '../src/domain.ts';
import { CapabilityRequestService } from '../src/capability-request.ts';
import { testWorld } from '../src/testing.ts';

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

const TEST_AGENT: Principal = { id: 'agent:test', kind: 'agent', tenantId: 'acme', roles: [], attributes: {} };

function ctx(overrides: Partial<GuardContext> = {}): GuardContext {
  const body = new Map<string, string>([['doc:acme-onboarding', 'Coffee machine is on floor 3.']]);
  return {
    sessionId: 'sess-test',
    modelText: '',
    context: body,
    steps: [],
    canaries: ['sk-fake-TESTKEY-0000'],
    classification: 'internal',
    principal: TEST_AGENT,
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

  test('bare number with no steps → exactly one unverified-claim, never numeric-mismatch', () => {
    const flags = runDetectors(ctx({ modelText: 'The value is 12345.', steps: [] }));
    assert.equal(flags.length, 1);
    assert.equal(flags[0]!.reason, 'unverified-claim');
    assert.ok(!flags.some((f) => f.reason === 'numeric-mismatch'));
  });

  test('number absent from step output → exactly one numeric-mismatch, never unverified-claim', () => {
    const flags = runDetectors(
      ctx({
        modelText: 'The value is 12345.',
        steps: [step('export', 'repo:acme/repo-a', true, '42 records')],
      }),
    );
    assert.equal(flags.length, 1);
    assert.equal(flags[0]!.reason, 'numeric-mismatch');
    assert.ok(!flags.some((f) => f.reason === 'unverified-claim'));
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
    assert.equal(typeof r.originalSealed, 'object');
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

  test('regenerate succeeds after repair fails → rung regenerate, regenerate ran exactly once', () => {
    const flags: readonly ClaimFlag[] = [{ claim: '12345', reason: 'unverified-claim' }];
    let calls = 0;
    const r = runLadder('The contract value is 12345.', flags, () => null, () => {
      calls++;
      return 'The value is unavailable.';
    }, { escalateText: 'ESCALATE', classification: 'internal', ctx: ctx() });
    assert.equal(calls, 1);
    assert.equal(r.status, 'repaired');
    assert.equal(r.text, 'The value is unavailable.');
    assert.equal(r.ladderRung, 'regenerate');
    assert.equal(typeof r.originalSealed, 'object');
    assert.ok(r.originalSealed !== null);
  });

  test('regenerate still flagged → withheld, rung abstain, no retry, original sealed', () => {
    const flags: readonly ClaimFlag[] = [{ claim: '12345', reason: 'unverified-claim' }];
    let calls = 0;
    const r = runLadder('The contract value is 12345.', flags, () => null, () => {
      calls++;
      return 'still 12345';
    }, { escalateText: 'ESCALATE', classification: 'internal', ctx: ctx() });
    assert.equal(calls, 1);
    assert.equal(r.status, 'withheld');
    assert.equal(r.ladderRung, 'abstain');
    assert.equal(typeof r.originalSealed, 'object');
    assert.ok(r.originalSealed !== null);
  });
});

describe('ladderRung mapping', () => {
  test('delivered → null', () => {
    const r = runLadder('clean answer', [], repairSpanStrip, null, {
      escalateText: 'ESCALATE',
      classification: 'internal',
      ctx: ctx(),
    });
    assert.equal(r.status, 'delivered');
    assert.equal(r.ladderRung, null);
  });

  test('repair success → repair', () => {
    const flags: readonly ClaimFlag[] = [{ claim: '12345', reason: 'unverified-claim' }];
    const r = runLadder('The contract value is 12345.', flags, repairSpanStrip, null, {
      escalateText: 'ESCALATE',
      classification: 'internal',
      ctx: ctx(),
    });
    assert.equal(r.status, 'repaired');
    assert.equal(r.ladderRung, 'repair');
  });

  test('withheld at internal classification → abstain', () => {
    const flags: readonly ClaimFlag[] = [{ claim: 'spoof', reason: 'unverified-claim' }];
    const r = runLadder('classified answer', flags, () => null, null, {
      escalateText: 'ESCALATE',
      classification: 'internal',
      ctx: ctx(),
    });
    assert.equal(r.status, 'withheld');
    assert.equal(r.ladderRung, 'abstain');
  });

  test('withheld at confidential classification → escalate', () => {
    const flags: readonly ClaimFlag[] = [{ claim: 'spoof', reason: 'unverified-claim' }];
    const r = runLadder('classified answer', flags, () => null, null, {
      escalateText: 'ESCALATE',
      classification: 'confidential',
      ctx: ctx(),
    });
    assert.equal(r.status, 'withheld');
    assert.equal(r.ladderRung, 'escalate');
  });
});

describe('escalate wires to the M4 capability-request flow', () => {
  function escalateCtx(overrides: Partial<GuardContext> = {}): GuardContext {
    return ctx({
      modelText: 'I deleted',
      steps: [step('read', 'doc:acme-onboarding', true, 'ok')],
      classification: 'confidential',
      ...overrides,
    });
  }

  function serviceFor(world: ReturnType<typeof testWorld>): CapabilityRequestService {
    return new CapabilityRequestService(world.eventLog, world.authorization, world.root);
  }

  test('escalate queues a CapabilityRequest when the service is provided', () => {
    const world = testWorld();
    const service = serviceFor(world);
    const g = new GroundedResponseGuard();
    const r = g.guard(escalateCtx({ capabilityRequestService: service }));
    assert.equal(r.status, 'withheld');
    assert.ok(r.requestId !== undefined);
    assert.ok(r.text.includes(r.requestId!));
    const request = service.get(r.requestId!);
    assert.ok(request !== undefined);
    assert.equal(request.status, 'pending');
    assert.equal(request.principalId, TEST_AGENT.id);
    assert.ok(request.requestedActions.includes('guard.review'));
    assert.ok(request.justification.includes('action-claim-mismatch'));
    const events = world.eventLog.all();
    assert.equal(events.filter((e) => e.action === 'capability.request').length, 1);
    assert.equal(events.filter((e) => e.action === 'session.guard').length, 0);
  });

  test('escalate falls back to text-only when no service', () => {
    const g = new GroundedResponseGuard();
    const r = g.guard(escalateCtx());
    assert.equal(r.text, 'This response is awaiting human review (escalation required).');
    assert.equal(r.requestId, undefined);
  });

  test('escalate does NOT queue when classification < confidential', () => {
    const world = testWorld();
    const service = serviceFor(world);
    const g = new GroundedResponseGuard();
    const r = g.guard(escalateCtx({ classification: 'internal', capabilityRequestService: service }));
    assert.equal(r.status, 'withheld');
    assert.equal(r.text, 'I could not verify this answer.');
    assert.equal(r.requestId, undefined);
    assert.equal(service.all().length, 0);
  });

  test('escalate does NOT queue when the principal is not an agent', () => {
    const world = testWorld();
    const service = serviceFor(world);
    const g = new GroundedResponseGuard();
    const principal: Principal = { id: 'user:bob', kind: 'user', tenantId: 'acme', roles: [], attributes: {} };
    const r = g.guard(escalateCtx({ principal, capabilityRequestService: service }));
    assert.equal(r.requestId, undefined);
    assert.equal(service.all().length, 0);
  });
});

describe('D6 critic hook', () => {
  test('no critic → no critic-flag and clean text is delivered', () => {
    const g = new GroundedResponseGuard();
    const r = g.guard(ctx({ modelText: 'The value is unavailable.' }));
    assert.equal(r.status, 'delivered');
    assert.ok(!r.flags.some((f) => f.reason === 'critic-flag'));
  });

  test('critic flags merge into the ladder and are stripped on repair', () => {
    const g = new GroundedResponseGuard();
    const r = g.guard(ctx({ modelText: 'The value is unavailable.' }), () => [
      { claim: 'unavailable', reason: 'critic-flag' },
    ]);
    assert.equal(r.status, 'repaired');
    assert.equal(r.ladderRung, 'repair');
    assert.equal(r.text, 'The value is [removed: critic-flag].');
  });

  test('critic flag reaches the withheld response when unrepairable', () => {
    const g = new GroundedResponseGuard();
    const r = g.guard(ctx({ modelText: 'x' }), () => [{ claim: 'x', reason: 'critic-flag' }]);
    assert.equal(r.status, 'withheld');
    assert.equal(r.ladderRung, 'abstain');
    assert.ok(r.flags.some((f) => f.reason === 'critic-flag'));
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
