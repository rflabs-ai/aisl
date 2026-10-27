/**
 * H14 — adversarial evaluation harness (ADR-033).
 *
 * Asserts the two properties the milestone actually claims: the run is
 * reproducible (digests are stable across processes and runs) and drift is
 * visible (any change to corpus, fixtures, or the decision vector fails a lane
 * until the baseline is deliberately re-blessed).
 *
 * Structural invariant: the report carries digests and counts only — never
 * fixture content. The canary test builds a report over a corpus file that
 * contains a unique secret-shaped token and asserts the token never reaches
 * the serialized report.
 */

import { test, describe } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { mockAuth } from '../src/testing.ts';
import { BASELINE_POLICY, createPolicyEngine, type PolicyRule } from '../src/policy.ts';
import { simulate, type Scenario } from '../src/policy-testing.ts';
import {
  ADVERSARIAL_REPORT_VERSION,
  buildBaseline,
  buildReport,
  corpusLane,
  decidedVector,
  digestDecisionVector,
  digestDirectory,
  differentialLane,
  driftLane,
  type Digests,
} from '../src/adversarial.ts';

const agent = {
  id: 'agent:a',
  kind: 'agent' as const,
  tenantId: 'acme',
  roles: [],
  attributes: {},
  auth: mockAuth({ subject: 'agent:a' }),
};

const doc = (id: string, classification: string) => ({
  id,
  type: 'document' as const,
  tenantId: 'acme',
  classification,
  attributes: {},
});

const scenarios: readonly Scenario[] = [
  { principal: agent, resource: doc('r', 'internal'), action: 'read', now: 1 },
  { principal: agent, resource: doc('phi', 'phi'), action: 'export', now: 1 },
  { principal: agent, resource: doc('phi', 'phi'), action: 'read', now: 1 },
];

const DIGESTS: Digests = {
  corpus: 'a'.repeat(64),
  fixtures: 'b'.repeat(64),
  decisions: 'c'.repeat(64),
};

function withTempDir(files: Record<string, string>, fn: (dir: string) => void): void {
  const dir = mkdtempSync(join(tmpdir(), 'h14-'));
  try {
    for (const [name, content] of Object.entries(files)) writeFileSync(join(dir, name), content);
    fn(dir);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
}

describe('H14: corpus digests are reproducible', () => {
  test('the same directory digests identically across calls', () => {
    withTempDir({ '02-b.json': '{"id":"b"}', '01-a.json': '{"id":"a"}' }, (dir) => {
      assert.equal(digestDirectory(dir), digestDirectory(dir));
    });
  });

  test('filename order on disk does not change the digest (sorted read)', () => {
    withTempDir({ '01-a.json': '{"id":"a"}', '02-b.json': '{"id":"b"}' }, (forward) => {
      let reverseDigest = '';
      withTempDir({ '02-b.json': '{"id":"b"}', '01-a.json': '{"id":"a"}' }, (reverse) => {
        reverseDigest = digestDirectory(reverse);
      });
      assert.equal(digestDirectory(forward), reverseDigest);
    });
  });

  test('a one-byte change fails the digest — drift is visible, not silent', () => {
    let before = '';
    withTempDir({ '01-a.json': '{"id":"a"}' }, (dir) => {
      before = digestDirectory(dir);
    });
    withTempDir({ '01-a.json': '{"id":"A"}' }, (dir) => {
      assert.notEqual(digestDirectory(dir), before);
    });
  });

  test('a renamed file fails the digest (names are part of the corpus contract)', () => {
    let before = '';
    withTempDir({ '01-a.json': '{"id":"a"}' }, (dir) => {
      before = digestDirectory(dir);
    });
    withTempDir({ '02-a.json': '{"id":"a"}' }, (dir) => {
      assert.notEqual(digestDirectory(dir), before);
    });
  });

  test('the digest is a lowercase sha256 hex string', () => {
    withTempDir({ '01-a.json': '{}' }, (dir) => {
      assert.match(digestDirectory(dir), /^[0-9a-f]{64}$/);
    });
  });
});

describe('H14: the decision vector is a stable oracle input', () => {
  test('two engines built from the same policy produce the same vector digest', () => {
    const a = simulate(createPolicyEngine(BASELINE_POLICY, 'a'), scenarios);
    const b = simulate(createPolicyEngine(BASELINE_POLICY, 'b'), scenarios);
    assert.equal(digestDecisionVector(decidedVector(a)), digestDecisionVector(decidedVector(b)));
  });

  test('the vector carries effect, rule id, and reason — not just allow/deny', () => {
    const decisions = simulate(createPolicyEngine(BASELINE_POLICY), scenarios);
    const vector = decidedVector(decisions);
    assert.equal(vector.length, scenarios.length);
    assert.match(vector[0]!, /^allow\|allow-agent-read-low\|/);
    assert.match(vector[1]!, /^deny\|deny-export-restricted\|/);
    assert.match(vector[2]!, /^deny\|\|/); // default deny: no rule id
  });

  test('a one-line overlay that changes a decision changes the vector digest', () => {
    const baseline = digestDecisionVector(
      decidedVector(simulate(createPolicyEngine(BASELINE_POLICY), scenarios)),
    );
    const flip: PolicyRule = {
      id: 'overlay-deny-agent-read',
      effect: 'deny',
      description: 'overlay',
      principals: { kinds: ['agent'] },
      actions: ['read'],
      resources: {},
    };
    const after = digestDecisionVector(
      decidedVector(simulate(createPolicyEngine([...BASELINE_POLICY, flip], 'overlay'), scenarios)),
    );
    assert.notEqual(after, baseline);
  });
});

describe('H14: drift lanes', () => {
  test('matching baseline passes the drift lane', () => {
    const baseline = buildBaseline(DIGESTS, '2026-10-27T00:00:00.000Z');
    const lane = driftLane(DIGESTS, baseline);
    assert.equal(lane.lane, 'drift');
    assert.equal(lane.passed, true);
  });

  test('a changed corpus digest fails the drift lane and names the lane', () => {
    const baseline = buildBaseline(DIGESTS, '2026-10-27T00:00:00.000Z');
    const lane = driftLane({ ...DIGESTS, corpus: 'd'.repeat(64) }, baseline);
    assert.equal(lane.passed, false);
    assert.match(lane.detail, /corpus/);
  });

  test('fixtures drift fails independently of corpus drift', () => {
    const baseline = buildBaseline(DIGESTS, '2026-10-27T00:00:00.000Z');
    const lane = driftLane({ ...DIGESTS, fixtures: 'e'.repeat(64) }, baseline);
    assert.equal(lane.passed, false);
    assert.match(lane.detail, /fixtures/);
  });

  test('no baseline fails closed with an actionable detail', () => {
    const lane = driftLane(DIGESTS, null);
    assert.equal(lane.passed, false);
    assert.match(lane.detail, /--bless/);
  });

  test('the differential lane tracks the decision vector, not the corpus', () => {
    const baseline = buildBaseline(DIGESTS, '2026-10-27T00:00:00.000Z');
    assert.equal(differentialLane(DIGESTS, baseline).passed, true);
    const lane = differentialLane({ ...DIGESTS, decisions: 'f'.repeat(64) }, baseline);
    assert.equal(lane.lane, 'differential');
    assert.equal(lane.passed, false);
    assert.match(lane.detail, /decision/);
  });

  test('the corpus lane reports the failed case ids', () => {
    assert.equal(corpusLane(12, 12).passed, true);
    const lane = corpusLane(11, 12, ['ATK-999-broken']);
    assert.equal(lane.passed, false);
    assert.match(lane.detail, /ATK-999-broken/);
  });
});

describe('H14: report shape and the no-plaintext invariant', () => {
  test('passed is true only when every lane passed', () => {
    const baseline = buildBaseline(DIGESTS, '2026-10-27T00:00:00.000Z');
    const ok = buildReport({
      generatedAt: '2026-10-27T00:00:00.000Z',
      gitHead: 'deadbeef',
      digests: DIGESTS,
      lanes: [corpusLane(12, 12), driftLane(DIGESTS, baseline), differentialLane(DIGESTS, baseline)],
    });
    assert.equal(ok.version, ADVERSARIAL_REPORT_VERSION);
    assert.equal(ok.passed, true);
    assert.equal(ok.lanes.length, 3);

    const bad = buildReport({
      generatedAt: '2026-10-27T00:00:00.000Z',
      gitHead: null,
      digests: DIGESTS,
      lanes: [corpusLane(11, 12, ['ATK-001'])],
    });
    assert.equal(bad.passed, false);
    assert.equal(bad.gitHead, null);
  });

  test('the serialized report carries no fixture content (canary never reaches it)', () => {
    const canary = 'sk-live-CANARY-9f3a2b7c1d';
    withTempDir({ '01-canary.json': `{"note":"${canary}"}` }, (dir) => {
      const digests: Digests = { corpus: digestDirectory(dir), fixtures: digestDirectory(dir), decisions: 'c'.repeat(64) };
      const report = buildReport({
        generatedAt: '2026-10-27T00:00:00.000Z',
        gitHead: null,
        digests,
        lanes: [corpusLane(1, 1)],
      });
      const serialized = JSON.stringify(report);
      assert.ok(!serialized.includes(canary));
      assert.ok(!serialized.includes('sk-live-CANARY'));
    });
  });
});
