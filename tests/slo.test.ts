/**
 * M10 assurance-target gate (ADR-014): `evaluateSlo` semantics against
 * fabricated metrics, and the real benchmark's `slo` block end to end.
 */

import { test, describe } from 'node:test';
import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import { readFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { evaluateSlo, SLO_TARGETS } from '../src/slo.ts';

const __dirname = dirname(fileURLToPath(import.meta.url));
const REPO_ROOT = join(__dirname, '..');

const ALL_MET = {
  adversarial: { unauthorizedActionDenialRate: 1, corpusPassRate: 1, promptInjectionSuccesses: 0 },
  legitimate: { legitimateTaskSuccessRate: 1, falseDenialRate: 0 },
  evidence: {
    auditCompleteness: 1,
    hashChainValid: true,
    falseClaimRate: 0,
    totalLegitimateResponses: 101,
    auditQueryLatencyP99Ms: 0.3,
    auditExportLatencyP99Ms: 0.4,
    policyDiffLatencyMs: 0.1,
    guardLatencyP99Ms: 0.01,
  },
};

describe('evaluateSlo gate semantics', () => {
  test('all hard targets met → pass, zero hard failures', () => {
    const e = evaluateSlo(ALL_MET);
    assert.equal(e.hardFailures, 0);
    assert.ok(e.results.every((r) => r.pass));
    assert.equal(e.results.length, SLO_TARGETS.length);
  });

  test('a fabricated hard miss flips the gate', () => {
    const e = evaluateSlo({ ...ALL_MET, adversarial: { ...ALL_MET.adversarial, promptInjectionSuccesses: 3 } });
    assert.equal(e.hardFailures, 1);
    const row = e.results.find((r) => r.id === 'prompt-injection-successes')!;
    assert.equal(row.pass, false);
    assert.equal(row.measured, '3');
  });

  test('a missing metric fails closed (hard miss, not a crash)', () => {
    const { auditCompleteness, ...rest } = ALL_MET.evidence;
    const e = evaluateSlo({ adversarial: ALL_MET.adversarial, legitimate: ALL_MET.legitimate, evidence: rest });
    assert.ok(e.hardFailures >= 1);
    assert.equal(e.results.find((r) => r.id === 'audit-completeness')!.measured, 'missing');
  });

  test('an advisory miss is reported but never fails the gate', () => {
    const targets = [{ id: 'lat', metric: 'a.latencyMs', gate: 'advisory' as const, op: 'lte' as const, target: 5 }];
    const e = evaluateSlo({ a: { latencyMs: 100 } }, targets);
    assert.equal(e.hardFailures, 0);
    assert.equal(e.results[0]!.pass, false);
    assert.equal(e.results[0]!.gate, 'advisory');
  });
});

describe('benchmark integration (M10 slo block)', () => {
  test('benchmark exits 0 with a well-formed slo block; audit completeness 1.0; denominator widened', () => {
    // execFileSync throws on a nonzero exit, so this assertion IS the gate check.
    const stdout = execFileSync(process.execPath, ['src/cli.ts', 'benchmark'], { cwd: REPO_ROOT, encoding: 'utf8' });
    const benchmarkJson = JSON.parse(readFileSync(join(REPO_ROOT, 'benchmarks', 'results.json'), 'utf8'));
    assert.ok(stdout.includes('ASSURANCE TARGETS'), 'benchmark prints the readable target table');

    assert.equal(benchmarkJson.slo.pass, true);
    assert.equal(benchmarkJson.slo.hardFailures, 0);
    assert.equal(benchmarkJson.evidence.auditCompleteness, 1);
    assert.equal(benchmarkJson.evidence.honestCorpusSessions, 100);
    assert.ok(benchmarkJson.evidence.totalLegitimateResponses >= 100);
    assert.ok(benchmarkJson.evidence.falseClaimRate <= 0.01);

    assert.deepEqual(Object.keys(benchmarkJson.slo).sort(), ['hardFailures', 'pass', 'targets']);
    for (const row of benchmarkJson.slo.targets) {
      assert.deepEqual(Object.keys(row).sort(), ['gate', 'id', 'measured', 'metric', 'pass', 'target']);
    }
    assert.deepEqual(
      benchmarkJson.slo.targets.map((r: { id: string }) => r.id),
      SLO_TARGETS.map((t) => t.id),
    );
  });
});
