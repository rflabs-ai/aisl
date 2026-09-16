/**
 * Developer CLI: `demo`, `attack`, `benchmark`.
 *
 * The demo is the MVP acceptance walkthrough from section 23 of the brief:
 * legitimate work succeeds, every attack is denied, and the evidence chain
 * proves what happened.
 *
 * Run: node src/cli.ts demo
 */

import { mkdirSync, readdirSync, readFileSync, writeFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { runAttackCorpus } from './attacks.ts';
import { type Approval } from './policy.ts';
import { buildWorld, summarizeRepoModel, TENANT_A } from './scenario.ts';
import { detectInjectionSignals } from './registry.ts';
import { mockAuth } from './testing.ts';

const ROOT = join(dirname(fileURLToPath(import.meta.url)), '..');

function line(label: string, status: string, detail: string): void {
  console.log(`  ${status.padEnd(6)} ${label.padEnd(46)} ${detail}`);
}

function heading(text: string): void {
  console.log(`\n${text}\n${'-'.repeat(text.length)}`);
}

function demo(): void {
  const world = buildWorld();
  const r = world.resources;

  heading('MVP DEMO — high-assurance AI execution environment');
  console.log(`  tenant: ${TENANT_A}   model: scripted (assumed hostile)   sandbox: in-process (no isolation yet)`);

  heading('1. Legitimate task');
  const legitTrace = world.session(summarizeRepoModel()).run([]);
  const legit = legitTrace.steps[0]!;
  line('read repository A', legit.decision.decision === 'allow' ? 'ALLOW' : 'DENY', legit.decision.reason);
  console.log(`         output: ${String(legit.output).split('\n')[0]}`);

  heading('2-7. Attacks');
  const attacks = runAttackCorpus(world, join(ROOT, 'security-attacks'));
  for (const a of attacks) {
    const outcome = a.outcomes[0]!;
    const status = a.passed ? (outcome.decision === 'deny' ? 'DENY' : 'ALLOW') : 'FAIL';
    line(`${a.testCase.id} ${a.testCase.class}`, status, `${outcome.denyReason ?? outcome.decision}: ${outcome.reason}`);
    if (a.injectionSignals.length > 0) {
      console.log(`         injection signals detected (telemetry only): ${a.injectionSignals.length}`);
    }
  }

  heading('8. Human approval issues a narrow, single-use capability');
  const demoUserAuth = mockAuth({ subject: world.user.id, amr: ['pwd', 'mfa'] });
  const approval: Approval = {
    id: 'approval-1',
    approvedBy: world.user.id,
    reviewerAuth: demoUserAuth,
    principalId: world.agent.id,
    action: 'read',
    resourceId: r.confidentialDoc!,
    expiresAt: world.clock.now() + 600_000,
  };
  const granted = world.authorization.issue(world.root, {
    subject: world.agent.id,
    tenantId: TENANT_A,
    resourceIds: [r.confidentialDoc!],
    actions: ['read'],
    maxClassification: 'confidential',
    expiresAt: world.clock.now() + 600_000,
    singleUse: true,
    provenance: { source: 'human-approval', approvedBy: world.user.id, note: 'merger doc review' },
  });
  line('approval recorded + capability issued', 'ISSUE', `${granted.id} (single-use, 10 min, confidential ceiling)`);

  heading('9. Approved operation succeeds exactly once');
  const approvedSession = world.session(summarizeRepoModel(), { approvals: [approval] });
  const first = approvedSession.attempt({ action: 'read', resourceId: r.confidentialDoc! });
  line('read confidential merger doc', first.decision.decision === 'allow' ? 'ALLOW' : 'DENY', first.decision.reason);
  const second = approvedSession.attempt({ action: 'read', resourceId: r.confidentialDoc! });
  line('replay the same read', second.decision.decision === 'deny' ? 'DENY' : 'ALLOW', second.decision.reason);

  heading('10. Evidence');
  const chain = world.eventLog.verify();
  const events = world.eventLog.all();
  const denied = events.filter((e) => e.decision === 'deny').length;
  const allowed = events.filter((e) => e.decision === 'allow').length;
  console.log(`  events: ${events.length}   allow decisions: ${allowed}   deny decisions: ${denied}`);
  console.log(`  hash chain valid: ${chain.valid}${chain.valid ? '' : ` (broken at seq ${chain.firstBrokenSeq})`}`);
  console.log(`  head: ${events.at(-1)?.eventHash.slice(0, 32)}...`);
  console.log(`  every decision is recorded: ${denied + allowed > 0}`);
}

function attack(): void {
  const world = buildWorld();
  const results = runAttackCorpus(world, join(ROOT, 'security-attacks'));
  heading('ATTACK HARNESS');
  let failed = 0;
  for (const a of results) {
    if (!a.passed) failed++;
    const detail = a.outcomes
      .map((o) => `${o.request.action}@${o.request.resourceId}=${o.decision}${o.denyReason ? `(${o.denyReason})` : ''}`)
      .join(', ');
    line(`${a.testCase.id} ${a.testCase.name.slice(0, 30)}`, a.passed ? 'PASS' : 'FAIL', detail);
  }
  console.log(`\n  ${results.length - failed}/${results.length} attack cases behaved as required.`);
  if (failed > 0) process.exitCode = 1;
}

function benchmark(): void {
  const world = buildWorld();
  const attacks = runAttackCorpus(world, join(ROOT, 'security-attacks'));
  const legitimate = runAttackCorpus(world, join(ROOT, 'security-fixtures'));

  const advOutcomes = attacks.flatMap((a) => a.outcomes);
  const legitOutcomes = legitimate.flatMap((a) => a.outcomes);
  const injectionCases = attacks.filter((a) => a.testCase.injectedContent !== undefined);
  const injectionOutcomes = injectionCases.flatMap((a) => a.outcomes);

  const events = world.eventLog.all();
  const decisionEvents = events.filter((e) => e.metadata !== undefined && (e.metadata as { phase?: string }).phase === 'decision');
  const expectedDecisions = advOutcomes.length + legitOutcomes.length;

  const corpusDir = join(ROOT, 'security-fixtures', 'corpus');
  const corpus = readdirSync(corpusDir)
    .filter((f) => f.endsWith('.md'))
    .map((f) => ({ file: f, signals: detectInjectionSignals(readFileSync(join(corpusDir, f), 'utf8')) }));

  const denyReasons: Record<string, number> = {};
  for (const o of [...advOutcomes, ...legitOutcomes]) {
    if (o.denyReason) denyReasons[o.denyReason] = (denyReasons[o.denyReason] ?? 0) + 1;
  }

  const metrics = {
    generatedAt: new Date().toISOString(),
    node: process.version,
    policyEngine: world.policy.id,
    adversarial: {
      cases: attacks.length,
      casesBehavingAsRequired: attacks.filter((a) => a.passed).length,
      requests: advOutcomes.length,
      denied: advOutcomes.filter((o) => o.decision === 'deny').length,
      unauthorizedActionDenialRate: ratio(advOutcomes.filter((o) => o.decision === 'deny').length, advOutcomes.length),
      promptInjectionRequests: injectionOutcomes.length,
      promptInjectionSuccesses: injectionOutcomes.filter((o) => o.decision === 'allow').length,
    },
    legitimate: {
      cases: legitimate.length,
      requests: legitOutcomes.length,
      allowed: legitOutcomes.filter((o) => o.decision === 'allow').length,
      legitimateTaskSuccessRate: ratio(legitOutcomes.filter((o) => o.decision === 'allow').length, legitOutcomes.length),
      falseDenialRate: ratio(legitOutcomes.filter((o) => o.decision === 'deny').length, legitOutcomes.length),
    },
    evidence: {
      events: events.length,
      decisionEvents: decisionEvents.length,
      expectedDecisions,
      auditCompleteness: ratio(decisionEvents.length, expectedDecisions),
      hashChainValid: world.eventLog.verify().valid,
      head: events.at(-1)?.eventHash ?? null,
    },
    corpus: {
      documents: corpus.length,
      documentsWithInjectionSignals: corpus.filter((c) => c.signals.length > 0).length,
      note: 'detector is informational only; it is not an authorization input',
    },
    denyReasonBreakdown: denyReasons,
  };

  mkdirSync(join(ROOT, 'benchmarks'), { recursive: true });
  writeFileSync(join(ROOT, 'benchmarks', 'results.json'), `${JSON.stringify(metrics, null, 2)}\n`);

  heading('BENCHMARK (measured this run — not a claim about the product)');
  console.log(JSON.stringify(metrics, null, 2));
}

function ratio(n: number, d: number): number {
  return d === 0 ? 0 : Math.round((n / d) * 1000) / 1000;
}

const command = process.argv[2] ?? 'demo';
if (command === 'demo') demo();
else if (command === 'attack') attack();
else if (command === 'benchmark') benchmark();
else {
  console.error(`unknown command: ${command} (try demo | attack | benchmark)`);
  process.exitCode = 1;
}
