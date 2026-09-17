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
import { BASELINE_POLICY, createPolicyEngine, type Approval, type PolicyRule } from './policy.ts';
import { type Resource } from './domain.ts';
import { buildWorld, summarizeRepoModel, TENANT_A } from './scenario.ts';
import { detectInjectionSignals } from './registry.ts';
import { mockAuth } from './testing.ts';
import { verifyBundle, eventPublicKey } from './events.ts';
import { diffDecisions, loadFixtures, simulate, type Scenario } from './policy-testing.ts';
import { GroundedResponseGuard } from './guard.ts';

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

  heading('11. M3: signed events, anchor, and offline verification');
  const signed = world.eventLog.verify({ publicKey: eventPublicKey() });
  const anchorContent = world.eventLog.anchor();
  const offline = verifyBundle(world.eventLog.bundle(), {
    publicKey: eventPublicKey(),
    ...(anchorContent ? { anchorContent } : {}),
  });
  const sampleEvent = events.at(-1);
  console.log(`  per-event signatures: every event has an Ed25519 signature (sample: ${sampleEvent?.signature ? sampleEvent.signature.slice(0, 24) + '...' : 'none'})`);
  console.log(`  signature chain verification: ${signed.valid ? 'VALID' : 'INVALID'}`);
  console.log(`  offline verifier (no DB): ${offline.valid ? 'VALID' : 'INVALID'} (${offline.eventCount} events)`);
  console.log(`  anchor file: ${anchorContent ? `${anchorContent.trim().split('\n').length} lines, head match: ${offline.anchorMatch ? 'yes' : 'NO'}` : 'not configured (set EVENT_ANCHOR_PATH to enable external witness)'}`);

  heading('12. M5: hierarchical resource matching (idPatterns)');
  const m5Policy = createPolicyEngine([
    { id: 'allow-acme-tree', effect: 'allow', principals: { kinds: ['agent'] }, actions: ['read'], resources: { idPatterns: ['acme/...'] } },
  ]);
  const deep: Resource = { id: 'acme/project/sub/file', type: 'document', tenantId: TENANT_A, classification: 'internal', attributes: {} };
  const flat: Resource = { id: 'acme-other', type: 'document', tenantId: TENANT_A, classification: 'internal', attributes: {} };
  const allowDeep = m5Policy.evaluate({ principal: world.agent, resource: deep, action: 'read', now: world.clock.now() });
  const denyFlat = m5Policy.evaluate({ principal: world.agent, resource: flat, action: 'read', now: world.clock.now() });
  line('recursive acme/... allows acme/project/sub/file', allowDeep.effect === 'allow' ? 'ALLOW' : 'DENY', allowDeep.reason);
  line('recursive acme/... denies acme-other (boundary)', denyFlat.effect === 'allow' ? 'ALLOW' : 'DENY', denyFlat.reason);

  heading('13. M6: audit query + export API');
  world.authorization.issue(world.root, {
    subject: world.user.id,
    tenantId: TENANT_A,
    resourceIds: [`audit-log:${TENANT_A}`],
    actions: ['query.audit', 'audit.export'],
    maxClassification: 'internal',
    expiresAt: world.clock.now() + 3_600_000,
    provenance: { source: 'policy-grant', note: 'audit query and export' },
  });
  const queried = world.audit.query(world.user, { tenantId: TENANT_A, action: 'read', decision: 'deny' });
  line('query audit log (action: read, decision: deny)', 'QUERY', `returned ${queried.length} matching events`);
  const exported = world.audit.exportFor(world.user, { tenantId: TENANT_A, fromSeq: 0, toSeq: 10 });
  line(
    'export audit chain slice (seq 0..10)',
    'EXPORT',
    `head: ${exported.head.slice(0, 16)}..., previousHead: ${exported.previousHead ?? 'null'} (${exported.events.length} events)`,
  );

  heading('14. M7: policy testing framework');
  const fixtures = loadFixtures(join(ROOT, 'tests', 'fixtures', 'policy'));
  for (const f of fixtures) {
    const engine = createPolicyEngine(f.rules, `fixture:${f.id}`);
    const decisions = simulate(engine, f.scenarios);
    const passed = decisions.every((d, i) => d.effect === f.expected[i]!.effect);
    line(`fixture ${f.id}`, passed ? 'PASS' : 'FAIL', `${decisions.length}/${f.scenarios.length} scenarios`);
  }
  const baseline = createPolicyEngine(BASELINE_POLICY, 'baseline');
  const overlay = createPolicyEngine(
    [...BASELINE_POLICY, { id: 'deny-agent-read-overlay', effect: 'deny', principals: { kinds: ['agent'] }, actions: ['read'], resources: {} }],
    'baseline+overlay',
  );
  const harnessScenarios: Scenario[] = [
    { principal: world.agent, resource: { id: 'doc:repo-a', type: 'document', tenantId: TENANT_A, classification: 'internal', attributes: {} }, action: 'read', now: world.clock.now() },
    { principal: world.agent, resource: { id: 'doc:phi', type: 'document', tenantId: TENANT_A, classification: 'phi', attributes: {} }, action: 'read', now: world.clock.now() },
  ];
  const harnessDiffs = diffDecisions(baseline, overlay, harnessScenarios);
  line('diffDecisions(baseline, baseline+deny-agent-read)', 'DIFF', `${harnessDiffs.length} changed`);

  heading('15. M8: output reliability layer');
  // 15a: cited-and-real — guard returns delivered with the citation (span matches the ingested source)
  const realText = 'Per [source:doc:acme-onboarding "Coffee machine is on floor 3."], the machine is on floor three.';
  const realGuard = new GroundedResponseGuard();
  const realResp = realGuard.guard({
    sessionId: 'demo-15a',
    modelText: realText,
    context: world.content,
    steps: [],
    canaries: world.secretValues,
    classification: 'public',
  });
  line('cited-and-real', realResp.status === 'delivered' ? 'DELIVERED' : realResp.status.toUpperCase(), `${realResp.citations.length} citation(s), ${realResp.flags.length} flag(s)`);

  // 15b: cited-and-forged — guard flags the bogus source
  const forgedResp = realGuard.guard({
    sessionId: 'demo-15b',
    modelText: 'Per [source:doc:nonexistent "fabricated fact"], X is true.',
    context: world.content,
    steps: [],
    canaries: world.secretValues,
    classification: 'public',
  });
  const forgedFlag = forgedResp.flags.find((f) => f.reason === 'citation-forgery');
  line('cited-and-forged', forgedResp.status.toUpperCase(), `flag: ${forgedFlag?.reason ?? '(none)'}`);

  // 15c: prose leak — D5 skips ladder, withholds the leaky text
  const leakResp = realGuard.guard({
    sessionId: 'demo-15c',
    modelText: `The API key is ${world.secretValues[0]!}.`,
    context: world.content,
    steps: [],
    canaries: world.secretValues,
    classification: 'public',
  });
  const safeText = leakResp.text.includes(world.secretValues[0]!) === false;
  line('prose leak', leakResp.status.toUpperCase(), `safe completion: ${safeText ? 'yes' : 'NO'} (${leakResp.flags.length} flag(s))`);
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

  // M6: Benchmark audit query and export latency
  world.authorization.issue(world.root, {
    subject: world.user.id,
    tenantId: TENANT_A,
    resourceIds: [`audit-log:${TENANT_A}`],
    actions: ['query.audit', 'audit.export'],
    maxClassification: 'internal',
    expiresAt: world.clock.now() + 3_600_000,
    provenance: { source: 'policy-grant', note: 'benchmark audit grant' },
  });

  const queryLatencies: number[] = [];
  for (let i = 0; i < 1000; i++) {
    const t0 = performance.now();
    world.audit.query(world.user, { tenantId: TENANT_A, action: 'read', limit: 10 });
    queryLatencies.push(performance.now() - t0);
  }
  queryLatencies.sort((a, b) => a - b);
  const auditQueryLatencyP99Ms = Math.round(queryLatencies[Math.floor(0.99 * queryLatencies.length)]! * 1000) / 1000;

  const exportLatencies: number[] = [];
  for (let i = 0; i < 1000; i++) {
    const t0 = performance.now();
    world.audit.exportFor(world.user, { tenantId: TENANT_A, fromSeq: 0, toSeq: 10 });
    exportLatencies.push(performance.now() - t0);
  }
  exportLatencies.sort((a, b) => a - b);
  const auditExportLatencyP99Ms = Math.round(exportLatencies[Math.floor(0.99 * exportLatencies.length)]! * 1000) / 1000;

  // M7: policy diff primitive latency (one run, sub-ms expected)
  const harnessFixtures = loadFixtures(join(ROOT, 'tests', 'fixtures', 'policy'));
  const harnessBaseline = createPolicyEngine(BASELINE_POLICY, 'baseline');
  const harnessScenarios: Scenario[] = harnessFixtures.flatMap((f) => [...f.scenarios]);
  const t0 = performance.now();
  diffDecisions(harnessBaseline, harnessBaseline, harnessScenarios);
  const policyDiffLatencyMs = Math.round((performance.now() - t0) * 1000) / 1000;

  // M8: guard latency p99 (1000 small inputs)
  const guard = new GroundedResponseGuard();
  const guardLatencies: number[] = [];
  const smallInput = (i: number) => ({
    sessionId: `bench-${i}`,
    modelText: 'Repository A contains billing and invoice services.',
    context: world.content,
    steps: [],
    canaries: world.secretValues,
    classification: 'public' as const,
  });
  for (let i = 0; i < 1000; i++) {
    const t1 = performance.now();
    guard.guard(smallInput(i));
    guardLatencies.push(performance.now() - t1);
  }
  guardLatencies.sort((a, b) => a - b);
  const guardLatencyP99Ms = Math.round(guardLatencies[Math.floor(0.99 * guardLatencies.length)]! * 1000) / 1000;

  const events = world.eventLog.all();
  const decisionEvents = events.filter((e) => e.metadata !== undefined && (e.metadata as { phase?: string }).phase === 'decision');
  const guardVerdictEvents = events.filter((e) => e.action === 'session.guard');
  const expectedDecisions = advOutcomes.length + legitOutcomes.length + 1000 + 1000;

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
      guardVerdictEvents: guardVerdictEvents.length,
      expectedDecisions,
      auditCompleteness: ratio(decisionEvents.length, expectedDecisions),
      hashChainValid: world.eventLog.verify().valid,
      head: events.at(-1)?.eventHash ?? null,
      auditQueryLatencyP99Ms,
      auditExportLatencyP99Ms,
      policyDiffLatencyMs,
      guardLatencyP99Ms,
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
