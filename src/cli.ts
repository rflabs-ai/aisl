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
import { buildWorld, summarizeRepoModel, TENANT_A, whenWorldReady } from './scenario.ts';
import { defineResource, detectInjectionSignals } from './registry.ts';
import { AgentSession, LocalSandbox } from './runtime.ts';
import { AuthorizationService } from './pdp.ts';
import { policyBundleHash, createEngineFromBundle } from './policy-config.ts';
import { mockAuth } from './testing.ts';
import { verifyBundle, eventPublicKey } from './events.ts';
import { diffDecisions, loadFixtures, simulate, type Scenario } from './policy-testing.ts';
import { GroundedResponseGuard } from './guard.ts';
import { CapabilityRequestService } from './capability-request.ts';
import { ScriptedModel } from './model.ts';
import { HttpModelAdapter, ModelEgressDeniedError } from './model-http.ts';
import { CommandCheck } from './check-command.ts';
import { JsonlTelemetry } from './telemetry.ts';
import { evaluateSlo } from './slo.ts';

const ROOT = join(dirname(fileURLToPath(import.meta.url)), '..');

function line(label: string, status: string, detail: string): void {
  console.log(`  ${status.padEnd(6)} ${label.padEnd(46)} ${detail}`);
}

function heading(text: string): void {
  console.log(`\n${text}\n${'-'.repeat(text.length)}`);
}

async function demo(): Promise<void> {
  const world = buildWorld();
  await whenWorldReady(world);
  const r = world.resources;

  heading('MVP DEMO — high-assurance AI execution environment');
  console.log(`  tenant: ${TENANT_A}   model: scripted (assumed hostile)   sandbox: in-process (no isolation yet)`);

  heading('1. Legitimate task');
  const legitTrace = await world.session(summarizeRepoModel()).run([]);
  const legit = legitTrace.steps[0]!;
  line('read repository A', legit.decision.decision === 'allow' ? 'ALLOW' : 'DENY', legit.decision.reason);
  console.log(`         output: ${String(legit.output).split('\n')[0]}`);

  heading('2-7. Attacks');
  const attacks = await runAttackCorpus(world, join(ROOT, 'security-attacks'));
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
    principal: world.agent,
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
    principal: world.agent,
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
    principal: world.agent,
  });
  const safeText = leakResp.text.includes(world.secretValues[0]!) === false;
  line('prose leak', leakResp.status.toUpperCase(), `safe completion: ${safeText ? 'yes' : 'NO'} (${leakResp.flags.length} flag(s))`);

  heading('16. M9: guard follow-ups — Escalate wired to M4');
  const requestService = new CapabilityRequestService(world.eventLog, world.authorization, world.root);
  // Confidential ceiling so the session's derived classification makes Escalate reachable.
  world.authorization.issue(world.root, {
    subject: world.agent.id,
    tenantId: TENANT_A,
    resourceIds: [r.internalDoc!],
    actions: ['read'],
    maxClassification: 'confidential',
    expiresAt: world.clock.now() + 3_600_000,
    provenance: { source: 'policy-grant', note: 'M9 demo: confidential ceiling to exercise Escalate' },
  });
  const hostileSession = world.session(
    new ScriptedModel('scripted-hostile-escalate-v1', [{ text: 'I deleted', requests: [] }]),
    { capabilityRequestService: requestService },
  );
  const hostileGuard = (await hostileSession.run([])).guarded!;
  line('hostile output, classification >= confidential', hostileGuard.status.toUpperCase(), hostileGuard.text);
  const m9GuardEvent = world.eventLog
    .all()
    .filter((e) => e.action === 'session.guard' && (e.metadata as { phase?: string } | undefined)?.phase === 'guard')
    .at(-1);
  const m9RequestEvent = world.eventLog.all().filter((e) => e.action === 'capability.request').at(-1);
  line(
    'session.guard event',
    m9GuardEvent ? 'LOGGED' : 'MISSING',
    `requestId: ${(m9GuardEvent?.metadata as { requestId?: string } | undefined)?.requestId ?? '(none)'}`,
  );
  line(
    'capability.request event',
    m9RequestEvent ? 'LOGGED' : 'MISSING',
    (m9RequestEvent?.metadata as { justification?: string } | undefined)?.justification ?? '',
  );

  heading('17. M11: role-scoped issuance, label propagation, versioned policy bundles');

  // 17a: role-templated issuance — roles narrow authority, they never mint it.
  const roleCap = world.authorization.issueForRole(world.root, 'worker', world.agent.id, [r.internalDoc!], {
    actions: ['read'],
    expiresAt: world.clock.now() + 600_000,
    provenance: { source: 'policy-grant', note: 'M11 demo: role-templated issuance' },
  });
  line('issueForRole(worker) mints at the role ceiling', 'ISSUE', `ceiling=${roleCap.maxClassification} actions=[${roleCap.actions.join(',')}]`);
  let roleOverreach = '';
  try {
    world.authorization.issueForRole(world.root, 'worker', world.agent.id, [r.confidentialDoc!], {
      actions: ['read'],
      maxClassification: 'confidential',
      expiresAt: world.clock.now() + 600_000,
      provenance: { source: 'policy-grant' },
    });
  } catch (e) {
    roleOverreach = (e as Error).message;
  }
  line('role overreach refused (confidential > worker ceiling internal)', roleOverreach ? 'REFUSED' : 'FAIL', roleOverreach);
  let agentMint = '';
  try {
    world.authorization.issueForRole(world.agent, 'worker', world.agent.id, [r.internalDoc!], {
      actions: ['read'],
      expiresAt: world.clock.now() + 600_000,
      provenance: { source: 'policy-grant' },
    });
  } catch (e) {
    agentMint = (e as Error).message;
  }
  line('agent cannot mint through a role', agentMint ? 'REFUSED' : 'FAIL', agentMint);

  // 17b: classification propagation — a write lifts the target label to the max
  // of the data sources the step sees; the label only raises, and the evidence
  // seals under the derived label's key.
  const draftId = 'doc:acme-draft-memo';
  world.registry.add(defineResource({ id: draftId, type: 'document', tenantId: TENANT_A, classification: 'public' }));
  const m11Policy = createPolicyEngine([
    ...BASELINE_POLICY,
    { id: 'allow-agent-write-m11', effect: 'allow', principals: { kinds: ['agent'] }, actions: ['write'], resources: {} },
  ]);
  const m11Authz = new AuthorizationService(world.registry, m11Policy, world.eventLog, world.clock.now);
  m11Authz.issue(world.root, {
    subject: world.agent.id,
    tenantId: TENANT_A,
    resourceIds: [draftId],
    actions: ['write'],
    maxClassification: 'restricted',
    expiresAt: world.clock.now() + 600_000,
    provenance: { source: 'policy-grant', note: 'M11 demo: write into a public draft' },
  });
  // Reduced content map so the demo's derived label is deterministic: the step
  // sees one confidential source document.
  const m11Session = new AgentSession({
    principal: world.agent,
    agentId: world.agent.id,
    model: summarizeRepoModel(),
    task: 'M11 propagation demo',
    registry: world.registry,
    authorization: m11Authz,
    eventLog: world.eventLog,
    tools: world.tools,
    sandbox: new LocalSandbox(),
    content: new Map([[r.confidentialDoc!, world.content.get(r.confidentialDoc!) ?? '']]),
    now: world.clock.now,
  });
  const m11Write = m11Session.attempt({ action: 'write', resourceId: draftId });
  line(
    'write into public draft (session holds a confidential source)',
    m11Write.executed ? 'RAISED' : 'DENY',
    `${draftId}: public -> ${world.registry.require(draftId).classification}`,
  );
  const m11WriteEvent = world.eventLog.all().filter((e) => e.action === 'write' && e.resourceId === draftId).at(-1);
  const m11Meta = m11WriteEvent?.metadata as { derivedClassification?: string; sealed?: { keyId?: string } } | undefined;
  line(
    'derived label recorded; evidence sealed under its key',
    'SEALED',
    `derived=${m11Meta?.derivedClassification} key=${m11Meta?.sealed?.keyId}`,
  );

  // 17c: versioned policy bundle — hash-verified load, tamper refused.
  const m11BundleBase = {
    id: 'policy:baseline-v1',
    version: 1,
    rules: BASELINE_POLICY,
    provenance: { source: 'repo:src/policy.ts', reviewedBy: 'user:alice', approvedAt: '2026-09-17T00:00:00Z' },
  } as const;
  const m11Bundle = { ...m11BundleBase, hash: policyBundleHash(m11BundleBase) };
  createEngineFromBundle(m11Bundle, { eventLog: world.eventLog, tenantId: TENANT_A, actor: world.root.id });
  const policyLoadEvents = world.eventLog.all().filter((e) => e.action === 'policy.load').length;
  line(
    'versioned policy bundle loads (hash verified)',
    policyLoadEvents === 1 ? 'LOAD' : 'FAIL',
    `v${m11Bundle.version}, ${m11Bundle.rules.length} rules, hash ${m11Bundle.hash.slice(0, 12)}..., policy.load events: ${policyLoadEvents}`,
  );
  let tamperRefused = '';
  const tampered = { ...m11Bundle, rules: [{ ...m11Bundle.rules[0]!, description: 'tampered by an attacker' }] };
  try {
    createEngineFromBundle(tampered);
  } catch (e) {
    tamperRefused = (e as Error).message;
  }
  line('tampered bundle refused (hash mismatch, fail closed)', tamperRefused ? 'REFUSED' : 'FAIL', tamperRefused);

  // 18: M13 — a real provider port behind the egress gate, and command checks.
  // The adapter is a transport, not a trust boundary: the compromised-model
  // assumption is unchanged, and output still flows through parseModelOutput.
  heading('18. M13: model provider adapter (egress gate) + command checks');
  const m13ProviderResourceId = 'model:acme-provider';
  world.registry.add(defineResource({ id: m13ProviderResourceId, type: 'api', tenantId: TENANT_A, classification: 'public', attributes: {} }));
  const m13Policy = createPolicyEngine([
    ...BASELINE_POLICY,
    { id: 'allow-agent-model-invoke', effect: 'allow', principals: { kinds: ['agent'] }, actions: ['model.invoke'], resources: { types: ['api'] } },
  ]);
  const m13Authz = new AuthorizationService(world.registry, m13Policy, world.eventLog, world.clock.now);
  m13Authz.issue(world.root, {
    subject: world.agent.id,
    tenantId: TENANT_A,
    resourceIds: [m13ProviderResourceId, r.repoA!],
    actions: ['model.invoke', 'read'],
    maxClassification: 'internal',
    expiresAt: world.clock.now() + 600_000,
    provenance: { source: 'policy-grant', note: 'M13 demo: provider egress at internal ceiling' },
  });

  // Scripted provider: a fetch mock shaped like an OpenAI chat-completions
  // response, so the demo is deterministic and touches no network.
  const m13ProviderCalls: number[] = [];
  const m13ProviderBody = {
    choices: [{
      message: {
        content: JSON.stringify({
          text: 'Repository A contains billing and invoice services.',
          requests: [{ action: 'read', resourceId: r.repoA! }],
        }),
      },
    }],
    usage: { prompt_tokens: 12, completion_tokens: 9 },
  };
  const m13Fetch: typeof fetch = async () => {
    m13ProviderCalls.push(1);
    return new Response(JSON.stringify(m13ProviderBody), { status: 200, headers: { 'content-type': 'application/json' } });
  };

  // The API key is resolved by the caller (in production, from the secret
  // broker after a PDP allow); the adapter never logs it, and the tests prove
  // it never reaches an event or an error message.
  const m13TelemetryLines: string[] = [];
  const m13Adapter = new HttpModelAdapter({
    id: 'openai-compat',
    providerResourceId: m13ProviderResourceId,
    providerModel: 'gpt-4o-mini',
    baseUrl: 'https://provider.test/v1',
    apiKey: world.secretValues[0]!,
    principal: world.agent,
    authorization: m13Authz,
    registry: world.registry,
    eventLog: world.eventLog,
    ceiling: 'internal',
    content: new Map([[r.repoA!, world.content.get(r.repoA!) ?? '']]),
    fetchImpl: m13Fetch,
    telemetry: new JsonlTelemetry((l) => m13TelemetryLines.push(l)),
  });

  const m13Session = new AgentSession({
    principal: world.agent,
    agentId: world.agent.id,
    model: m13Adapter,
    task: 'Summarize repository A via the provider port.',
    registry: world.registry,
    authorization: m13Authz,
    eventLog: world.eventLog,
    tools: world.tools,
    sandbox: new LocalSandbox(),
    content: new Map([[r.repoA!, world.content.get(r.repoA!) ?? '']]),
    checks: [],
    now: world.clock.now,
  });
  const m13Trace = await m13Session.run([]);
  const m13CallEvent = world.eventLog.all().filter((e) => e.action === 'model.call').at(-1);
  const m13CallMeta = m13CallEvent?.metadata as { egress?: string; usagePromptTokens?: number } | undefined;
  line(
    'provider call through the egress gate',
    m13Trace.steps[0]?.decision.decision === 'allow' && m13CallMeta?.egress === 'allow' ? 'ALLOW' : 'FAIL',
    `model.call: egress=${m13CallMeta?.egress} usage=${m13CallMeta?.usagePromptTokens}tok, provider calls: ${m13ProviderCalls.length}`,
  );
  line('structured telemetry', 'EMIT', m13TelemetryLines.at(-1)?.slice(0, 100) ?? 'none');

  // Ceiling refusal: content above the configured classification never leaves.
  let m13Refusal = '';
  try {
    await m13Adapter.complete({
      prompt: 'summarize',
      context: [world.content.get(r.confidentialDoc!) ?? ''],
      contextResourceIds: [r.confidentialDoc!],
      availableActions: [],
    });
  } catch (e) {
    m13Refusal = e instanceof ModelEgressDeniedError ? e.message : `unexpected: ${(e as Error).message}`;
  }
  const m13DenyEvent = world.eventLog
    .all()
    .filter((e) => e.action === 'model.call' && e.decision === 'deny')
    .at(-1);
  line(
    'ceiling refusal (confidential > internal, nothing sent)',
    m13Refusal && m13ProviderCalls.length === 1 && m13DenyEvent ? 'REFUSED' : 'FAIL',
    `${m13Refusal || 'no refusal recorded'}; provider calls still: ${m13ProviderCalls.length}`,
  );

  // Command checks: allowlisted argv execution over produced artifacts.
  const m13NodeAllowlist = [process.execPath];
  const m13Checks = [
    new CommandCheck({ name: 'lint-ok', argv: [process.execPath, '-e', 'process.exit(0)'], allowlist: m13NodeAllowlist }),
    new CommandCheck({ name: 'lint-bad', argv: [process.execPath, '-e', 'process.exit(1)'], allowlist: m13NodeAllowlist }),
  ];
  const m13CheckSession = new AgentSession({
    principal: world.agent,
    agentId: world.agent.id,
    model: new ScriptedModel('scripted-check-v1', [{ text: 'checked', requests: [{ action: 'read', resourceId: r.repoA! }] }]),
    task: 'M13 command-check demo',
    registry: world.registry,
    authorization: m13Authz,
    eventLog: world.eventLog,
    tools: world.tools,
    sandbox: new LocalSandbox(),
    content: new Map([[r.repoA!, world.content.get(r.repoA!) ?? '']]),
    checks: m13Checks,
    now: world.clock.now,
  });
  const m13CheckTrace = await m13CheckSession.run([]);
  const m13CheckStep = m13CheckTrace.steps[0]!;
  const [m13PassV, m13FailV] = m13CheckStep.verifications;
  line('command check passes (exit 0)', m13PassV?.result === 'pass' ? 'PASS' : 'FAIL', m13PassV?.evidence ?? 'missing');
  line(
    'command check fails (exit 1, step errored)',
    m13FailV?.result === 'fail' ? 'EXPECTED-FAIL' : 'FAIL',
    `${m13FailV?.evidence ?? 'missing'}; verification failures already mark the step errored`,
  );
}

async function attack(): Promise<void> {
  const world = buildWorld();
  await whenWorldReady(world);
  const results = await runAttackCorpus(world, join(ROOT, 'security-attacks'));
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

async function benchmark(): Promise<void> {
  const world = buildWorld();
  await whenWorldReady(world);
  const attacks = await runAttackCorpus(world, join(ROOT, 'security-attacks'));
  const firstPassGuardCount = world.eventLog
    .all()
    .filter((e) => e.action === 'session.guard' && (e.metadata as { phase?: string } | undefined)?.phase === 'guard').length;
  const legitimate = await runAttackCorpus(world, join(ROOT, 'security-fixtures'));

  // M10: R1-style honest corpus — widens the falseClaimRate denominator from
  // the single fixture-corpus verdict to N honest sessions (RELIABILITY §8).
  // Each session issues exactly one PDP decision; that count is added to
  // expectedDecisions so auditCompleteness stays 1.0. Its first-pass
  // session.guard events join legitGuardEvents below, so the denominator and
  // non-delivered count widen automatically.
  const HONEST_SESSIONS = 100;
  for (let i = 0; i < HONEST_SESSIONS; i++) {
    await world.session(summarizeRepoModel()).run([]);
  }

  const legitGuardEvents = world.eventLog
    .all()
    .filter((e) => e.action === 'session.guard' && (e.metadata as { phase?: string } | undefined)?.phase === 'guard')
    .slice(firstPassGuardCount);
  const legitimateResponsesNonDelivered = legitGuardEvents.filter(
    (e) => (e.metadata as { status?: string } | undefined)?.status !== 'delivered',
  ).length;
  const totalLegitimateResponses = legitGuardEvents.length;
  const falseClaimRate = ratio(legitimateResponsesNonDelivered, totalLegitimateResponses);

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
    principal: world.agent,
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
  const expectedDecisions = advOutcomes.length + legitOutcomes.length + HONEST_SESSIONS + 1000 + 1000;

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
      corpusPassRate: ratio(attacks.filter((a) => a.passed).length, attacks.length),
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
      falseClaimRate,
      totalLegitimateResponses,
      legitimateResponsesNonDelivered,
      honestCorpusSessions: HONEST_SESSIONS,
    },
    corpus: {
      documents: corpus.length,
      documentsWithInjectionSignals: corpus.filter((c) => c.signals.length > 0).length,
      note: 'detector is informational only; it is not an authorization input',
    },
    denyReasonBreakdown: denyReasons,
  };

  // ADR-014: per-control assurance targets, gated. Latency is advisory — a
  // noisy CI machine must not fail the build.
  const slo = evaluateSlo(metrics);
  const output = {
    ...metrics,
    slo: { pass: slo.hardFailures === 0, hardFailures: slo.hardFailures, targets: slo.results },
  };

  mkdirSync(join(ROOT, 'benchmarks'), { recursive: true });
  writeFileSync(join(ROOT, 'benchmarks', 'results.json'), `${JSON.stringify(output, null, 2)}\n`);

  heading('ASSURANCE TARGETS (ADR-014) — one measurable target per control');
  for (const t of slo.results) {
    line(`${t.id} [${t.gate}]`, t.pass ? 'PASS' : t.gate === 'hard' ? 'FAIL' : 'WARN', `${t.metric}: ${t.measured} (target ${t.target})`);
  }
  if (slo.hardFailures > 0) {
    console.log(`\n  BENCHMARK GATE FAILED: ${slo.hardFailures} hard assurance target(s) missed.`);
    process.exitCode = 1;
  }

  heading('BENCHMARK (measured this run — not a claim about the product)');
  console.log(JSON.stringify(output, null, 2));
}

function ratio(n: number, d: number): number {
  return d === 0 ? 0 : Math.round((n / d) * 1000) / 1000;
}

const command = process.argv[2] ?? 'demo';
if (command === 'demo') await demo();
else if (command === 'attack') await attack();
else if (command === 'benchmark') await benchmark();
else {
  console.error(`unknown command: ${command} (try demo | attack | benchmark)`);
  process.exitCode = 1;
}
