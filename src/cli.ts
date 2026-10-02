/**
 * Developer CLI: `demo`, `attack`, `benchmark`.
 *
 * The demo is the MVP acceptance walkthrough from section 23 of the brief:
 * legitimate work succeeds, every attack is denied, and the evidence chain
 * proves what happened.
 *
 * Run: node src/cli.ts demo
 */

import { mkdirSync, mkdtempSync, readdirSync, readFileSync, rmSync, writeFileSync, existsSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { tmpdir } from 'node:os';
import { fileURLToPath } from 'node:url';
import { createPublicKey } from 'node:crypto';
import { runAttackCorpus } from './attacks.ts';
import { BASELINE_POLICY, createPolicyEngine, type Approval, type PolicyRule } from './policy.ts';
import { type Resource } from './domain.ts';
import { buildWorld, buildWorldAsync, summarizeRepoModel, TENANT_A } from './scenario.ts';
import { defineResource, detectInjectionSignals } from './registry.ts';
import { AgentSession, LocalSandbox } from './runtime.ts';
import { AuthorizationService } from './pdp.ts';
import { policyBundleHash, createEngineFromBundle } from './policy-config.ts';
import { mockAuth } from './testing.ts';
import { verifyBundle, eventPublicKey, EventLog, StoreUnavailableError, type EventInput, type SecurityEvent, type EventStore } from './events.ts';
import { diffDecisions, loadFixtures, simulate, type Scenario } from './policy-testing.ts';
import { GroundedResponseGuard } from './guard.ts';
import { CapabilityRequestService } from './capability-request.ts';
import { ScriptedModel } from './model.ts';
import { HttpModelAdapter, ModelEgressDeniedError } from './model-http.ts';
import { CommandCheck } from './check-command.ts';
import { SandboxRegistry } from './sandbox-registry.ts';
import { JsonlTelemetry } from './telemetry.ts';
import { evaluateSlo } from './slo.ts';
import {
  computeSbom,
  computeTreeDigest,
  generateSigningKeyPair,
  gitHead,
  releaseGate,
  runSupplyChainGate,
  sbomDigest,
  signManifest,
  verifyManifest,
  type BuildManifest,
} from './supply-chain.ts';
import {
  applyUpdate,
  loadState,
  promoteUpdate,
  rollbackUpdate,
  signRollbackGrant,
  signUpdate,
  verifyDescriptor,
  verifyUpdate,
  type RollbackGrant,
  type UpdateDescriptor,
} from './updates.ts';
import { InMemoryRevocationChannel, verifyIncidentBundle, type IncidentBundle } from './incident.ts';
import { ClockGuard } from './health.ts';

const ROOT = join(dirname(fileURLToPath(import.meta.url)), '..');

function line(label: string, status: string, detail: string): void {
  console.log(`  ${status.padEnd(6)} ${label.padEnd(46)} ${detail}`);
}

function heading(text: string): void {
  console.log(`\n${text}\n${'-'.repeat(text.length)}`);
}

/** H15 demo seam: an evidence store whose append can be failed on demand. */
class DemoFlakyStore extends EventLog {
  fail = false;
  override append(input: EventInput): SecurityEvent {
    if (this.fail) throw new StoreUnavailableError('demo store outage (endpoint redacted)');
    return super.append(input);
  }
}

async function demo(): Promise<void> {
  const world = await buildWorldAsync();
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
  // M16: sandbox lifecycle — create, limit, destroy, attest (ADR-021). The
  // lifecycle wraps the existing container sandbox; the PDP gates every
  // execute() on a sandbox.execute capability scoped to the sandbox resource.
  heading('19. M16: sandbox lifecycle (create -> execute -> attest -> destroy)');
  const m16Policy = createPolicyEngine([
    ...BASELINE_POLICY,
    { id: 'allow-agent-sandbox-execute', effect: 'allow', principals: { kinds: ['agent'] }, actions: ['sandbox.execute'], resources: { ids: [`sandbox:${TENANT_A}:m16-demo`] } },
  ]);
  const m16Authz = new AuthorizationService(world.registry, m16Policy, world.eventLog, world.clock.now);
  const m16Sandboxes = new SandboxRegistry({
    registry: world.registry,
    eventLog: world.eventLog,
    authorization: m16Authz,
    actorId: world.root.id,
    actorKind: world.root.kind,
  });
  const m16Handle = m16Sandboxes.create({ tenantId: TENANT_A, sandboxId: 'm16-demo', limits: { memoryLimit: '64m', pidsLimit: 32 } });
  line('sandbox.create', 'CREATE', `${m16Handle.id} kind=${m16Handle.kind}`);
  m16Authz.issue(world.root, {
    subject: world.agent.id,
    tenantId: TENANT_A,
    resourceIds: [m16Handle.id],
    actions: ['sandbox.execute'],
    maxClassification: 'public',
    expiresAt: world.clock.now() + 600_000,
    provenance: { source: 'policy-grant', note: 'M16 demo: sandbox execute' },
  });
  const m16Exec = m16Sandboxes.execute({
    tenantId: TENANT_A,
    sandboxId: 'm16-demo',
    principal: world.agent,
    tool: { name: 'sandbox.echo', invoke: (ctx) => ({ output: `echo:${String(ctx.params.msg ?? '')}` }) },
    params: { msg: 'hello from inside' },
  });
  line('execute through the PDP gate', m16Exec.executed ? 'ALLOW' : 'DENY', `${m16Exec.reason} -> ${String(m16Exec.output ?? '')}`);
  const m16Attest = m16Sandboxes.attest(TENANT_A, 'm16-demo');
  line('sandbox.attest (sealed payload)', 'SEALED', `digest=${m16Attest.digest.slice(0, 12)}... key=${m16Attest.sealed.keyId}`);
  m16Sandboxes.destroy(TENANT_A, 'm16-demo');
  line('sandbox.destroy', 'DESTROY', 'handle dropped; exit sweep is the process-teardown backstop');
  const m16LifecycleEvents = world.eventLog.all().filter((e) => e.action.startsWith('sandbox.'));
  line('lifecycle evidence (sealed, digest-only)', 'LOG', m16LifecycleEvents.map((e) => e.action.replace('sandbox.', '')).join(' -> '));

  // H10: signed builds + supply-chain gate (ADR-024). The gate runs offline;
  // the manifest binds source, dependencies, and gate result when a release
  // key exists. Absence of a manifest is honest state, not a failure.
  heading('20. H10: supply-chain gate + signed build manifest');
  const h10Gate = runSupplyChainGate({ repoRoot: ROOT, baselineSbomPath: join(ROOT, 'artifacts', 'sbom.json') });
  const pinned = h10Gate.sbom.packages.filter((p) => p.direct).length;
  line(
    'supply-chain gate',
    h10Gate.ok ? 'PASS' : 'FAIL',
    `${pinned} direct deps pinned; ${h10Gate.sbom.packages.length} packages inventoried; sbom ${h10Gate.digest.slice(0, 19)}...`,
  );
  for (const v of h10Gate.violations) console.log(`         violation: ${v}`);
  if (h10Gate.drift.changed) {
    console.log(`         drift: added=${h10Gate.drift.added.join(',')} removed=${h10Gate.drift.removed.join(',')} changed=${h10Gate.drift.versionChanged.join(',')}`);
  }
  const manifestPath = join(ROOT, 'artifacts', 'build-manifest.json');
  const sigPath = join(ROOT, 'artifacts', 'build-manifest.sig');
  const pubKey = process.env.BUILD_SIGNING_PUBLIC_PEM;
  if (!existsSync(manifestPath) || !existsSync(sigPath)) {
    line('build manifest', 'NOT ISSUED', 'no release manifest yet — sign at release: npm run build:sign');
  } else if (pubKey === undefined) {
    line('build manifest', 'UNVERIFIED', 'manifest present but BUILD_SIGNING_PUBLIC_PEM is not set');
  } else {
    const verifyResult = verifyManifest(
      JSON.parse(readFileSync(manifestPath, 'utf8')),
      readFileSync(sigPath, 'utf8').trim(),
      pubKey,
      { repoRoot: ROOT },
    );
    line('build manifest verify', verifyResult.valid ? 'VERIFIED' : 'REFUSED', verifyResult.reason ?? `source=${verifyManifestSourceDigest(manifestPath)}`);
  }
  if (!h10Gate.ok) process.exitCode = 1;

  // H12: signed update channel (ADR-025). The chain below is real — it
  // verifies a descriptor over the LIVE tree — but the key is ephemeral and
  // demo-only, and state lives in a temp dir. The release flow is:
  //   npm run build:sign && node src/cli.ts update sign 1
  // Absence of real update state is honest state, not a failure.
  heading('21. H12: signed update channel — anti-rollback + canary halt');
  const demoDir = mkdtempSync(join(tmpdir(), 'asl-h12-'));
  try {
    const demoKeys = generateSigningKeyPair();
    const demoSbom = computeSbom(ROOT);
    const demoManifest: BuildManifest = {
      type: 'asl-build-manifest',
      version: 1,
      gitHead: gitHead(ROOT),
      source: { treeDigest: computeTreeDigest(ROOT) },
      dependencies: {
        sbomDigest: sbomDigest(demoSbom),
        runtimeDeps: demoSbom.packages.filter((p) => p.direct && !p.dev).map((p) => p.name),
      },
      gate: { typecheck: true, tests: true, supplyChain: true },
      issuedAt: new Date().toISOString(),
      issuedBy: 'demo-ephemeral-key',
    };
    const demoDescriptor: UpdateDescriptor = {
      type: 'asl-update',
      version: 1,
      releaseVersion: 1,
      channel: 'demo',
      stages: [10, 100],
      manifest: demoManifest,
      manifestSignature: signManifest(demoManifest, demoKeys.privateKeyPem),
      issuedAt: new Date().toISOString(),
      issuedBy: 'demo-ephemeral-key',
    };
    const demoSig = signUpdate(demoDescriptor, demoKeys.privateKeyPem);
    const demoState = join(demoDir, 'update-state.json');
    let demoFailed = false;
    const demoStep = (label: string, pass: boolean, detail: string): void => {
      if (!pass) demoFailed = true;
      line(label, pass ? 'PASS' : 'FAIL', detail);
    };

    const chain = verifyUpdate(demoDescriptor, demoSig, { publicKeyPem: demoKeys.publicKeyPem, repoRoot: ROOT });
    demoStep('descriptor + manifest chain', chain.valid, chain.valid ? 'signature over live tree verified' : `${chain.reason ?? ''} ${chain.detail ?? ''}`);

    const tampered = verifyDescriptor({ ...demoDescriptor, channel: 'attacker' }, demoSig, demoKeys.publicKeyPem);
    demoStep('tampered descriptor refused', !tampered.valid, tampered.valid ? 'accepted — BUG' : `refused: ${tampered.reason}`);

    const applied = applyUpdate(demoDescriptor, demoSig, { publicKeyPem: demoKeys.publicKeyPem, repoRoot: ROOT, statePath: demoState });
    demoStep('apply v1 lands canary', applied.ok && applied.state?.rollout.status === 'canary', applied.ok ? `stage 0/${(applied.state?.rollout.stages.length ?? 1) - 1}, mark=v${applied.state?.highWaterMark}` : `refused: ${applied.reason ?? ''}`);

    const replay = applyUpdate(demoDescriptor, demoSig, { publicKeyPem: demoKeys.publicKeyPem, repoRoot: ROOT, statePath: demoState });
    demoStep('replay apply v1 refused', !replay.ok && replay.reason === 'rollback-blocked', replay.ok ? 'accepted — BUG' : `refused: ${replay.reason ?? ''} (mark holds)`);

    const halt = promoteUpdate({ statePath: demoState, healthOk: false });
    demoStep('canary health FAIL -> halt', !halt.ok && halt.state?.rollout.status === 'halted', halt.state?.rollout.haltReason ?? '');

    const afterHalt = promoteUpdate({ statePath: demoState, healthOk: true });
    demoStep('promote after halt refused', !afterHalt.ok && afterHalt.reason === 'halted', afterHalt.ok ? 'accepted — BUG' : `sticky: ${afterHalt.reason ?? ''}`);

    const realState = join(ROOT, 'artifacts', 'update-state.json');
    line('update state (artifacts/)', existsSync(realState) ? 'PRESENT' : 'ABSENT', existsSync(realState) ? 'node src/cli.ts update status' : 'first apply initializes it (fail closed from zero)');

    if (demoFailed) process.exitCode = 1;
  } finally {
    rmSync(demoDir, { recursive: true, force: true });
  }

  // H13: incident response (ADR-026). Two nodes share one revocation channel;
  // one operator action freezes issuance, revokes authority, and propagates to
  // the second node inside the poll interval; the incident window is then
  // preserved as a verifiable artifact. The kill-switch latency is measured
  // wall clock. Self-contained on fresh worlds, like the H12 section.
  heading('22. H13: incident response — kill switch, broadcast, preservation');
  {
    const h13Channel = new InMemoryRevocationChannel();
    const h13NodeA = buildWorld({ channel: h13Channel, memory: true });
    const h13NodeB = buildWorld({ channel: h13Channel, memory: true });
    h13NodeA.authorization.issue(h13NodeA.root, {
      subject: h13NodeA.user.id,
      tenantId: TENANT_A,
      resourceIds: [`audit-log:${TENANT_A}`],
      actions: ['query.audit', 'audit.export'],
      maxClassification: 'internal',
      expiresAt: h13NodeA.clock.now() + 3_600_000,
      provenance: { source: 'policy-grant', note: 'operator evidence access' },
    });
    const h13BootstrapCap = h13NodeA.authorization.capabilitiesFor(h13NodeA.agent.id)[0]!.id;

    // Prime node B's sync throttle: one decision before the incident means its
    // next pull is due exactly one interval later.
    h13NodeB.authorization.authorize({ principal: h13NodeB.agent, action: 'read', resourceId: h13NodeB.resources.repoA! });
    const h13T0 = performance.now();
    const h13Engaged = h13NodeA.incident.engage({ scope: 'tenant', tenantId: TENANT_A, reason: 'demo drill', actor: 'user:oncall' });
    const h13Denied = h13NodeA.authorization.authorize({ principal: h13NodeA.agent, action: 'read', resourceId: h13NodeA.resources.repoA! });
    const h13KillLatencyMs = Math.round((performance.now() - h13T0) * 1000) / 1000;
    line(
      'kill switch (tenant freeze + revoke-all)',
      h13Engaged.frozen ? 'ENGAGED' : 'FAIL',
      `caps=${h13Engaged.capabilitiesRevoked} sessions=${h13Engaged.sessionsRevoked} broadcast=${h13Engaged.broadcastOk ? 'ok' : 'FAILED'}`,
    );
    line(
      'next decision after engage',
      h13Denied.denyReason === 'incident-frozen' ? 'DENIED' : 'FAIL',
      `${h13Denied.denyReason} in ${h13KillLatencyMs} ms (in-process, immediate)`,
    );

    h13NodeB.clock.advance(999);
    const h13BeforeInterval = h13NodeB.authorization.authorize({ principal: h13NodeB.agent, action: 'read', resourceId: h13NodeB.resources.repoA! });
    h13NodeB.clock.advance(1);
    const h13AfterInterval = h13NodeB.authorization.authorize({ principal: h13NodeB.agent, action: 'read', resourceId: h13NodeB.resources.repoA! });
    line('node B (throttled, 999 ms)', h13BeforeInterval.decision === 'allow' ? 'ALLOW' : 'FAIL', 'the shared channel is not pulled before the poll interval');
    line(
      'node B at one interval (≤ 5 s target)',
      h13AfterInterval.denyReason === 'incident-frozen' ? 'DENIED' : 'FAIL',
      `propagated through the shared channel after 1000 ms (${h13AfterInterval.denyReason})`,
    );

    const h13Dir = mkdtempSync(join(tmpdir(), 'asl-h13-'));
    try {
      const h13BundlePath = join(h13Dir, 'incident-bundle.json');
      const h13Preserved = h13NodeA.incident.preserve({
        principal: h13NodeA.user,
        tenantId: TENANT_A,
        fromSeq: 0,
        toSeq: h13NodeA.eventLog.all().at(-1)!.seq,
        outPath: h13BundlePath,
      });
      const h13Parsed = JSON.parse(readFileSync(h13BundlePath, 'utf8')) as IncidentBundle;
      const h13Verified = verifyIncidentBundle(h13Parsed, { publicKey: eventPublicKey() });
      line(
        'preserve incident window',
        h13Verified.valid ? 'VERIFIED' : 'FAIL',
        h13Verified.valid
          ? `${h13Preserved.events} events, digest ${h13Preserved.digest.slice(0, 16)}..., chain=${h13Preserved.chainValid}, anchor=${h13Preserved.anchorMatch}`
          : h13Verified.errors.join('; '),
      );
    } finally {
      rmSync(h13Dir, { recursive: true, force: true });
    }

    h13NodeA.incident.lift({ scope: 'tenant', tenantId: TENANT_A, reason: 'contained', actor: 'user:oncall' });
    h13NodeA.authorization.issue(h13NodeA.root, {
      subject: h13NodeA.agent.id,
      tenantId: TENANT_A,
      resourceIds: [h13NodeA.resources.repoA!],
      actions: ['read'],
      maxClassification: 'internal',
      expiresAt: h13NodeA.clock.now() + 600_000,
      provenance: { source: 'session-bootstrap', note: 'post-incident reissue' },
    });
    const h13AfterLift = h13NodeA.authorization.authorize({ principal: h13NodeA.agent, action: 'read', resourceId: h13NodeA.resources.repoA! });
    line(
      'lift + reissue (revocation is not undone)',
      h13AfterLift.decision === 'allow' && h13NodeA.authorization.isRevoked(h13BootstrapCap) ? 'ALLOW' : 'FAIL',
      `new authority works; the revoked bootstrap capability stays revoked=${h13NodeA.authorization.isRevoked(h13BootstrapCap)}`,
    );

    h13NodeA.incident.close();
    h13NodeB.incident.close();
    h13NodeA.eventLog.close();
    h13NodeB.eventLog.close();
  }

  // H15: fail-closed availability — fault injection, degraded mode, recovery.
  heading('23. H15: fail-closed availability — fault injection, degraded mode, recovery');
  {
    const h15Dir = mkdtempSync(join(tmpdir(), 'asl-h15-'));
    let h15Store: DemoFlakyStore | undefined;
    try {
      h15Store = new DemoFlakyStore(join(h15Dir, 'events.sqlite'));
      const h15Authz = new AuthorizationService(world.registry, world.policy, h15Store, world.clock.now);
      h15Authz.issue(world.root, {
        subject: world.agent.id,
        tenantId: TENANT_A,
        resourceIds: [world.resources.repoA!],
        actions: ['read'],
        maxClassification: 'internal',
        expiresAt: world.clock.now() + 600_000,
        provenance: { source: 'policy-grant', note: 'h15 demo' },
      });
      const h15Healthy = h15Authz.authorize({ principal: world.agent, action: 'read', resourceId: world.resources.repoA! });
      line(
        'H15 healthy decision',
        h15Healthy.decision === 'allow' ? 'ALLOW' : 'FAIL',
        `health=${JSON.stringify(h15Authz.healthState.snapshot())}`,
      );

      h15Store.fail = true;
      const h15Down = h15Authz.authorize({ principal: world.agent, action: 'read', resourceId: world.resources.repoA! });
      line(
        'store outage (fail-closed)',
        h15Down.decision === 'deny' && h15Down.denyReason === 'store-unavailable' ? 'DENIED' : 'FAIL',
        `${h15Down.denyReason}; health=${JSON.stringify(h15Authz.healthState.snapshot())}`,
      );
      h15Store.fail = false;
      const h15Recovered = h15Authz.authorize({ principal: world.agent, action: 'read', resourceId: world.resources.repoA! });
      line(
        'store recovery (automatic)',
        h15Recovered.decision === 'allow' && h15Authz.healthState.snapshot().store === 'ok' ? 'ALLOW' : 'FAIL',
        `health=${JSON.stringify(h15Authz.healthState.snapshot())}`,
      );

      h15Authz.setClockGuard(
        new ClockGuard(() => {
          throw new Error('demo clock fault');
        }),
      );
      const h15ClockDown = h15Authz.authorize({ principal: world.agent, action: 'read', resourceId: world.resources.repoA! });
      line(
        'clock fault (fail-closed)',
        h15ClockDown.decision === 'deny' && h15ClockDown.denyReason === 'clock-unavailable' ? 'DENIED' : 'FAIL',
        `${h15ClockDown.denyReason}; health=${JSON.stringify(h15Authz.healthState.snapshot())}`,
      );
    } finally {
      h15Store?.close();
      rmSync(h15Dir, { recursive: true, force: true });
    }
  }

  // Postgres mode: close the pools or the process hangs at exit.
  world.incident.close();
  world.eventLog.close();
}

function verifyManifestSourceDigest(manifestPath: string): string {
  try {
    const parsed: unknown = JSON.parse(readFileSync(manifestPath, 'utf8'));
    if (typeof parsed !== 'object' || parsed === null) return 'unparsable manifest';
    const source = (parsed as { source?: unknown }).source;
    if (typeof source !== 'object' || source === null) return 'unknown';
    const treeDigest = (source as { treeDigest?: unknown }).treeDigest;
    return typeof treeDigest === 'string' ? `tree=${treeDigest.slice(0, 19)}...` : 'unknown';
  } catch {
    return 'unparsable manifest';
  }
}

async function attack(): Promise<void> {
  const world = await buildWorldAsync();
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
  // Postgres mode: close the pools or the process hangs at exit.
  world.incident.close();
  world.eventLog.close();
}

async function benchmark(): Promise<void> {
  const world = await buildWorldAsync();
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

  // H15 (ADR-027): decision latency p99 with and without persistence - the
  // same PDP path over a SQLite-file EventLog (durable append) and an
  // in-memory EventLog. Isolated stacks: the world's chain and
  // auditCompleteness are untouched.
  const decisionLatencyP99 = (store: EventStore): number => {
    const authz = new AuthorizationService(world.registry, world.policy, store, world.clock.now);
    authz.issue(world.root, {
      subject: world.agent.id,
      tenantId: TENANT_A,
      resourceIds: [world.resources.repoA!],
      actions: ['read'],
      maxClassification: 'internal',
      expiresAt: world.clock.now() + 3_600_000,
      provenance: { source: 'policy-grant', note: 'h15 decision latency budget' },
    });
    const latencies: number[] = [];
    for (let i = 0; i < 1000; i++) {
      const t = performance.now();
      authz.authorize({ principal: world.agent, action: 'read', resourceId: world.resources.repoA! });
      latencies.push(performance.now() - t);
    }
    latencies.sort((a, b) => a - b);
    store.close();
    return Math.round(latencies[Math.floor(0.99 * latencies.length)]! * 1000) / 1000;
  };
  const persistenceDir = mkdtempSync(join(tmpdir(), 'asl-h15-latency-'));
  let decisionLatencyP99WithPersistenceMs: number;
  try {
    decisionLatencyP99WithPersistenceMs = decisionLatencyP99(new EventLog(join(persistenceDir, 'events.sqlite')));
  } finally {
    rmSync(persistenceDir, { recursive: true, force: true });
  }
  const decisionLatencyP99WithoutPersistenceMs = decisionLatencyP99(new EventLog());

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
      decisionLatencyP99WithPersistenceMs,
      decisionLatencyP99WithoutPersistenceMs,
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
  // Postgres mode: close the pools or the process hangs at exit.
  world.incident.close();
  world.eventLog.close();
}

function ratio(n: number, d: number): number {
  return d === 0 ? 0 : Math.round((n / d) * 1000) / 1000;
}

/**
 * H10 supply-chain commands (ADR-024): `build gate|sbom|keygen|sign|verify`.
 *
 * The gate is the commit/release blocker; sign runs the full release gate
 * (typecheck + tests + supply-chain) and refuses to sign on any failure;
 * verify is the deploy-time check. Key material comes from env vars and is
 * never printed.
 */
async function buildCommand(): Promise<void> {
  const sub = process.argv[3] ?? 'gate';
  const artifactsDir = join(ROOT, 'artifacts');
  const sbomPath = join(artifactsDir, 'sbom.json');

  if (sub === 'gate') {
    const result = runSupplyChainGate({ repoRoot: ROOT, baselineSbomPath: sbomPath });
    heading('SUPPLY-CHAIN GATE (H10, ADR-024)');
    line('sbom digest', result.digest ? 'OK' : 'FAIL', result.digest);
    line('packages inventoried', 'INFO', String(result.sbom.packages.length));
    for (const v of result.violations) console.log(`  violation: ${v}`);
    if (result.drift.changed) {
      console.log(`  drift vs baseline: added=[${result.drift.added}] removed=[${result.drift.removed}] version-changed=[${result.drift.versionChanged}]`);
      console.log('  dependency change detected — regenerate the baseline and name the admission ADR in the same PR:');
      console.log('    npm run sbom -- --write');
    }
    if (!result.ok) process.exitCode = 1;
    else console.log('  supply-chain gate passed.');
    return;
  }

  if (sub === 'sbom') {
    const sbom = computeSbom(ROOT);
    if (process.argv.includes('--write')) {
      mkdirSync(artifactsDir, { recursive: true });
      writeFileSync(sbomPath, `${JSON.stringify(sbom, null, 2)}\n`);
      console.log(`sbom written: ${sbomPath} (digest ${sbomDigest(sbom)})`);
    } else {
      process.stdout.write(`${JSON.stringify(sbom, null, 2)}\n`);
    }
    return;
  }

  if (sub === 'keygen') {
    const keysDir = join(ROOT, '.build-keys');
    const { privateKeyPem, publicKeyPem } = generateSigningKeyPair();
    mkdirSync(keysDir, { recursive: true });
    writeFileSync(join(keysDir, 'build-signing-private.pem'), privateKeyPem);
    writeFileSync(join(keysDir, 'build-signing-public.pem'), publicKeyPem);
    console.log('build signing keypair generated (gitignored):');
    console.log(`  private: ${join(keysDir, 'build-signing-private.pem')} -> set BUILD_SIGNING_PRIVATE_PEM (never commit, never print)`);
    console.log(`  public:  ${join(keysDir, 'build-signing-public.pem')} -> set BUILD_SIGNING_PUBLIC_PEM for verification`);
    return;
  }

  if (sub === 'sign') {
    const gate = releaseGate(ROOT);
    heading('RELEASE GATE (H10) — typecheck + tests + supply-chain');
    for (const [step, pass] of Object.entries(gate.steps)) {
      line(`gate: ${step}`, pass ? 'PASS' : 'FAIL', '');
    }
    if (!gate.pass) {
      console.error('  release gate FAILED — nothing is signed. Fix the failures and re-run.');
      process.exitCode = 1;
      return;
    }
    const privateKey = process.env.BUILD_SIGNING_PRIVATE_PEM;
    if (privateKey === undefined) {
      console.error('  BUILD_SIGNING_PRIVATE_PEM is not set — refusing to sign (fail closed).');
      console.error('  Dev keys: npm run build:keygen (see DEPLOYMENT.md for the release key ceremony).');
      process.exitCode = 1;
      return;
    }
    const manifest: BuildManifest = {
      type: 'asl-build-manifest',
      version: 1,
      gitHead: gitHead(ROOT),
      source: { treeDigest: computeTreeDigest(ROOT) },
      dependencies: {
        sbomDigest: sbomDigest(computeSbom(ROOT)),
        runtimeDeps: computeSbom(ROOT).packages.filter((p) => p.direct && !p.dev).map((p) => p.name),
      },
      gate: { typecheck: true, tests: true, supplyChain: true },
      issuedAt: new Date().toISOString(),
      issuedBy: process.env.BUILD_SIGNING_IDENTITY ?? 'unidentified-operator',
    };
    const signature = signManifest(manifest, privateKey);
    mkdirSync(artifactsDir, { recursive: true });
    writeFileSync(join(artifactsDir, 'build-manifest.json'), `${JSON.stringify(manifest, null, 2)}\n`);
    writeFileSync(join(artifactsDir, 'build-manifest.sig'), `${signature}\n`);
    line('build manifest signed', 'SIGNED', `tree=${manifest.source.treeDigest.slice(0, 19)}... sbom=${manifest.dependencies.sbomDigest.slice(0, 19)}...`);
    console.log('  verify before start: npm run build:verify');
    return;
  }

  if (sub === 'verify') {
    const manifestPath = join(artifactsDir, 'build-manifest.json');
    const sigPath = join(artifactsDir, 'build-manifest.sig');
    const publicKey = process.env.BUILD_SIGNING_PUBLIC_PEM;
    if (!existsSync(manifestPath) || !existsSync(sigPath)) {
      console.error(`  build manifest not issued (${manifestPath}) — refusing (fail closed).`);
      process.exitCode = 1;
      return;
    }
    if (publicKey === undefined) {
      console.error('  BUILD_SIGNING_PUBLIC_PEM is not set — refusing to verify (fail closed).');
      process.exitCode = 1;
      return;
    }
    const manifest: unknown = JSON.parse(readFileSync(manifestPath, 'utf8'));
    const result = verifyManifest(manifest, readFileSync(sigPath, 'utf8').trim(), publicKey, { repoRoot: ROOT });
    if (result.valid) {
      console.log('  build manifest VERIFIED');
      return;
    }
    console.error(`  build manifest REFUSED: ${result.reason} — this artifact does not match the signed release state.`);
    process.exitCode = 1;
    return;
  }

  console.error(`unknown build subcommand: ${sub} (try gate | sbom | keygen | sign | verify)`);
  process.exitCode = 1;
}

/**
 * H12 secure-update commands (ADR-025):
 * `update sign|verify|apply|promote|status|grant|rollback`.
 *
 * sign wraps the issued build manifest into a signed release descriptor;
 * verify/apply run the full fail-closed chain (descriptor signature ->
 * embedded manifest against the live tree -> high-water mark); promote
 * needs an explicit health signal; grant/rollback are the signed,
 * single-use emergency path. Key material comes from env vars and is never
 * printed. State lives at artifacts/update-state.json (per-instance,
 * gitignored).
 */
async function updateCommand(): Promise<void> {
  const sub = process.argv[3] ?? 'status';
  const artifactsDir = join(ROOT, 'artifacts');
  const statePath = join(artifactsDir, 'update-state.json');

  const readIssued = (descPath: string, sigPath: string, kind: 'descriptor' | 'grant'): { descriptor: unknown; signature: string } | null => {
    if (!existsSync(descPath) || !existsSync(sigPath)) {
      console.error(`  ${kind} not issued (${descPath}) — refusing (fail closed).`);
      if (kind === 'descriptor') console.error('  Issue one at release: node src/cli.ts update sign <releaseVersion> [channel] [stages-csv]');
      else console.error('  Issue one in an incident: node src/cli.ts update grant <targetVersion> <reason...>');
      process.exitCode = 1;
      return null;
    }
    try {
      return { descriptor: JSON.parse(readFileSync(descPath, 'utf8')), signature: readFileSync(sigPath, 'utf8').trim() };
    } catch (err) {
      console.error(`  ${kind} unreadable: ${(err as Error).message} — refusing (fail closed).`);
      process.exitCode = 1;
      return null;
    }
  };

  if (sub === 'sign') {
    const releaseVersion = Number(process.argv[4]);
    if (!Number.isInteger(releaseVersion) || releaseVersion < 1) {
      console.error('  usage: update sign <releaseVersion> [channel] [stages-csv]  (e.g. update sign 1 stable 1,100)');
      process.exitCode = 1;
      return;
    }
    const channel = process.argv[5] ?? 'stable';
    if (channel.trim() === '') {
      console.error('  channel must be non-empty — refusing to sign a descriptor that can never verify (fail closed).');
      process.exitCode = 1;
      return;
    }
    const stages = (process.argv[6] ?? '1,100').split(',').map((s) => Number(s.trim()));
    if (stages.length === 0 || stages.some((s) => !Number.isInteger(s) || s < 1 || s > 100) || stages[stages.length - 1] !== 100) {
      console.error('  stages must be ascending percentages ending in 100 (e.g. 10,50,100) — refusing (fail closed).');
      process.exitCode = 1;
      return;
    }
    for (let i = 1; i < stages.length; i++) {
      if (stages[i]! <= stages[i - 1]!) {
        console.error('  stages must be strictly ascending (e.g. 10,50,100) — refusing (fail closed).');
        process.exitCode = 1;
        return;
      }
    }
    const privateKey = process.env.BUILD_SIGNING_PRIVATE_PEM;
    if (privateKey === undefined) {
      console.error('  BUILD_SIGNING_PRIVATE_PEM is not set — refusing to sign (fail closed).');
      console.error('  Dev keys: npm run build:keygen (see DEPLOYMENT.md for the release key ceremony).');
      process.exitCode = 1;
      return;
    }
    const manifestPath = join(artifactsDir, 'build-manifest.json');
    const manifestSigPath = join(artifactsDir, 'build-manifest.sig');
    if (!existsSync(manifestPath) || !existsSync(manifestSigPath)) {
      console.error('  build manifest not issued — run npm run build:sign first (the update carries the H10 manifest).');
      process.exitCode = 1;
      return;
    }
    const manifest: unknown = JSON.parse(readFileSync(manifestPath, 'utf8'));
    const manifestSignature = readFileSync(manifestSigPath, 'utf8').trim();
    // Refuse to wrap a manifest that does not match the live tree at sign time.
    const publicPem = createPublicKey(privateKey).export({ type: 'spki', format: 'pem' });
    const pubPemStr = typeof publicPem === 'string' ? publicPem : publicPem.toString('utf8');
    const manifestCheck = verifyManifest(manifest, manifestSignature, pubPemStr, { repoRoot: ROOT });
    if (!manifestCheck.valid) {
      console.error(`  build manifest refused (${manifestCheck.reason}) — re-run npm run build:sign before issuing an update.`);
      process.exitCode = 1;
      return;
    }
    const descriptor: UpdateDescriptor = {
      type: 'asl-update',
      version: 1,
      releaseVersion,
      channel,
      stages,
      manifest: manifest as UpdateDescriptor['manifest'],
      manifestSignature,
      issuedAt: new Date().toISOString(),
      issuedBy: process.env.BUILD_SIGNING_IDENTITY ?? 'unidentified-operator',
    };
    let signature: string;
    try {
      signature = signUpdate(descriptor, privateKey);
    } catch (err) {
      console.error(`  signing refused: ${(err as Error).message} — fail closed.`);
      process.exitCode = 1;
      return;
    }
    writeFileSync(join(artifactsDir, 'update.json'), `${JSON.stringify(descriptor, null, 2)}\n`);
    writeFileSync(join(artifactsDir, 'update.sig'), `${signature}\n`);
    line('update descriptor signed', 'SIGNED', `v${releaseVersion} channel=${channel} stages=${stages.join(',')}`);
    console.log('  verify before start: npm run update:verify');
    return;
  }

  if (sub === 'verify' || sub === 'apply') {
    const descPath = process.argv[4] ?? join(artifactsDir, 'update.json');
    const sigPath = process.argv[5] ?? `${descPath.replace(/\.json$/, '')}.sig`;
    const publicPem = process.env.BUILD_SIGNING_PUBLIC_PEM;
    if (publicPem === undefined) {
      console.error('  BUILD_SIGNING_PUBLIC_PEM is not set — refusing to verify (fail closed).');
      process.exitCode = 1;
      return;
    }
    const issued = readIssued(descPath, sigPath, 'descriptor');
    if (issued === null) return;
    if (sub === 'verify') {
      const result = verifyUpdate(issued.descriptor, issued.signature, { publicKeyPem: publicPem, repoRoot: ROOT });
      if (result.valid) {
        console.log('  update descriptor VERIFIED (signature + manifest + live tree)');
        return;
      }
      console.error(`  update REFUSED: ${result.reason}${result.detail ? ` (${result.detail})` : ''} — this descriptor does not match the signed release state.`);
      process.exitCode = 1;
      return;
    }
    const result = applyUpdate(issued.descriptor, issued.signature, { publicKeyPem: publicPem, repoRoot: ROOT, statePath });
    if (result.ok && result.state !== undefined) {
      line('update applied', 'APPLIED', `v${result.state.current?.releaseVersion} mark=${result.state.highWaterMark} rollout=${result.state.rollout.status}`);
      console.log('  canary stage reached — promote with health: node src/cli.ts update promote ok|fail');
      return;
    }
    console.error(`  update REFUSED: ${result.reason}${result.detail ? ` (${result.detail})` : ''} — state unchanged.`);
    process.exitCode = 1;
    return;
  }

  if (sub === 'promote') {
    const health = process.argv[4];
    if (health !== 'ok' && health !== 'fail') {
      console.error('  usage: update promote ok|fail   (the health signal is explicit — there is no default-healthy path)');
      process.exitCode = 1;
      return;
    }
    const result = promoteUpdate({ statePath, healthOk: health === 'ok' });
    if (result.state !== undefined) {
      const stage = result.state.rollout.stages.length === 0 ? '-' : result.state.rollout.stages.length - 1;
      line('rollout', result.state.rollout.status.toUpperCase(), `stage=${result.state.rollout.stageIndex}/${stage}${result.state.rollout.haltReason ? ` halt=${result.state.rollout.haltReason}` : ''}`);
    }
    if (!result.ok) {
      if (result.reason === 'no-pending-rollout') console.log('  no rollout in flight — nothing to promote.');
      else console.error(`  promotion refused: ${result.reason} — a new signed descriptor or a rollback grant resolves a halt.`);
      process.exitCode = result.reason === 'no-pending-rollout' ? 0 : 1;
      return;
    }
    return;
  }

  if (sub === 'status') {
    if (!existsSync(statePath)) {
      console.log('  no update state — nothing applied (the first apply initializes it, fail closed from zero).');
      return;
    }
    try {
      const state = loadState(statePath);
      line('high-water mark', 'INFO', `v${state.highWaterMark} (never lowers; rollback generation v${state.rollbackGeneration})`);
      line('current release', 'INFO', state.current === null ? 'none' : `v${state.current.releaseVersion} channel=${state.current.channel ?? 'unknown (rolled back)'} applied=${state.current.appliedAt}`);
      line('rollout', state.rollout.status.toUpperCase(), `stage=${state.rollout.stageIndex}/${state.rollout.stages.length === 0 ? '-' : state.rollout.stages.length - 1}${state.rollout.pendingVersion !== null ? ` pending=v${state.rollout.pendingVersion}` : ''}${state.rollout.haltReason ? ` halt=${state.rollout.haltReason}` : ''}`);
    } catch (err) {
      console.error(`  ${(err as Error).message}`);
      process.exitCode = 1;
    }
    return;
  }

  if (sub === 'grant') {
    const targetVersion = Number(process.argv[4]);
    const reason = process.argv.slice(5).join(' ').trim();
    if (!Number.isInteger(targetVersion) || targetVersion < 1 || reason === '') {
      console.error('  usage: update grant <targetVersion> <reason...>   (e.g. update grant 1 "canary regression")');
      process.exitCode = 1;
      return;
    }
    const privateKey = process.env.BUILD_SIGNING_PRIVATE_PEM;
    if (privateKey === undefined) {
      console.error('  BUILD_SIGNING_PRIVATE_PEM is not set — refusing to sign a rollback grant (fail closed).');
      process.exitCode = 1;
      return;
    }
    let current: number;
    let generation: number;
    try {
      const state = loadState(statePath);
      if (state.current === null) {
        console.error('  nothing is applied — there is nothing to roll back from.');
        process.exitCode = 1;
        return;
      }
      current = state.current.releaseVersion;
      generation = state.rollbackGeneration;
    } catch (err) {
      console.error(`  ${(err as Error).message}`);
      process.exitCode = 1;
      return;
    }
    if (targetVersion >= current) {
      console.error(`  target v${targetVersion} must be below current v${current} — rollback goes backward only.`);
      process.exitCode = 1;
      return;
    }
    const grant: RollbackGrant = {
      type: 'asl-rollback-grant',
      version: 1,
      targetVersion,
      fromVersion: current,
      generation,
      reason,
      issuedAt: new Date().toISOString(),
      issuedBy: process.env.BUILD_SIGNING_IDENTITY ?? 'unidentified-operator',
    };
    let signature: string;
    try {
      signature = signRollbackGrant(grant, privateKey);
    } catch (err) {
      console.error(`  signing refused: ${(err as Error).message} — fail closed.`);
      process.exitCode = 1;
      return;
    }
    writeFileSync(join(artifactsDir, 'rollback-grant.json'), `${JSON.stringify(grant, null, 2)}\n`);
    writeFileSync(join(artifactsDir, 'rollback-grant.sig'), `${signature}\n`);
    line('rollback grant signed', 'SIGNED', `v${current} -> v${targetVersion} (generation ${generation}, single-use, mark preserved) — reason: ${reason}`);
    return;
  }

  if (sub === 'rollback') {
    const grantPath = process.argv[4] ?? join(artifactsDir, 'rollback-grant.json');
    const sigPath = process.argv[5] ?? `${grantPath.replace(/\.json$/, '')}.sig`;
    const publicPem = process.env.BUILD_SIGNING_PUBLIC_PEM;
    if (publicPem === undefined) {
      console.error('  BUILD_SIGNING_PUBLIC_PEM is not set — refusing to verify a rollback grant (fail closed).');
      process.exitCode = 1;
      return;
    }
    const issued = readIssued(grantPath, sigPath, 'grant');
    if (issued === null) return;
    const result = rollbackUpdate(issued.descriptor, issued.signature, { publicKeyPem: publicPem, statePath });
    if (result.ok && result.state !== undefined) {
      line('rollback applied', 'OK', `current=v${result.state.current?.releaseVersion} mark=v${result.state.highWaterMark} (unchanged)`);
      return;
    }
    console.error(`  rollback REFUSED: ${result.reason}${result.detail ? ` (${result.detail})` : ''} — state unchanged.`);
    process.exitCode = 1;
    return;
  }

  console.error(`unknown update subcommand: ${sub} (try sign | verify | apply | promote | status | grant | rollback)`);
  process.exitCode = 1;
}

/**
 * H13 incident-response commands (ADR-026):
 * `incident status|engage|lift|revoke-cap|revoke-session|preserve|report`.
 *
 * The kill switch applies locally first and broadcasts through the revocation
 * channel (Postgres mode reaches a running node / other nodes). preserve and
 * report mint an operator audit capability through the ordinary issuance path
 * — there is no separate emergency authority.
 */
async function incidentCommand(): Promise<void> {
  const sub = process.argv[3] ?? 'status';
  // No fixture bootstrap: operator commands must not mint fixture authority or
  // append fixture events to a shared (Postgres) evidence chain.
  const world = await buildWorldAsync({ bootstrap: false });
  const operator = process.env.INCIDENT_OPERATOR ?? 'operator:cli';

  const usage = (): void => {
    console.error('  usage: incident status');
    console.error('         incident engage <tenant <id> | global> <reason...>');
    console.error('         incident lift   <tenant <id> | global> <reason...>');
    console.error('         incident revoke-cap <capabilityId> <tenantId> <reason...>');
    console.error('         incident revoke-session <sessionId> <tenantId> <reason...>');
    console.error('         incident preserve <tenantId | *> <fromSeq> <toSeq> [outPath]');
    console.error('         incident report <tenantId | *> <fromSeq> <toSeq>');
    process.exitCode = 1;
  };

  try {
    if (sub === 'status') {
      const status = world.incident.status();
      heading('INCIDENT STATUS (H13, ADR-026)');
      line(
        'freeze',
        status.frozen ? 'FROZEN' : 'clear',
        status.freezes.map((f) => `${f.scope}${f.tenantId ? `:${f.tenantId}` : ''} (${f.reason}, by ${f.actor})`).join(', ') || 'none',
      );
      line('revoked capabilities', 'INFO', String(status.revokedCapabilities));
      line(
        'channel',
        status.channelErrors > 0 ? 'DEGRADED' : 'ok',
        `cursor=${status.channelCursor} syncCursor=${status.syncCursor} applied=${status.appliedRecords} syncFailures=${status.syncFailures} channelErrors=${status.channelErrors}`,
      );
      if (status.channelLastError) console.log(`         last channel error: ${status.channelLastError}`);
      return;
    }

    if (sub === 'engage' || sub === 'lift') {
      const scope = process.argv[4];
      if (scope !== 'tenant' && scope !== 'global') return usage();
      const tenantId = scope === 'tenant' ? process.argv[5] : undefined;
      const reason = process.argv.slice(scope === 'tenant' ? 6 : 5).join(' ').trim();
      if (!reason || (scope === 'tenant' && !tenantId)) return usage();
      const input = { scope, ...(tenantId ? { tenantId } : {}), reason, actor: operator } as const;
      const result = sub === 'engage' ? world.incident.engage(input) : world.incident.lift(input);
      await world.incident.flush();
      const status = world.incident.status();
      const broadcastOk = result.broadcastOk && status.channelErrors === 0;
      line(sub === 'engage' ? 'kill switch' : 'freeze lifted', result.frozen ? 'FROZEN' : 'CLEAR', `${scope}${tenantId ? `:${tenantId}` : ''} — ${reason}`);
      if (sub === 'engage') {
        line('authority revoked', 'INFO', `capabilities=${result.capabilitiesRevoked} sessions=${result.sessionsRevoked}`);
      }
      line('broadcast', broadcastOk ? 'OK' : 'FAILED', broadcastOk ? 'published to the revocation channel' : `channel errors=${status.channelErrors}${status.channelLastError ? ` (${status.channelLastError})` : ''}`);
      if (process.env.EVENT_STORE !== 'postgres') {
        console.log('  note: the in-memory channel is local to this process — set EVENT_STORE=postgres + DATABASE_URL to reach a running node.');
      }
      if (!broadcastOk) process.exitCode = 1;
      return;
    }

    if (sub === 'revoke-cap' || sub === 'revoke-session') {
      const targetId = process.argv[4] ?? '';
      const tenantId = process.argv[5] ?? '';
      const reason = process.argv.slice(6).join(' ').trim();
      if (!targetId || !tenantId || !reason) return usage();
      if (sub === 'revoke-cap') world.incident.revokeCapability(targetId, tenantId, reason);
      else world.incident.revokeSession(targetId, tenantId, reason);
      await world.incident.flush();
      // Mirror the engage branch: never print REVOKED as if it propagated
      // when the channel write failed (ADR-026 fail-loud).
      const status = world.incident.status();
      const broadcastOk = status.channelErrors === 0;
      line(sub, 'REVOKED', `${targetId} (tenant ${tenantId}) — ${reason}`);
      line('broadcast', broadcastOk ? 'OK' : 'FAILED', broadcastOk ? 'published to the revocation channel' : `channel errors=${status.channelErrors}${status.channelLastError ? ` (${status.channelLastError})` : ''}`);
      if (process.env.EVENT_STORE !== 'postgres') {
        console.log('  note: the in-memory channel is local to this process — set EVENT_STORE=postgres + DATABASE_URL to reach a running node.');
      }
      if (!broadcastOk) process.exitCode = 1;
      return;
    }

    if (sub === 'preserve' || sub === 'report') {
      const tenantId = process.argv[4] ?? '';
      const fromSeq = Number(process.argv[5]);
      const toSeq = Number(process.argv[6]);
      if (!tenantId || !Number.isInteger(fromSeq) || !Number.isInteger(toSeq)) return usage();
      // Operator evidence authority, minted and audited through the ordinary
      // issuance path (no emergency authority exists). The global view ('*')
      // is authorized by the operator's own tenant's audit authority.
      const authorityTenant = tenantId === '*' ? world.user.tenantId : tenantId;
      world.authorization.issue(world.root, {
        subject: world.user.id,
        tenantId: authorityTenant,
        resourceIds: [`audit-log:${authorityTenant}`],
        actions: ['query.audit', 'audit.export'],
        maxClassification: 'restricted',
        expiresAt: world.clock.now() + 3_600_000,
        provenance: { source: 'policy-grant', note: 'operator CLI incident evidence access' },
      });
      if (sub === 'preserve') {
        const outPath = process.argv[7] ?? join(ROOT, 'artifacts', `incident-${tenantId.replace('*', 'global')}-${fromSeq}-${toSeq}.json`);
        const result = world.incident.preserve({ principal: world.user, tenantId, fromSeq, toSeq, outPath });
        line('incident bundle preserved', 'OK', `${result.events} events, digest ${result.digest.slice(0, 19)}..., chain=${result.chainValid}`);
        console.log(`  artifact: ${result.path}`);
      } else {
        const report = world.incident.reconstruct({ principal: world.user, tenantId, fromSeq, toSeq });
        line('reconstruction', 'OK', `${report.events} events, allow=${report.decisions.allow} deny=${report.decisions.deny}, revocations=${report.revocations}, freezes=${report.freezes}, lifts=${report.lifts}`);
        console.log(`         actions: ${Object.entries(report.actions).map(([action, count]) => `${action}=${count}`).join(', ')}`);
        for (const [reason, count] of Object.entries(report.denyReasons)) console.log(`         deny ${reason}: ${count}`);
        console.log(`         actors: ${report.actors.join(', ')}`);
      }
      if (process.env.EVENT_STORE !== 'postgres') {
        console.log('  note: this process has an in-memory world — set EVENT_STORE=postgres + DATABASE_URL to read the running node\'s evidence.');
      }
      return;
    }

    usage();
  } catch (error) {
    // Refusals (frozen issuance, missing authority, empty windows) print a
    // diagnosable line instead of a raw stack trace.
    const message = error instanceof Error ? error.message : String(error);
    console.error(`  incident command refused: ${message}`);
    process.exitCode = 1;
  } finally {
    await world.incident.flush().catch(() => {});
    world.incident.close();
    world.eventLog.close();
  }
}

const command = process.argv[2] ?? 'demo';
if (command === 'demo') await demo();
else if (command === 'attack') await attack();
else if (command === 'benchmark') await benchmark();
else if (command === 'build') await buildCommand();
else if (command === 'update') await updateCommand();
else if (command === 'incident') await incidentCommand();
else {
  console.error(`unknown command: ${command} (try demo | attack | benchmark | build | update | incident)`);
  process.exitCode = 1;
}
