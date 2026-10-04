/** H8 hypothesis check (scratch, not a test): does the probe have real gaps to close? */
import { testWorld, mockAuth } from '../../src/testing.ts';
import { TENANT_A, TENANT_B, AUDIT_POLICY_RULE } from '../../src/scenario.ts';
import { sealFor, keyIdForTenant } from '../../src/seal.ts';
import { authorizationRoot } from '../../src/pdp.ts';
import { CapabilityRequestService } from '../../src/capability-request.ts';
import type { Principal } from '../../src/domain.ts';
import type { PolicyRule } from '../../src/policy.ts';

const EVIDENCE_RULE: PolicyRule = {
  id: 'allow-auditor-evidence-decrypt',
  effect: 'allow',
  principals: { roles: ['auditor'] },
  actions: ['evidence.decrypt'],
  resources: { types: ['system'] },
};

const world = testWorld({ policies: [AUDIT_POLICY_RULE, EVIDENCE_RULE] });

const auditor: Principal = {
  id: 'user:auditor',
  kind: 'user',
  tenantId: TENANT_A,
  roles: ['auditor'],
  attributes: {},
  auth: mockAuth({ subject: 'user:auditor' }),
};

world.authorization.issue(world.root, {
  subject: auditor.id,
  tenantId: TENANT_A,
  resourceIds: [keyIdForTenant(TENANT_B, 'confidential')],
  actions: ['evidence.decrypt'],
  maxClassification: 'confidential',
  expiresAt: Date.now() + 3_600_000,
  provenance: { source: 'policy-grant' },
});

const sealed = sealFor(TENANT_B, 'GLOBEX-SECRET', 'confidential');
const eventB = world.eventLog.append({
  tenantId: TENANT_B,
  principal: 'agent:globex',
  actor: 'agent:globex',
  actorKind: 'agent',
  action: 'write',
  resourceId: 'doc:globex-strategy',
  result: 'success',
  metadata: { sealed },
});

console.log('--- revealEvidence cross-tenant ---');
console.log('decrypted:', world.authorization.revealEvidence(auditor, eventB));
console.log('registry key bound to:', world.registry.get(sealed.keyId)?.tenantId);

console.log('--- CapabilityRequestService cross-tenant review ---');
const requests = new CapabilityRequestService(world.eventLog, world.authorization, world.root);
const bAgent: Principal = {
  id: 'agent:globex', kind: 'agent', tenantId: TENANT_B, roles: [], attributes: {},
  auth: mockAuth({ subject: 'agent:globex' }),
};
const bReq = requests.submit(bAgent, 'sess-b', ['doc:globex-strategy'], ['read'], 'internal', 'b request');
try {
  const r = requests.approve(bReq.id, world.user);
  console.log('approve by A reviewer SUCCEEDED:', r.request.status, r.request.tenantId);
} catch (e) {
  console.log('approve by A reviewer threw:', (e as Error).message);
}
const aReq = requests.submit(world.agent, 'sess-a', ['doc:acme-merger'], ['read'], 'internal', 'a request');
try {
  const r = requests.approve(aReq.id, bAgent);
  console.log('approve A request by B agent reviewer:', r.request.status, '(should have thrown: kind)');
} catch (e) {
  console.log('approve by B agent threw (expected kind check):', (e as Error).message);
}
const bob: Principal = { id: 'user:bob', kind: 'user', tenantId: TENANT_B, roles: [], attributes: {}, auth: mockAuth({ subject: 'user:bob' }) };
try {
  const r = requests.approve(aReq.id, bob);
  console.log('approve A request by B user reviewer SUCCEEDED:', r.request.status, r.request.tenantId);
} catch (e) {
  console.log('approve A request by B user threw:', (e as Error).message);
}

console.log('--- incident global view ---');
world.eventLog.append({ tenantId: '', principal: 'operator', actor: 'operator', actorKind: 'user', action: 'incident.freeze', resourceId: 'global', result: 'success', metadata: { phase: 'probe' } });
world.eventLog.append({ tenantId: TENANT_B, principal: 'agent:globex', actor: 'agent:globex', actorKind: 'agent', action: 'read', resourceId: 'doc:globex-strategy', result: 'success', metadata: { marker: 'GLOBEX-MARKER' } });
world.authorization.issue(world.root, {
  subject: auditor.id, tenantId: TENANT_A, resourceIds: [`audit-log:${TENANT_A}`], actions: ['query.audit'],
  maxClassification: 'internal', expiresAt: Date.now() + 3_600_000, provenance: { source: 'policy-grant' },
});
const last = world.eventLog.all().at(-1)!.seq;
const report = world.incident.reconstruct({ principal: auditor, tenantId: '*', fromSeq: 0, toSeq: last });
console.log('global report:', JSON.stringify({ events: report.events, actors: report.actors, actions: report.actions }));
