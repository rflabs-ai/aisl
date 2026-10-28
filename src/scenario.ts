/**
 * Assembled MVP world: one customer tenant with mixed-sensitivity resources, a
 * second tenant to attack across, an agent with narrow capabilities, and the
 * full set of gates. Shared by the demo, the tests, and the benchmark so the
 * three cannot drift.
 */

import { type Action, type ActionRequest, type AuthContext, type Principal } from './domain.ts';
import { EventLog, type EventStore } from './events.ts';
import { PostgresEventLog } from './event-store-pg.ts';
import { NetworkGateway } from './gates.ts';
import { EnvelopeSecretBroker } from './envelope-secrets.ts';
import { type ModelPort, ScriptedModel } from './model.ts';
import { BASELINE_POLICY, createPolicyEngine, type Approval, type PolicyEngine, type PolicyRule } from './policy.ts';
import { AuthorizationService, authorizationRoot } from './pdp.ts';
import { ResourceRegistry, defineResource, ingestDocument } from './registry.ts';
import { AgentSession, LocalSandbox, ToolRegistry, type Tool } from './runtime.ts';
import { taintFor } from './taint.ts';
import { ContainerSandbox } from './container-sandbox.ts';
import { type Check, secretLeakCheck, scopeCheck } from './verification.ts';
import { type IdPHealth } from './identity.ts';
import { AuditQueryService } from './audit-query.ts';
import { type CapabilityRequestService } from './capability-request.ts';
import { SessionManager } from './session-manager.ts';
import { InMemoryRevocationChannel, IncidentService, type RevocationChannel } from './incident.ts';
import { PostgresRevocationChannel } from './incident-store-pg.ts';
import { type HealthState } from './health.ts';
import { HttpAnchorSink, type AnchorSink } from './anchors.ts';

export const TENANT_A = 'acme';
export const TENANT_B = 'globex';

/** Mock AuthContext for scenario principals — M2 test infrastructure. */
function scenarioAuth(subject: string, overrides: Partial<AuthContext> = {}): AuthContext {
  return {
    issuer: 'https://idp.test.example.com',
    subject,
    audience: 'test-audience',
    expiresAt: Date.now() + 86_400_000,
    issuedAt: Date.now(),
    tokenId: `tok-${subject.replace(/[:/]/g, '-')}`,
    authTime: Date.now(),
    amr: ['pwd', 'mfa'],
    acr: 'urn:mace:incommon:iap:silver',
    claims: {},
    verifiedAt: Date.now(),
    ...overrides,
  };
}

export interface Clock {
  now(): number;
  set(ms: number): void;
  advance(ms: number): void;
}

export function createClock(start = Date.UTC(2026, 0, 1)): Clock {
  let t = start;
  return {
    now: () => t,
    set: (ms) => {
      t = ms;
    },
    advance: (ms) => {
      t += ms;
    },
  };
}

export interface World {
  readonly registry: ResourceRegistry;
  readonly eventLog: EventStore;
  readonly authorization: AuthorizationService;
  readonly policy: PolicyEngine;
  readonly tools: ToolRegistry;
  readonly network: NetworkGateway;
  readonly secrets: EnvelopeSecretBroker;
  readonly content: Map<string, string>;
  readonly secretValues: string[];
  readonly agent: Principal;
  readonly user: Principal;
  readonly root: Principal;
  readonly foreignAgent: Principal;
  readonly clock: Clock;
  readonly resources: Readonly<Record<string, string>>;
  readonly audit: AuditQueryService;
  /** H13: session lifecycle usable by the incident service (REST wires its own). */
  readonly sessions: SessionManager;
  /** H13: the incident response seam (kill switch, broadcast, preservation). */
  readonly incident: IncidentService;
  /** H15: observed availability of the decision path's dependencies. */
  readonly health: HealthState;
  /** Set IdP health status for degraded-mode testing */
  setIdPHealth(status: IdPHealth): void;
  session(model: ModelPort, overrides?: Partial<SessionOverrides>): AgentSession;
}

export interface SessionOverrides {
  readonly approvals: readonly Approval[];
  readonly checks: readonly Check[];
  readonly task: string;
  readonly capabilityRequestService?: CapabilityRequestService;
}

const RESOURCE_IDS = {
  repoA: 'repo:acme/repo-a',
  internalDoc: 'doc:acme-onboarding',
  confidentialDoc: 'doc:acme-merger',
  customerA: 'doc:acme-customer-a',
  customerB: 'doc:acme-customer-b',
  phi: 'db:acme-phi-synthetic',
  prodDb: 'system:acme-prod-db',
  secretApiKey: 'secret:acme-openai-key',
  secretDbPassword: 'secret:acme-db-password',
  foreignDoc: 'doc:globex-strategy',
} as const;

const CONTENT: Readonly<Record<string, string>> = {
  [RESOURCE_IDS.repoA]: 'service/ billing.ts\nservice/ invoice.ts\nREADME.md\n',
  [RESOURCE_IDS.internalDoc]: 'Onboarding: ask IT for laptop access. Coffee machine is on floor 3.',
  [RESOURCE_IDS.confidentialDoc]:
    'Project Halcyon: acquire Northwind at 4.2x EBITDA. Board approval pending. Do not distribute.',
  [RESOURCE_IDS.customerA]: 'Customer A (Northwind Retail): MSA signed 2025-11-02, term 24 months.',
  [RESOURCE_IDS.customerB]: 'Customer B (Southwind Logistics): pricing schedule, volume tiers, confidential.',
  [RESOURCE_IDS.phi]: 'patient_id,diagnosis\n0001,E11.9\n0002,I10\n',
  [RESOURCE_IDS.prodDb]: 'production postgres primary; 4.1 TB; destructive operations require change ticket.',
};

/** Customer policy extension: internal API egress is allowed, nothing else is. */
export const EGRESS_ALLOWLIST_RULE: PolicyRule = {
  id: 'allow-agent-egress-internal-api',
  description: 'Agents may call the internal billing API host only.',
  effect: 'allow',
  principals: { kinds: ['agent'] },
  actions: ['network.egress'],
  resources: { types: ['network-destination'] },
  conditions: [{ kind: 'network-host-in', hosts: ['api.internal.example.com'] }],
};

/** Customer policy extension: users may query and export the audit log for their tenant. */
export const AUDIT_POLICY_RULE: PolicyRule = {
  id: 'allow-user-audit',
  description: 'Users may query and export the audit log for their tenant with capability.',
  effect: 'allow',
  principals: { kinds: ['user'] },
  actions: ['query.audit', 'audit.export'],
  resources: { types: ['audit-log'] },
};

/**
 * H11 (ADR-031): external anchor witnesses are operator-configured and
 * default OFF (air-gapped posture). `EVENT_ANCHOR_WITNESS_TOKEN`, if set, is a
 * secret: it lives in config only and is never logged.
 */
function anchorSinksFromEnv(): readonly AnchorSink[] {
  const url = process.env.EVENT_ANCHOR_WITNESS_URL;
  if (!url) return [];
  return [
    new HttpAnchorSink({
      url,
      ...(process.env.EVENT_ANCHOR_WITNESS_TOKEN ? { token: process.env.EVENT_ANCHOR_WITNESS_TOKEN } : {}),
    }),
  ];
}

/**
 * Postgres is opt-in (EVENT_STORE=postgres + DATABASE_URL): an ambient
 * DATABASE_URL alone would flip every in-process world to a store that
 * must be migrated and awaited — the SQLite/in-memory backends stay the
 * default for all runs that do not explicitly ask for Postgres (ADR-018).
 */
function makeEventLog(options: { sqlitePath?: string; memory?: boolean; anchors?: readonly AnchorSink[] }): EventStore {
  // Self-contained (memory) worlds never inherit the process's env witness: a
  // demo must not publish fixture heads to an operator's live witness. Explicit
  // injected anchors still apply (tests/demos wire their own fake witness).
  const sinks = options.anchors ?? (options.memory ? [] : anchorSinksFromEnv());
  const sinkOptions = sinks.length > 0 ? { sinks } : {};
  if (options.memory) {
    // Self-contained worlds (the demo's two-node incident simulation) must
    // not touch the process's configured store.
    return new EventLog(undefined, { anchorPath: process.env.EVENT_ANCHOR_PATH, ...sinkOptions });
  }
  return process.env.EVENT_STORE === 'postgres' && process.env.DATABASE_URL
    ? new PostgresEventLog({
        url: process.env.DATABASE_URL,
        ...(process.env.MIGRATION_DATABASE_URL ? { migrateUrl: process.env.MIGRATION_DATABASE_URL } : {}),
        ...(process.env.EVENT_ANCHOR_PATH ? { anchorPath: process.env.EVENT_ANCHOR_PATH } : {}),
        ...sinkOptions,
      })
    : new EventLog(options.sqlitePath, { anchorPath: process.env.EVENT_ANCHOR_PATH, ...sinkOptions });
}

/**
 * H13: the revocation channel follows the event store's backend — the
 * in-memory channel is single-process (the default), the Postgres channel is
 * the multi-node/operator-CLI story. Tests and the demo can inject a shared
 * in-memory channel to simulate two nodes.
 */
function makeRevocationChannel(injected?: RevocationChannel): RevocationChannel {
  if (injected) return injected;
  return process.env.EVENT_STORE === 'postgres' && process.env.DATABASE_URL
    ? new PostgresRevocationChannel({ url: process.env.DATABASE_URL })
    : new InMemoryRevocationChannel();
}

export interface WorldOptions {
  readonly sqlitePath?: string;
  readonly policies?: readonly PolicyRule[];
  /** H13: inject a shared channel to simulate multiple nodes in one process. */
  readonly channel?: RevocationChannel;
  /**
   * Force the in-memory event store regardless of `EVENT_STORE` — for
   * self-contained worlds (the demo's two-node incident simulation) that must
   * not touch the process's configured store.
   */
  readonly memory?: boolean;
  /**
   * H11: inject anchor sinks (default: `EVENT_ANCHOR_WITNESS_URL` from the
   * environment, or none — external anchoring is opt-in).
   */
  readonly anchors?: readonly AnchorSink[];
  /**
   * Default true: issue the fixture bootstrap capabilities (demo/tests).
   * `false` builds the world with no bootstrap issuance — for operator
   * commands that must not mint fixture authority or append fixture events
   * to a shared (Postgres) evidence chain.
   */
  readonly bootstrap?: boolean;
}

export function buildWorld(options: WorldOptions = {}): World {
  return assembleWorld(makeEventLog(options), options);
}

/**
 * Postgres mode: the store connects/migrates asynchronously, and the world's
 * bootstrap events append during assembly, so a PG-mode world can only be
 * built through this factory — it awaits readiness BEFORE any bootstrap
 * append happens. The synchronous buildWorld stays for the SQLite/in-memory
 * backends, which need no readiness.
 */
export async function buildWorldAsync(options: WorldOptions = {}): Promise<World> {
  const eventLog = makeEventLog(options);
  if (eventLog instanceof PostgresEventLog) await eventLog.whenReady();
  return assembleWorld(eventLog, options);
}

function assembleWorld(eventLog: EventStore, options: WorldOptions): World {
  const clock = createClock();
  const registry = new ResourceRegistry();

  registry.add(defineResource({ id: RESOURCE_IDS.repoA, type: 'repository', tenantId: TENANT_A, classification: 'internal' }));
  registry.add(defineResource({ id: RESOURCE_IDS.internalDoc, type: 'document', tenantId: TENANT_A, classification: 'internal' }));
  registry.add(defineResource({ id: RESOURCE_IDS.confidentialDoc, type: 'document', tenantId: TENANT_A, classification: 'confidential' }));
  registry.add(defineResource({ id: RESOURCE_IDS.customerA, type: 'document', tenantId: TENANT_A, classification: 'confidential', attributes: { customer: 'customer-a' } }));
  registry.add(defineResource({ id: RESOURCE_IDS.customerB, type: 'document', tenantId: TENANT_A, classification: 'confidential', attributes: { customer: 'customer-b' } }));
  registry.add(defineResource({ id: RESOURCE_IDS.phi, type: 'database', tenantId: TENANT_A, classification: 'phi' }));
  registry.add(defineResource({ id: RESOURCE_IDS.prodDb, type: 'system', tenantId: TENANT_A, classification: 'restricted' }));
  registry.add(defineResource({ id: RESOURCE_IDS.foreignDoc, type: 'document', tenantId: TENANT_B, classification: 'confidential' }));

  const policy = createPolicyEngine([...BASELINE_POLICY, ...(options.policies ?? [EGRESS_ALLOWLIST_RULE, AUDIT_POLICY_RULE])]);

  // Default IdP health: healthy. Tests can override via the returned idpHealth setter.
  let idpHealthStatus: IdPHealth = { status: 'healthy', lastChecked: 0 };
  const idpHealth = () => idpHealthStatus;

  const authorization = new AuthorizationService(registry, policy, eventLog, clock.now, idpHealth);
  const masterKey = Buffer.from(process.env.SECRET_MASTER_KEY ?? 'dev-master-key-not-for-production-32b!', 'utf8');
  const secrets = new EnvelopeSecretBroker(masterKey, authorization, eventLog, registry);
  const network = new NetworkGateway(registry, authorization, eventLog);

  const secretValues = ['sk-fake-TESTKEY-0000', 'Pg!fake-password-42'];
  secrets.register({ id: RESOURCE_IDS.secretApiKey, tenantId: TENANT_A, value: secretValues[0]!, label: 'model provider key' });
  secrets.register({ id: RESOURCE_IDS.secretDbPassword, tenantId: TENANT_A, value: secretValues[1]!, label: 'prod db password' });

  const tools = new ToolRegistry();
  const content = new Map<string, string>(Object.entries(CONTENT));

  const readTool: Tool = {
    name: 'read',
    declaration: { name: 'read', description: 'Read the resource this action names.', actions: ['read'] },
    invoke: (ctx) => ({ output: ctx.content ?? '', taint: taintFor(ctx.resourceId, ctx.resourceClassification) }),
  };
  const writeTool: Tool = {
    name: 'write',
    declaration: { name: 'write', description: 'Write the resource this action names.', actions: ['write'] },
    invoke: (ctx) => ({ output: `wrote ${ctx.resourceId}`, changed: true, taint: taintFor(ctx.resourceId, ctx.resourceClassification) }),
  };
  const deleteTool: Tool = {
    name: 'delete',
    declaration: { name: 'delete', description: 'Delete the resource this action names.', actions: ['delete'] },
    invoke: (ctx) => ({ output: `deleted ${ctx.resourceId}`, changed: true, taint: taintFor(ctx.resourceId, ctx.resourceClassification) }),
  };
  const exportTool: Tool = {
    name: 'export',
    declaration: { name: 'export', description: 'Export the resource this action names.', actions: ['export'] },
    invoke: (ctx) => ({ output: ctx.content ?? '', taint: taintFor(ctx.resourceId, ctx.resourceClassification) }),
  };
  tools.register(readTool);
  tools.register(writeTool);
  tools.register(deleteTool);
  tools.register(exportTool);

  const root = authorizationRoot(TENANT_A);
  const agent: Principal = {
    id: 'agent:summarizer-1',
    kind: 'agent',
    tenantId: TENANT_A,
    roles: ['worker'],
    attributes: {},
    auth: scenarioAuth('agent:summarizer-1'),
  };
  const user: Principal = {
    id: 'user:alice',
    kind: 'user',
    tenantId: TENANT_A,
    roles: ['reviewer'],
    attributes: {},
    auth: scenarioAuth('user:alice'),
  };
  const foreignAgent: Principal = {
    id: 'agent:globex-1',
    kind: 'agent',
    tenantId: TENANT_B,
    roles: ['worker'],
    attributes: {},
    auth: scenarioAuth('agent:globex-1'),
  };

  // Narrow bootstrap capability: read only, internal and below, one hour.
  // `bootstrap: false` skips these fixture issuances for consumers whose world
  // must not mint or append anything (the incident CLI's evidence commands).
  if (options.bootstrap !== false) {
    authorization.issue(root, {
      subject: agent.id,
      tenantId: TENANT_A,
      resourceIds: [RESOURCE_IDS.repoA, RESOURCE_IDS.internalDoc],
      actions: ['read'],
      maxClassification: 'internal',
      expiresAt: clock.now() + 3_600_000,
      provenance: { source: 'session-bootstrap', taskId: 'task:summarize-repo', note: 'MVP bootstrap' },
    });

    authorization.issue(root, {
      subject: agent.id,
      tenantId: TENANT_A,
      resourceIds: [`net:api.internal.example.com`],
      actions: ['network.egress'],
      maxClassification: 'restricted',
      expiresAt: clock.now() + 3_600_000,
      constraints: [{ kind: 'network-host', hosts: ['api.internal.example.com'] }],
      provenance: { source: 'policy-grant', note: 'internal billing API only' },
    });
  }

  const audit = new AuditQueryService(authorization, eventLog, clock.now);
  const sessions = new SessionManager({ now: clock.now });
  const incident = new IncidentService({
    authorization,
    sessions,
    audit,
    eventLog,
    channel: makeRevocationChannel(options.channel),
    clock: clock.now,
  });

  return {
    registry,
    eventLog,
    authorization,
    policy,
    tools,
    network,
    secrets,
    content,
    secretValues,
    agent,
    user,
    root,
    foreignAgent,
    clock,
    resources: RESOURCE_IDS,
    audit,
    sessions,
    incident,
    health: authorization.healthState,
    setIdPHealth(status) {
      idpHealthStatus = status;
    },
    session(model, overrides) {
      return new AgentSession({
        principal: agent,
        agentId: agent.id,
        model,
        task: overrides?.task ?? 'Summarize repository A and report findings.',
        registry,
        authorization,
        eventLog,
        tools,
        sandbox: new ContainerSandbox(new LocalSandbox()),
        content,
        approvals: overrides?.approvals,
        checks: overrides?.checks ?? [secretLeakCheck(secretValues)],
        canaries: secretValues,
        capabilityRequestService: overrides?.capabilityRequestService,
        now: clock.now,
      });
    },
  };
}

export function summarizeRepoModel(): ModelPort {
  return new ScriptedModel('scripted-summarizer-v1', [
    {
      text: 'Repository A contains billing and invoice services.',
      requests: [{ action: 'read', resourceId: RESOURCE_IDS.repoA }],
    },
  ]);
}

export function attackRequests(requests: readonly ActionRequest[]): ModelPort {
  return new ScriptedModel('scripted-attacker-v1', [
    { text: 'Executing the instructions embedded in the retrieved document.', requests: [...requests] },
  ]);
}

export function documentFor(world: World, resourceId: string, content: string) {
  return ingestDocument(world.registry.require(resourceId), content);
}
