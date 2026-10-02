/**
 * H15 acceptance: fail-closed availability engineering (ADR-027).
 *
 * Fault injection per dependency (engine throws, store unwritable, clock
 * stalled/throwing/backward): every fault denies with its own reason AND
 * emits a health signal on the transition; recovery is automatic and loud.
 * Degradation is deny-only - a fault never produces an allow. Safety
 * mechanisms degrade the same way: issue() records evidence before
 * registering authority, revokeAll completes under evidence failure, engage
 * completes local enforcement and reports what it could not record, and
 * unfreeze refuses to lift a freeze it cannot record.
 *
 * These tests were written before src/health.ts existed; the red signal
 * (ERR_MODULE_NOT_FOUND without the module) was verified by the 2026-10-02
 * audit probe, not captured during the build (audit ticket 02).
 */

import { describe, test } from 'node:test';
import assert from 'node:assert/strict';
import { EventLog, StoreUnavailableError, type EventInput, type SecurityEvent } from '../src/events.ts';
import { AuthorizationService, authorizationRoot } from '../src/pdp.ts';
import { CapabilityIssuanceError, type IssueRequest } from '../src/capability.ts';
import type { EvaluationContext, PolicyEngine, PolicyResult } from '../src/policy.ts';
import { ResourceRegistry, defineResource } from '../src/registry.ts';
import { HealthState, ClockGuard, type DependencyStatus, type HealthDependency } from '../src/health.ts';
import { AuditQueryService } from '../src/audit-query.ts';
import { SessionManager } from '../src/session-manager.ts';
import { InMemoryRevocationChannel, IncidentService } from '../src/incident.ts';
import { RestApi } from '../src/rest-api.ts';
import { createMockIdP, mockAuth, testUser, testWorld, unauthPrincipal } from '../src/testing.ts';
import { TENANT_A } from '../src/scenario.ts';
import type { Principal } from '../src/domain.ts';

const T0 = Date.UTC(2026, 0, 1);
const CANARY = 'canary-secret-value-do-not-leak';

interface Transition {
  readonly dep: HealthDependency;
  readonly status: DependencyStatus;
  readonly detail?: string;
}

/** Policy engine whose failure mode is switchable mid-test. */
class SwitchableEngine implements PolicyEngine {
  readonly id = 'h15-switchable';
  fail = false;

  evaluate(_ctx: EvaluationContext): PolicyResult {
    if (this.fail) throw new Error(`policy engine exploded while holding ${CANARY}`);
    return { effect: 'allow', ruleId: 'h15-allow', reason: 'h15 test allow' };
  }
}

/** EventLog whose append can be made to fail like a full disk or a dead store. */
class FlakyEventLog extends EventLog {
  failMode: 'ok' | 'typed' | 'untyped' = 'ok';

  override append(input: EventInput): SecurityEvent {
    if (this.failMode === 'typed') {
      throw new StoreUnavailableError(`evidence store unavailable (endpoint redacted) near ${CANARY}`);
    }
    if (this.failMode === 'untyped') {
      throw new Error(`disk full near ${CANARY}`);
    }
    return super.append(input);
  }
}

interface Wall {
  value: number;
  mode: 'ok' | 'throw' | 'nan';
}

function wallNow(wall: Wall): () => number {
  return () => {
    if (wall.mode === 'throw') throw new Error('clock source dead');
    if (wall.mode === 'nan') return Number.NaN;
    return wall.value;
  };
}

interface Stack {
  readonly registry: ResourceRegistry;
  readonly engine: SwitchableEngine;
  readonly store: FlakyEventLog;
  readonly transitions: Transition[];
  readonly authz: AuthorizationService;
  readonly wall: Wall;
  readonly user: Principal;
  readonly root: Principal;
  readonly now: () => number;
}

function stack(options: { ownHealth?: boolean } = {}): Stack {
  const registry = new ResourceRegistry();
  registry.add(defineResource({ id: 'r1', type: 'document', tenantId: TENANT_A, classification: 'internal' }));
  const engine = new SwitchableEngine();
  const store = new FlakyEventLog();
  const transitions: Transition[] = [];
  const health = new HealthState((dep, status, detail) => {
    transitions.push({ dep, status, ...(detail !== undefined ? { detail } : {}) });
  });
  const wall: Wall = { value: T0, mode: 'ok' };
  const now = wallNow(wall);
  const authz = new AuthorizationService(registry, engine, store, now);
  if (!options.ownHealth) authz.setHealth(health);
  const root = authorizationRoot(TENANT_A);
  const user = testUser('user:alice', TENANT_A);
  return { registry, engine, store, transitions, authz, wall, user, root, now };
}

function readRequest(): { action: 'read'; resourceId: 'r1' } {
  return { action: 'read', resourceId: 'r1' };
}

function issueRead(s: Stack, subject = 'user:alice', singleUse = false): string {
  const request: IssueRequest = {
    subject,
    tenantId: TENANT_A,
    resourceIds: ['r1'],
    actions: ['read'],
    maxClassification: 'internal',
    expiresAt: s.wall.value + 3_600_000,
    singleUse,
    provenance: { source: 'policy-grant', note: 'h15 test' },
  };
  return s.authz.issue(s.root, request).id;
}

describe('H15: fault injection - policy engine', () => {
  test('a throwing engine denies evaluation-error and emits a health transition', () => {
    const s = stack();
    issueRead(s);
    s.engine.fail = true;
    const decision = s.authz.authorize({ principal: s.user, ...readRequest() });
    assert.equal(decision.decision, 'deny');
    assert.equal(decision.denyReason, 'evaluation-error');
    assert.equal(s.authz.healthState.snapshot().engine, 'unavailable');
    assert.deepEqual(s.transitions.at(-1), { dep: 'engine', status: 'unavailable', detail: 'policy engine threw' });
  });

  test('engine recovery is automatic and loud', () => {
    const s = stack();
    issueRead(s);
    s.engine.fail = true;
    s.authz.authorize({ principal: s.user, ...readRequest() });
    s.engine.fail = false;
    const decision = s.authz.authorize({ principal: s.user, ...readRequest() });
    assert.equal(decision.decision, 'allow');
    assert.equal(s.authz.healthState.snapshot().engine, 'ok');
    assert.deepEqual(s.transitions.at(-1), { dep: 'engine', status: 'ok' });
  });
});

describe('H15: fault injection - evidence store', () => {
  test('a typed store outage denies store-unavailable and never allows unrecorded', () => {
    const s = stack();
    issueRead(s);
    s.store.failMode = 'typed';
    const decision = s.authz.authorize({ principal: s.user, ...readRequest() });
    assert.equal(decision.decision, 'deny', 'fail-closed floor: no unrecorded allow');
    assert.equal(decision.denyReason, 'store-unavailable');
    assert.equal(s.authz.healthState.snapshot().store, 'unavailable');
    assert.deepEqual(s.transitions.at(-1), { dep: 'store', status: 'unavailable', detail: 'evidence append failed' });
  });

  test('an untyped write failure (full disk) denies evidence-write-failure with the same health signal', () => {
    const s = stack();
    issueRead(s);
    s.store.failMode = 'untyped';
    const decision = s.authz.authorize({ principal: s.user, ...readRequest() });
    assert.equal(decision.decision, 'deny');
    assert.equal(decision.denyReason, 'evidence-write-failure');
    assert.equal(s.authz.healthState.snapshot().store, 'unavailable');
    assert.deepEqual(s.transitions.at(-1), { dep: 'store', status: 'unavailable', detail: 'evidence append failed' });
  });

  test('store recovery is automatic and loud', () => {
    const s = stack();
    issueRead(s);
    s.store.failMode = 'typed';
    s.authz.authorize({ principal: s.user, ...readRequest() });
    s.store.failMode = 'ok';
    const decision = s.authz.authorize({ principal: s.user, ...readRequest() });
    assert.equal(decision.decision, 'allow');
    assert.equal(s.authz.healthState.snapshot().store, 'ok');
    assert.deepEqual(s.transitions.at(-1), { dep: 'store', status: 'ok' });
  });
});

describe('H15: fault injection - clock', () => {
  test('a throwing clock denies clock-unavailable before any authority is examined', () => {
    const s = stack();
    issueRead(s);
    s.wall.mode = 'throw';
    const decision = s.authz.authorize({ principal: s.user, ...readRequest() });
    assert.equal(decision.decision, 'deny');
    assert.equal(decision.denyReason, 'clock-unavailable');
    assert.equal(s.authz.healthState.snapshot().clock, 'unavailable');
    assert.deepEqual(s.transitions.at(-1), { dep: 'clock', status: 'unavailable', detail: 'clock read failed' });
  });

  test('a non-finite clock reading denies clock-unavailable', () => {
    const s = stack();
    issueRead(s);
    s.wall.mode = 'nan';
    const decision = s.authz.authorize({ principal: s.user, ...readRequest() });
    assert.equal(decision.decision, 'deny');
    assert.equal(decision.denyReason, 'clock-unavailable');
    assert.equal(s.authz.healthState.snapshot().clock, 'unavailable');
  });

  test('a stalled clock (strict guard) denies clock-unavailable; recovery is automatic', () => {
    const s = stack();
    issueRead(s);
    let mono = 0;
    s.authz.setClockGuard(new ClockGuard(s.now, { monotonic: () => mono, stallAfterMs: 10 }));
    const first = s.authz.authorize({ principal: s.user, ...readRequest() });
    assert.equal(first.decision, 'allow', 'the first decision is fine');
    mono += 100;
    const stalled = s.authz.authorize({ principal: s.user, ...readRequest() });
    assert.equal(stalled.decision, 'deny');
    assert.equal(stalled.denyReason, 'clock-unavailable');
    assert.equal(s.authz.healthState.snapshot().clock, 'unavailable');
    s.wall.value += 1;
    const recovered = s.authz.authorize({ principal: s.user, ...readRequest() });
    assert.equal(recovered.decision, 'allow');
    assert.equal(s.authz.healthState.snapshot().clock, 'ok');
    assert.deepEqual(s.transitions.at(-1), { dep: 'clock', status: 'ok' });
  });

  test('a backward clock jump (strict guard) denies clock-unavailable', () => {
    const s = stack();
    issueRead(s);
    s.authz.setClockGuard(new ClockGuard(s.now, { monotonic: () => 0 }));
    assert.equal(s.authz.authorize({ principal: s.user, ...readRequest() }).decision, 'allow');
    s.wall.value = T0 - 5_000;
    const decision = s.authz.authorize({ principal: s.user, ...readRequest() });
    assert.equal(decision.decision, 'deny');
    assert.equal(decision.denyReason, 'clock-unavailable');
    assert.equal(s.authz.healthState.snapshot().clock, 'unavailable');
  });

  test('false-denial pin: a frozen or backward test clock is fine without trend detection', () => {
    const s = stack();
    issueRead(s);
    assert.equal(s.authz.authorize({ principal: s.user, ...readRequest() }).decision, 'allow');
    assert.equal(s.authz.authorize({ principal: s.user, ...readRequest() }).decision, 'allow', 'frozen wall must not deny');
    s.wall.value = T0 - 5_000;
    assert.equal(s.authz.authorize({ principal: s.user, ...readRequest() }).decision, 'allow', 'backward wall must not deny (lenient default)');
    assert.equal(s.authz.healthState.snapshot().clock, 'ok');
  });
});

describe('H15: degraded mode - what still works', () => {
  test('IdP outage: unauthenticated principals deny idp-unavailable; authenticated authority continues', () => {
    const world = testWorld();
    world.setIdPHealth({ status: 'unreachable', lastChecked: 0 });
    const denied = world.authorization.authorize({
      principal: unauthPrincipal('agent:stray'),
      action: 'read',
      resourceId: world.resources.repoA!,
    });
    assert.equal(denied.decision, 'deny');
    assert.equal(denied.denyReason, 'idp-unavailable');

    const allowed = world.authorization.authorize({
      principal: world.agent,
      action: 'read',
      resourceId: world.resources.repoA!,
    });
    assert.equal(allowed.decision, 'allow', 'a valid auth context is checked locally; an IdP outage must not revoke it');
  });

  test('store outage: the allow path is denied, never silently dropped or allowed', () => {
    const s = stack();
    issueRead(s);
    s.store.failMode = 'typed';
    for (let i = 0; i < 3; i++) {
      const decision = s.authz.authorize({ principal: s.user, ...readRequest() });
      assert.equal(decision.decision, 'deny');
      assert.equal(decision.denyReason, 'store-unavailable');
    }
    assert.equal(s.transitions.filter((t) => t.dep === 'store').length, 1, 'one loud transition, not one per denied decision');
  });
});

describe('H15: safety mechanisms under store outage', () => {
  test('issue() records evidence before authority: a store outage refuses the mint and leaves nothing registered', () => {
    const s = stack();
    s.store.failMode = 'typed';
    assert.throws(() => issueRead(s), CapabilityIssuanceError);
    assert.equal(s.authz.capabilitiesFor('user:alice').length, 0, 'no unaudited authority may exist');
    assert.equal(s.authz.healthState.snapshot().store, 'unavailable');
  });

  test('revokeAll completes the kill switch when evidence writes fail', () => {
    const s = stack();
    const a = issueRead(s);
    const b = issueRead(s);
    s.store.failMode = 'untyped';
    const revoked = s.authz.revokeAll('tenant', TENANT_A, 'incident drill');
    assert.equal(revoked, 2);
    assert.equal(s.authz.isRevoked(a), true);
    assert.equal(s.authz.isRevoked(b), true);
  });

  test('engage completes local enforcement under a store outage and reports evidenceRecorded=false', () => {
    const s = stack();
    const cap = issueRead(s);
    const sessions = new SessionManager({ now: s.now });
    const session = sessions.create(s.user, s.user.auth!);
    const incident = new IncidentService({
      authorization: s.authz,
      sessions,
      audit: new AuditQueryService(s.authz, s.store),
      eventLog: s.store,
      channel: new InMemoryRevocationChannel(),
      clock: s.now,
      syncIntervalMs: 60_000,
    });
    s.store.failMode = 'typed';
    const result = incident.engage({ scope: 'tenant', tenantId: TENANT_A, reason: 'drill', actor: 'user:oncall' });
    assert.equal(result.frozen, true, 'the freeze applies even when its evidence cannot be recorded');
    assert.equal(result.evidenceRecorded, false);
    assert.equal(result.capabilitiesRevoked, 1);
    assert.equal(s.authz.isRevoked(cap), true);
    assert.equal(sessions.isValid(session.id), false);
  });

  test('lift refuses to clear a freeze it cannot record (degradation never widens)', () => {
    const s = stack();
    const sessions = new SessionManager({ now: s.now });
    const incident = new IncidentService({
      authorization: s.authz,
      sessions,
      audit: new AuditQueryService(s.authz, s.store),
      eventLog: s.store,
      channel: new InMemoryRevocationChannel(),
      clock: s.now,
      syncIntervalMs: 60_000,
    });
    incident.engage({ scope: 'tenant', tenantId: TENANT_A, reason: 'drill', actor: 'user:oncall' });
    s.store.failMode = 'typed';
    assert.throws(() => incident.lift({ scope: 'tenant', tenantId: TENANT_A, reason: 'contained', actor: 'user:oncall' }));
    assert.equal(s.authz.isFrozen(TENANT_A), true, 'the freeze stays engaged until the lift can be recorded');
  });
});

describe('H15: /healthz and the structural invariant', () => {
  test('GET /healthz reports idp, store, engine, clock and tracks observed faults', async () => {
    const s = stack();
    issueRead(s);
    const mockIdp = await createMockIdP();
    const idp = await mockIdp.createIdP();
    const api = new RestApi({
      authorization: s.authz,
      idp,
      eventLog: s.store,
      resolvePrincipal: (auth) => (auth.subject === s.user.id ? s.user : undefined),
      health: s.authz.healthState,
    });
    const port = await api.start();
    try {
      const healthy = (await (await fetch(`http://127.0.0.1:${port}/healthz`)).json()) as Record<string, unknown>;
      assert.deepEqual(Object.keys(healthy).sort(), ['clock', 'engine', 'idp', 'store']);
      assert.equal(healthy.store, 'ok');
      assert.equal(healthy.engine, 'ok');
      assert.equal(healthy.clock, 'ok');

      s.store.failMode = 'typed';
      s.authz.authorize({ principal: s.user, ...readRequest() });
      const degraded = (await (await fetch(`http://127.0.0.1:${port}/healthz`)).json()) as Record<string, unknown>;
      assert.equal(degraded.store, 'unavailable');
    } finally {
      api.stop();
    }
  });

  test('without a HealthState the M14 /healthz shape is unchanged', async () => {
    const world = testWorld();
    const mockIdp = await createMockIdP();
    const idp = await mockIdp.createIdP();
    const api = new RestApi({
      authorization: world.authorization,
      idp,
      eventLog: world.eventLog,
      resolvePrincipal: (auth) => (auth.subject === world.user.id ? world.user : undefined),
    });
    const port = await api.start();
    try {
      const body = (await (await fetch(`http://127.0.0.1:${port}/healthz`)).json()) as Record<string, unknown>;
      assert.deepEqual(Object.keys(body).sort(), ['idp', 'store']);
    } finally {
      api.stop();
    }
  });

  test('health surfaces carry no secret values (structural)', async () => {
    const s = stack({ ownHealth: true });
    issueRead(s);
    const warnings: string[] = [];
    const onWarning = (w: Error): void => {
      warnings.push(w.message);
    };
    process.on('warning', onWarning);
    try {
      s.engine.fail = true;
      s.authz.authorize({ principal: s.user, ...readRequest() });
      s.engine.fail = false;
      s.store.failMode = 'untyped';
      s.authz.authorize({ principal: s.user, ...readRequest() });
      s.wall.mode = 'throw';
      s.authz.authorize({ principal: s.user, ...readRequest() });
      await new Promise((resolve) => setTimeout(resolve, 20));
    } finally {
      process.off('warning', onWarning);
    }
    const healthSurface = JSON.stringify({
      snapshot: s.authz.healthState.snapshot(),
      transitions: s.transitions,
      warnings,
    });
    assert.equal(healthSurface.includes(CANARY), false, 'health state, transitions, and warnings carry no secret values');
    assert.ok(warnings.length > 0, 'the default health tracker emits a loud process warning');
    assert.ok(
      warnings.some((m) => m.includes('store') || m.includes('engine') || m.includes('clock')),
      'the warning names the degraded dependency',
    );
  });
});

describe('H15: audit follow-up (tickets 01-08, 2026-10-02)', () => {
  test('ticket 01: a faulted clock denies/refuses even with the production broadcast hook installed', () => {
    const s = stack();
    issueRead(s);
    s.authz.setBroadcastSync(() => {}, 60_000);
    s.wall.mode = 'throw';
    const decision = s.authz.authorize({ principal: s.user, ...readRequest() });
    assert.equal(decision.decision, 'deny');
    assert.equal(decision.denyReason, 'clock-unavailable', 'the sync hook must not turn a clock fault into a crash');
    assert.throws(() => issueRead(s), CapabilityIssuanceError);
    assert.equal(s.authz.healthState.snapshot().clock, 'unavailable');
  });

  test('ticket 03: a clock-faulted issuance refusal is recorded as evidence', () => {
    const s = stack();
    s.wall.mode = 'throw';
    assert.throws(() => issueRead(s), CapabilityIssuanceError);
    const refusal = s.store
      .all()
      .find((e) => e.action === 'capability.issue' && e.denyReason === 'clock-unavailable');
    assert.ok(refusal, 'the refusal is in the signed log');
    assert.equal(s.authz.capabilitiesFor('user:alice').length, 0);
  });

  test('ticket 05: the kill switch and single-use consumption survive a faulted clock', () => {
    const s = stack();
    const cap = issueRead(s, 'user:alice', true);
    s.wall.mode = 'throw';
    s.authz.freeze('tenant', TENANT_A, 'clock drill', 'user:oncall');
    assert.equal(s.authz.isFrozen(TENANT_A), true, 'freeze applies with bookkeeping time only');
    s.authz.consume(cap);
    assert.notEqual(s.authz.get(cap)?.usedAt, undefined, 'single-use consumption is recorded');
    s.authz.revoke(cap, 'clock drill');
    assert.equal(s.authz.isRevoked(cap), true, 'revocation applies with bookkeeping time only');
  });

  test('ticket 06: a clock-fault deny recovers store health on its successful append', () => {
    const s = stack();
    issueRead(s);
    s.store.failMode = 'typed';
    s.authz.authorize({ principal: s.user, ...readRequest() });
    assert.equal(s.authz.healthState.snapshot().store, 'unavailable');
    s.store.failMode = 'ok';
    s.wall.mode = 'throw';
    const decision = s.authz.authorize({ principal: s.user, ...readRequest() });
    assert.equal(decision.denyReason, 'clock-unavailable');
    assert.equal(s.authz.healthState.snapshot().store, 'ok', 'the successful appended deny recovers store health');
  });

  test('ticket 08: queryAudit denies clock-unavailable when the clock faults', () => {
    const s = stack();
    s.wall.mode = 'throw';
    const decision = s.authz.queryAudit(
      { principal: s.user, action: 'query.audit', resourceId: '' },
      { tenantId: TENANT_A },
    );
    assert.equal(decision.decision, 'deny');
    assert.equal(decision.denyReason, 'clock-unavailable');
    const event = s.store
      .all()
      .find((e) => e.action === 'query.audit' && e.denyReason === 'clock-unavailable');
    assert.ok(event, 'the query-audit clock fault is recorded');
  });
});