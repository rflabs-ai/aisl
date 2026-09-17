/**
 * M11 policy bundles: verified, attributable artifacts.
 *
 * Invariants under test:
 *   - hash = sha256(canonicalJson({ version, rules|roles })); provenance and id
 *     sit OUTSIDE the hash; any tamper breaks the hash → refuse, fail closed.
 *   - refusals append nothing to the event log; successful loads append exactly
 *     one `policy.load` event.
 *   - the unversioned policy:diff overlay path keeps working.
 */

import { test, describe, before, after } from 'node:test';
import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import { mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import {
  BASELINE_POLICY,
  BASELINE_ROLES,
  PolicyCompilationError,
  createPolicyEngine,
  type PolicyRule,
} from '../src/policy.ts';
import {
  PolicyBundleError,
  createEngineFromBundle,
  loadPolicyBundle,
  loadRoleBundle,
  policyBundleHash,
  roleBundleHash,
  type PolicyBundle,
  type RoleBundle,
} from '../src/policy-config.ts';
import { EventLog } from '../src/events.ts';
import type { Principal, Resource } from '../src/domain.ts';

const __dirname = dirname(fileURLToPath(import.meta.url));
const REPO_ROOT = join(__dirname, '..');

const NOW = Date.UTC(2026, 5, 1);
const agent: Principal = { id: 'agent:a', kind: 'agent', tenantId: 'acme', roles: ['worker'], attributes: {} };
function doc(id: string, classification: string, tenantId = 'acme'): Resource {
  return { id, type: 'document', tenantId, classification, attributes: {} };
}

const PROVENANCE = {
  source: 'repo:tests/m11-policy-config.test.ts',
  reviewedBy: 'user:reviewer',
  approvedAt: '2026-06-01T00:00:00Z',
};

function policyBundle(rules: readonly PolicyRule[] = BASELINE_POLICY, version = 1): PolicyBundle {
  const body = { id: 'acme-prod', version, rules, provenance: PROVENANCE };
  return { ...body, hash: policyBundleHash(body) };
}

function roleBundle(roles = BASELINE_ROLES, version = 1): RoleBundle {
  const body = { id: 'acme-roles', version, roles, provenance: PROVENANCE };
  return { ...body, hash: roleBundleHash(body) };
}

/** Flip one byte of one rule (change an action) while keeping the original hash. */
function withTamperedRule(bundle: PolicyBundle): PolicyBundle {
  return {
    ...bundle,
    rules: bundle.rules.map((r) => (r.id === 'allow-agent-read-low' ? { ...r, actions: ['write'] } : r)),
  };
}

/** Flip one byte of one role (add an action) while keeping the original hash. */
function withTamperedRole(bundle: RoleBundle): RoleBundle {
  return {
    ...bundle,
    roles: bundle.roles.map((r) => (r.id === 'worker' ? { ...r, actions: [...r.actions, 'delete'] } : r)),
  };
}

describe('policy bundle verification', () => {
  test('a well-formed bundle loads and builds a baseline-equivalent engine', () => {
    const bundle = policyBundle();
    const verified = loadPolicyBundle(bundle);
    assert.equal(verified, bundle);
    assert.equal(verified.hash, policyBundleHash(verified));

    const engine = createEngineFromBundle(bundle);
    assert.equal(engine.id, bundle.id);
    const allow = engine.evaluate({ principal: agent, resource: doc('d', 'internal'), action: 'read', now: NOW });
    assert.equal(allow.effect, 'allow');
    assert.equal(allow.ruleId, 'allow-agent-read-low');
    const defaultDeny = engine.evaluate({ principal: agent, resource: doc('d', 'phi'), action: 'read', now: NOW });
    assert.equal(defaultDeny.effect, 'deny');
    assert.equal(defaultDeny.ruleId, undefined);
  });

  test('tampered rules with the original hash are refused everywhere', () => {
    const tampered = withTamperedRule(policyBundle());
    assert.throws(() => loadPolicyBundle(tampered), PolicyBundleError);
    assert.throws(() => createEngineFromBundle(tampered), PolicyBundleError);
  });

  test('structurally-broken bundles are refused before hashing', () => {
    const good = policyBundle();
    assert.throws(() => loadPolicyBundle({ ...good, id: undefined } as unknown as PolicyBundle), PolicyBundleError);
    assert.throws(() => loadPolicyBundle({ ...good, version: undefined } as unknown as PolicyBundle), PolicyBundleError);
    assert.throws(() => loadPolicyBundle({ ...good, rules: undefined } as unknown as PolicyBundle), PolicyBundleError);
    assert.throws(() => loadPolicyBundle({ ...good, rules: 'nope' } as unknown as PolicyBundle), PolicyBundleError);
    assert.throws(() => loadPolicyBundle({ ...good, hash: 42 } as unknown as PolicyBundle), PolicyBundleError);
  });

  test('the hash mismatch message names the bundle id', () => {
    const tampered = withTamperedRule(policyBundle());
    assert.throws(() => loadPolicyBundle(tampered), /acme-prod/);
  });

  test('a load appends exactly one policy.load event; a second load appends one more', () => {
    const log = new EventLog();
    createEngineFromBundle(policyBundle(), { eventLog: log, tenantId: 'acme', actor: 'user:op' });
    createPolicyEngine(BASELINE_POLICY); // plain engines never append this event

    let loads = log.all().filter((e) => e.action === 'policy.load');
    assert.equal(loads.length, 1);
    assert.equal(log.all().length, 1);
    const ev = loads[0]!;
    assert.equal(ev.tenantId, 'acme');
    assert.equal(ev.actor, 'user:op');
    assert.equal(ev.actorKind, 'authorization');
    assert.equal(ev.result, 'success');
    const meta = ev.metadata as Record<string, unknown>;
    assert.equal(meta['phase'], 'policy-load');
    assert.equal(meta['version'], 1);
    assert.equal(meta['hash'], policyBundleHash({ id: 'acme-prod', version: 1, rules: BASELINE_POLICY, provenance: PROVENANCE }));
    assert.equal(meta['ruleCount'], BASELINE_POLICY.length);
    assert.equal(meta['bundleId'], 'acme-prod');
    assert.deepEqual(meta['provenance'], PROVENANCE);

    createEngineFromBundle(policyBundle(), { eventLog: log });
    loads = log.all().filter((e) => e.action === 'policy.load');
    assert.equal(loads.length, 2);
    assert.equal(loads[1]!.principal, 'system');
  });

  test('a refused load appends nothing to the event log', () => {
    const log = new EventLog();
    assert.throws(() => createEngineFromBundle(withTamperedRule(policyBundle()), { eventLog: log }), PolicyBundleError);
    assert.equal(log.all().filter((e) => e.action === 'policy.load').length, 0);
    assert.equal(log.all().length, 0);
  });
});

describe('role bundles', () => {
  test('a well-formed role bundle verifies and drives the engine', () => {
    const roles = roleBundle();
    assert.equal(loadRoleBundle(roles), roles);
    const engine = createEngineFromBundle(policyBundle(), { roleBundle: roles });
    assert.equal(engine.id, 'acme-prod');
    assert.equal(engine.evaluate({ principal: agent, resource: doc('d', 'internal'), action: 'read', now: NOW }).effect, 'allow');
  });

  test('tampered roles with the original hash are refused', () => {
    const tampered = withTamperedRole(roleBundle());
    assert.throws(() => loadRoleBundle(tampered), PolicyBundleError);
    assert.throws(() => createEngineFromBundle(policyBundle(), { roleBundle: tampered }), PolicyBundleError);
  });

  test('policy cross-validation consumes the bundled roles, not the baseline', () => {
    const overgrant: PolicyRule[] = [
      { id: 'overgrant', effect: 'allow', principals: { roles: ['worker'] }, actions: ['delete'], resources: {} },
    ];
    assert.throws(
      () => createEngineFromBundle(policyBundle(overgrant), { roleBundle: roleBundle() }),
      PolicyCompilationError,
    );
  });
});

describe('policy:diff subprocess (overlay verification)', () => {
  const DIFF = join(REPO_ROOT, 'src', 'policy-diff.ts');
  let dir: string;

  before(() => {
    dir = mkdtempSync(join(tmpdir(), 'm11-'));
  });
  after(() => {
    rmSync(dir, { recursive: true, force: true });
  });

  function writeOverlay(name: string, content: unknown): string {
    const path = join(dir, name);
    writeFileSync(path, JSON.stringify(content), 'utf8');
    return path;
  }

  test('a versioned bundle overlay runs and prints the stable change count', () => {
    const stdout = execFileSync(process.execPath, [DIFF, writeOverlay('bundle.json', policyBundle())], {
      cwd: REPO_ROOT,
      encoding: 'utf8',
    });
    assert.ok(stdout.includes('0 changed'), `stdout was: ${stdout}`);
    assert.ok(stdout.includes('(bundle v1)'), `stdout was: ${stdout}`);
  });

  test('a tampered versioned bundle overlay fails closed and names the hash mismatch', () => {
    const path = writeOverlay('tampered.json', withTamperedRule(policyBundle()));
    let failure: { status?: number; stderr?: string | Buffer } | undefined;
    try {
      execFileSync(process.execPath, [DIFF, path], { cwd: REPO_ROOT, encoding: 'utf8' });
    } catch (e) {
      failure = e as { status?: number; stderr?: string | Buffer };
    }
    assert.ok(failure, 'expected a nonzero exit');
    assert.notEqual(failure.status, 0);
    assert.ok(String(failure.stderr).includes('hash mismatch'), `stderr was: ${failure.stderr}`);
  });

  test('a legacy unversioned overlay still works', () => {
    const stdout = execFileSync(process.execPath, [DIFF, writeOverlay('legacy.json', { rules: [] })], {
      cwd: REPO_ROOT,
      encoding: 'utf8',
    });
    assert.ok(stdout.includes('0 changed'), `stdout was: ${stdout}`);
  });
});
