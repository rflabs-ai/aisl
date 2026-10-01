/**
 * H12 acceptance: secure updates (ADR-025).
 *
 * The update channel refuses what ROADMAP names: unsigned updates, rollback
 * to a previously-applied version, and promotion without an explicit health
 * pass. The signed descriptor chains into the H10 build manifest (live tree
 * recomputed), the high-water mark never lowers — including under emergency
 * rollback — and the canary halt is sticky. Each refusal has a distinct
 * reason; no serialized state/grant/descriptor carries key material.
 *
 * These tests were written BEFORE src/updates.ts existed (red-confirmed)
 * per the H12 kickoff contract.
 */

import { describe, test } from 'node:test';
import assert from 'node:assert/strict';
import { generateKeyPairSync, type KeyObject } from 'node:crypto';
import { mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { spawnSync } from 'node:child_process';
import { join } from 'node:path';
import {
  computeSbom,
  computeTreeDigest,
  sbomDigest,
  signManifest,
  type BuildManifest,
} from '../src/supply-chain.ts';
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
} from '../src/updates.ts';

function pemOf(key: KeyObject): string {
  const exported = key.type === 'private'
    ? key.export({ type: 'pkcs8', format: 'pem' })
    : key.export({ type: 'spki', format: 'pem' });
  return typeof exported === 'string' ? exported : exported.toString('utf8');
}

const KP = generateKeyPairSync('ed25519');
const PRIVATE_PEM = pemOf(KP.privateKey);
const PUBLIC_PEM = pemOf(KP.publicKey);
const OTHER_PUBLIC_PEM = pemOf(generateKeyPairSync('ed25519').publicKey);

/** A real git fixture repo: verifyUpdate recomputes tree + SBOM digests from it. */
function fixtureRepo(): string {
  const dir = mkdtempSync(join(tmpdir(), 'h12-fix-'));
  mkdirSync(join(dir, 'src'), { recursive: true });
  writeFileSync(join(dir, 'src', 'a.ts'), 'x\n');
  writeFileSync(join(dir, 'package.json'), `${JSON.stringify({ dependencies: { jose: '6.2.12' }, devDependencies: {} }, null, 2)}\n`);
  writeFileSync(
    join(dir, 'package-lock.json'),
    `${JSON.stringify({
      name: 'x', lockfileVersion: 3, requires: true,
      packages: {
        '': { dependencies: { jose: '6.2.12' } },
        'node_modules/jose': { version: '6.2.12', resolved: 'https://registry.npmjs.org/jose/-/jose-6.2.12.tgz', integrity: 'sha512-AAAA' },
      },
    }, null, 2)}\n`,
  );
  spawnSync('git', ['init', '--initial-branch=main'], { cwd: dir });
  spawnSync('git', ['add', '.'], { cwd: dir });
  return dir;
}

function manifestFor(dir: string, gate?: BuildManifest['gate']): BuildManifest {
  const sbom = computeSbom(dir);
  return {
    type: 'asl-build-manifest',
    version: 1,
    gitHead: null,
    source: { treeDigest: computeTreeDigest(dir) },
    dependencies: { sbomDigest: sbomDigest(sbom), runtimeDeps: ['jose'] },
    gate: gate ?? { typecheck: true, tests: true, supplyChain: true },
    issuedAt: '2026-10-01T00:00:00.000Z',
    issuedBy: 'h12-test',
  };
}

function descriptorFor(
  dir: string,
  opts: { releaseVersion?: number; stages?: number[]; channel?: string; gate?: BuildManifest['gate'] } = {},
): { descriptor: UpdateDescriptor; manifestSig: string } {
  const manifest = manifestFor(dir, opts.gate);
  const manifestSig = signManifest(manifest, PRIVATE_PEM);
  const descriptor: UpdateDescriptor = {
    type: 'asl-update',
    version: 1,
    releaseVersion: opts.releaseVersion ?? 1,
    channel: opts.channel ?? 'stable',
    stages: opts.stages ?? [1, 100],
    manifest,
    manifestSignature: manifestSig,
    issuedAt: '2026-10-01T00:00:00.000Z',
    issuedBy: 'h12-test',
  };
  return { descriptor, manifestSig };
}

function statePathIn(): { dir: string; statePath: string } {
  const dir = mkdtempSync(join(tmpdir(), 'h12-state-'));
  return { dir, statePath: join(dir, 'update-state.json') };
}

describe('Update descriptor signature', () => {
  test('round trip: a signed descriptor verifies with the release key', () => {
    const dir = fixtureRepo();
    try {
      const { descriptor } = descriptorFor(dir);
      const sig = signUpdate(descriptor, PRIVATE_PEM);
      const result = verifyDescriptor(descriptor, sig, PUBLIC_PEM);
      assert.equal(result.valid, true, result.reason);
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });

  test('tampered descriptor, wrong key, and garbage signature all refuse with bad-signature', () => {
    const dir = fixtureRepo();
    try {
      const { descriptor } = descriptorFor(dir);
      const sig = signUpdate(descriptor, PRIVATE_PEM);
      const tampered: UpdateDescriptor = { ...descriptor, channel: 'attacker' };
      assert.equal(verifyDescriptor(tampered, sig, PUBLIC_PEM).reason, 'bad-signature');
      assert.equal(verifyDescriptor(descriptor, sig, OTHER_PUBLIC_PEM).reason, 'bad-signature');
      assert.equal(verifyDescriptor(descriptor, 'AAA', PUBLIC_PEM).reason, 'bad-signature');
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });

  test('bad structure refuses before any signature claim: not-an-update / bad-stages / bad-version', () => {
    const dir = fixtureRepo();
    try {
      const { descriptor } = descriptorFor(dir);
      const sig = signUpdate(descriptor, PRIVATE_PEM);
      assert.equal(verifyDescriptor({ type: 'evil', version: 1 }, sig, PUBLIC_PEM).reason, 'not-an-update');
      assert.equal(verifyDescriptor({ ...descriptor, type: 'asl-build-manifest' }, sig, PUBLIC_PEM).reason, 'not-an-update');
      for (const stages of [[], [100, 10], [50], [10, 10], [0, 100], [10, 101], ['1', 100]]) {
        const bad = { ...descriptor, stages };
        assert.equal(verifyDescriptor(bad, sig, PUBLIC_PEM).reason, 'bad-stages', `stages=${JSON.stringify(stages)}`);
      }
      for (const releaseVersion of [0, -1, 1.5, '2']) {
        const bad = { ...descriptor, releaseVersion };
        assert.equal(verifyDescriptor(bad, sig, PUBLIC_PEM).reason, 'bad-version', `releaseVersion=${String(releaseVersion)}`);
      }
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });

  test('a missing verification key refuses with no-verification-key — never a pass', () => {
    const dir = fixtureRepo();
    try {
      const { descriptor } = descriptorFor(dir);
      const sig = signUpdate(descriptor, PRIVATE_PEM);
      assert.equal(verifyDescriptor(descriptor, sig, '').reason, 'no-verification-key');
      const chain = verifyUpdate(descriptor, sig, { publicKeyPem: '', repoRoot: dir });
      assert.equal(chain.valid, false);
      assert.equal(chain.reason, 'no-verification-key');
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });
});

describe('Chain: descriptor -> build manifest -> live tree', () => {
  test('the full chain verifies against the live fixture repo', () => {
    const dir = fixtureRepo();
    try {
      const { descriptor } = descriptorFor(dir);
      const sig = signUpdate(descriptor, PRIVATE_PEM);
      const result = verifyUpdate(descriptor, sig, { publicKeyPem: PUBLIC_PEM, repoRoot: dir });
      assert.equal(result.valid, true, `${result.reason ?? ''} ${result.detail ?? ''}`);
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });

  test('a forged inner manifest signature surfaces as manifest-rejected/bad-signature', () => {
    const dir = fixtureRepo();
    try {
      const { descriptor } = descriptorFor(dir);
      const forged: UpdateDescriptor = { ...descriptor, manifestSignature: 'AAAA' };
      const sig = signUpdate(forged, PRIVATE_PEM);
      const result = verifyUpdate(forged, sig, { publicKeyPem: PUBLIC_PEM, repoRoot: dir });
      assert.equal(result.valid, false);
      assert.equal(result.reason, 'manifest-rejected');
      assert.equal(result.detail, 'bad-signature');
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });

  test('a source change after signing surfaces as manifest-rejected/stale-source', () => {
    const dir = fixtureRepo();
    try {
      const { descriptor } = descriptorFor(dir);
      const sig = signUpdate(descriptor, PRIVATE_PEM);
      writeFileSync(join(dir, 'src', 'a.ts'), 'evil\n');
      spawnSync('git', ['add', '.'], { cwd: dir });
      const result = verifyUpdate(descriptor, sig, { publicKeyPem: PUBLIC_PEM, repoRoot: dir });
      assert.equal(result.valid, false);
      assert.equal(result.reason, 'manifest-rejected');
      assert.equal(result.detail, 'stale-source');
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });

  test('a gate that did not pass surfaces as manifest-rejected/gate-not-passed', () => {
    const dir = fixtureRepo();
    try {
      const { descriptor } = descriptorFor(dir, { gate: { typecheck: true, tests: true, supplyChain: false } });
      const sig = signUpdate(descriptor, PRIVATE_PEM);
      const result = verifyUpdate(descriptor, sig, { publicKeyPem: PUBLIC_PEM, repoRoot: dir });
      assert.equal(result.valid, false);
      assert.equal(result.reason, 'manifest-rejected');
      assert.equal(result.detail, 'gate-not-passed');
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });
});

describe('Anti-rollback: the high-water mark never lowers', () => {
  test('apply advances the mark, lands canary, and persists state across loads', () => {
    const dir = fixtureRepo();
    const { statePath } = statePathIn();
    try {
      const { descriptor } = descriptorFor(dir, { releaseVersion: 1 });
      const sig = signUpdate(descriptor, PRIVATE_PEM);
      const applied = applyUpdate(descriptor, sig, { publicKeyPem: PUBLIC_PEM, repoRoot: dir, statePath });
      assert.equal(applied.ok, true, applied.reason);
      assert.equal(applied.state?.highWaterMark, 1);
      assert.equal(applied.state?.current?.releaseVersion, 1);
      assert.equal(applied.state?.rollout.status, 'canary');
      assert.equal(applied.state?.rollout.stageIndex, 0);
      const reloaded = loadState(statePath);
      assert.equal(reloaded.highWaterMark, 1, 'state survives a fresh load');
      assert.deepEqual(reloaded.rollout.stages, [1, 100]);
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });

  test('a perfectly signed, perfectly stale descriptor is refused (rollback-blocked) and the mark holds', () => {
    const dir = fixtureRepo();
    const { statePath } = statePathIn();
    try {
      const v1 = descriptorFor(dir, { releaseVersion: 1 });
      const v2 = descriptorFor(dir, { releaseVersion: 2 });
      const sig1 = signUpdate(v1.descriptor, PRIVATE_PEM);
      const sig2 = signUpdate(v2.descriptor, PRIVATE_PEM);
      assert.equal(applyUpdate(v1.descriptor, sig1, { publicKeyPem: PUBLIC_PEM, repoRoot: dir, statePath }).ok, true);
      assert.equal(applyUpdate(v2.descriptor, sig2, { publicKeyPem: PUBLIC_PEM, repoRoot: dir, statePath }).ok, true);

      const replay1 = applyUpdate(v1.descriptor, sig1, { publicKeyPem: PUBLIC_PEM, repoRoot: dir, statePath });
      assert.equal(replay1.ok, false);
      assert.equal(replay1.reason, 'rollback-blocked');
      const replay2 = applyUpdate(v2.descriptor, sig2, { publicKeyPem: PUBLIC_PEM, repoRoot: dir, statePath });
      assert.equal(replay2.ok, false, 're-applying the current version is also a replay');
      assert.equal(replay2.reason, 'rollback-blocked');
      assert.equal(loadState(statePath).highWaterMark, 2, 'the mark neither moved nor lowered');
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });

  test('a malformed state file is a refusal, never a reset to zero', () => {
    const dir = fixtureRepo();
    const { statePath } = statePathIn();
    try {
      writeFileSync(statePath, '{"highWaterMark": ');
      const { descriptor } = descriptorFor(dir, { releaseVersion: 1 });
      const sig = signUpdate(descriptor, PRIVATE_PEM);
      const result = applyUpdate(descriptor, sig, { publicKeyPem: PUBLIC_PEM, repoRoot: dir, statePath });
      assert.equal(result.ok, false);
      assert.equal(result.reason, 'state-malformed');
      assert.match(readFileSync(statePath, 'utf8'), /highWaterMark/, 'the corrupt file is not overwritten');
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });
});

describe('Staged rollout: canary, promotion, sticky halt', () => {
  test('a failing health signal halts the rollout and the halt is sticky', () => {
    const dir = fixtureRepo();
    const { statePath } = statePathIn();
    try {
      const { descriptor } = descriptorFor(dir, { releaseVersion: 1, stages: [10, 50, 100] });
      const sig = signUpdate(descriptor, PRIVATE_PEM);
      assert.equal(applyUpdate(descriptor, sig, { publicKeyPem: PUBLIC_PEM, repoRoot: dir, statePath }).ok, true);

      const halted = promoteUpdate({ statePath, healthOk: false });
      assert.equal(halted.ok, false);
      assert.equal(halted.reason, 'halted');
      assert.equal(halted.state?.rollout.status, 'halted');
      assert.equal(halted.state?.rollout.haltReason, 'health-check-failed');

      const afterHalt = promoteUpdate({ statePath, healthOk: true });
      assert.equal(afterHalt.ok, false, 'a passing signal must not clear a halt by itself');
      assert.equal(afterHalt.reason, 'halted');
      assert.equal(afterHalt.state?.rollout.status, 'halted');
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });

  test('promotion advances one stage per pass and reaches promoted exactly at the last stage', () => {
    const dir = fixtureRepo();
    const { statePath } = statePathIn();
    try {
      const { descriptor } = descriptorFor(dir, { releaseVersion: 1, stages: [10, 50, 100] });
      const sig = signUpdate(descriptor, PRIVATE_PEM);
      applyUpdate(descriptor, sig, { publicKeyPem: PUBLIC_PEM, repoRoot: dir, statePath });

      const s1 = promoteUpdate({ statePath, healthOk: true });
      assert.equal(s1.ok, true);
      assert.equal(s1.state?.rollout.status, 'canary', '50% is still not full rollout');
      assert.equal(s1.state?.rollout.stageIndex, 1);

      const s2 = promoteUpdate({ statePath, healthOk: true });
      assert.equal(s2.ok, true);
      assert.equal(s2.state?.rollout.status, 'promoted', 'reaching the final stage is the promotion');
      assert.equal(s2.state?.rollout.stageIndex, 2);
      assert.equal(s2.state?.current?.releaseVersion, 1);

      const done = promoteUpdate({ statePath, healthOk: true });
      assert.equal(done.ok, false);
      assert.equal(done.reason, 'no-pending-rollout');
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });

  test('promote with no rollout in flight refuses — there is no default-healthy path', () => {
    const { statePath } = statePathIn();
    const result = promoteUpdate({ statePath, healthOk: true });
    assert.equal(result.ok, false);
    assert.equal(result.reason, 'no-pending-rollout');
  });
});

describe('Emergency rollback: signed, single-use, mark preserved', () => {
  function appliedPair(dir: string, statePath: string): { v1sig: string; v2sig: string; v1: UpdateDescriptor; v2: UpdateDescriptor } {
    const v1 = descriptorFor(dir, { releaseVersion: 1 });
    const v2 = descriptorFor(dir, { releaseVersion: 2 });
    const v1sig = signUpdate(v1.descriptor, PRIVATE_PEM);
    const v2sig = signUpdate(v2.descriptor, PRIVATE_PEM);
    assert.equal(applyUpdate(v1.descriptor, v1sig, { publicKeyPem: PUBLIC_PEM, repoRoot: dir, statePath }).ok, true);
    assert.equal(applyUpdate(v2.descriptor, v2sig, { publicKeyPem: PUBLIC_PEM, repoRoot: dir, statePath }).ok, true);
    return { v1sig, v2sig, v1: v1.descriptor, v2: v2.descriptor };
  }

  test('a signed grant moves current back without lowering the mark, and cannot be replayed', () => {
    const dir = fixtureRepo();
    const { statePath } = statePathIn();
    try {
      appliedPair(dir, statePath);
      const grant: RollbackGrant = {
        type: 'asl-rollback-grant', version: 1,
        targetVersion: 1, fromVersion: 2, generation: 0,
        reason: 'canary regression', issuedAt: '2026-10-01T00:00:00.000Z', issuedBy: 'h12-test',
      };
      const grantSig = signRollbackGrant(grant, PRIVATE_PEM);
      const rolled = rollbackUpdate(grant, grantSig, { publicKeyPem: PUBLIC_PEM, statePath });
      assert.equal(rolled.ok, true, rolled.reason);
      assert.equal(rolled.state?.current?.releaseVersion, 1);
      assert.equal(rolled.state?.highWaterMark, 2, 'the mark never lowers');
      assert.equal(rolled.state?.rollout.status, 'none');

      const replay = rollbackUpdate(grant, grantSig, { publicKeyPem: PUBLIC_PEM, statePath });
      assert.equal(replay.ok, false, 'the grant names the exact from-version and works once');
      assert.equal(replay.reason, 'grant-mismatch');
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });

  test('a burned version stays burned after rollback: re-apply refused, the next version applies', () => {
    const dir = fixtureRepo();
    const { statePath } = statePathIn();
    try {
      const { v1, v1sig, v2, v2sig } = appliedPair(dir, statePath);
      const grant: RollbackGrant = {
        type: 'asl-rollback-grant', version: 1,
        targetVersion: 1, fromVersion: 2, generation: 0,
        reason: 'regression', issuedAt: '2026-10-01T00:00:00.000Z', issuedBy: 'h12-test',
      };
      rollbackUpdate(grant, signRollbackGrant(grant, PRIVATE_PEM), { publicKeyPem: PUBLIC_PEM, statePath });

      const reapplied = applyUpdate(v2, v2sig, { publicKeyPem: PUBLIC_PEM, repoRoot: dir, statePath });
      assert.equal(reapplied.ok, false);
      assert.equal(reapplied.reason, 'rollback-blocked', 'the version rolled back FROM cannot be re-applied');

      const v3 = descriptorFor(dir, { releaseVersion: 3 });
      const v3sig = signUpdate(v3.descriptor, PRIVATE_PEM);
      const next = applyUpdate(v3.descriptor, v3sig, { publicKeyPem: PUBLIC_PEM, repoRoot: dir, statePath });
      assert.equal(next.ok, true, next.reason);
      assert.equal(next.state?.highWaterMark, 3);
      assert.ok(v1.releaseVersion === 1 && v1sig.length > 0, 'v1 fixture was used');
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });

  test('a used grant stays used: re-arriving at its from-version does not revive it (audit 01)', () => {
    const dir = fixtureRepo();
    const { statePath } = statePathIn();
    try {
      appliedPair(dir, statePath); // current v2, mark 2, generation 0
      const grantA: RollbackGrant = {
        type: 'asl-rollback-grant', version: 1,
        targetVersion: 1, fromVersion: 2, generation: 0,
        reason: 'first rollback', issuedAt: '2026-10-01T00:00:00.000Z', issuedBy: 'h12-test',
      };
      const grantASig = signRollbackGrant(grantA, PRIVATE_PEM);
      assert.equal(rollbackUpdate(grantA, grantASig, { publicKeyPem: PUBLIC_PEM, statePath }).ok, true);

      for (const releaseVersion of [3, 4]) {
        const next = descriptorFor(dir, { releaseVersion });
        const applied = applyUpdate(next.descriptor, signUpdate(next.descriptor, PRIVATE_PEM), { publicKeyPem: PUBLIC_PEM, repoRoot: dir, statePath });
        assert.equal(applied.ok, true, applied.reason);
      }

      const grantB: RollbackGrant = {
        type: 'asl-rollback-grant', version: 1,
        targetVersion: 2, fromVersion: 4, generation: 1,
        reason: 'second rollback', issuedAt: '2026-10-01T00:00:00.000Z', issuedBy: 'h12-test',
      };
      const viaB = rollbackUpdate(grantB, signRollbackGrant(grantB, PRIVATE_PEM), { publicKeyPem: PUBLIC_PEM, statePath });
      assert.equal(viaB.ok, true, viaB.reason);
      assert.equal(viaB.state?.current?.releaseVersion, 2, 'current is back at grant A\'s from-version');

      const replayA = rollbackUpdate(grantA, grantASig, { publicKeyPem: PUBLIC_PEM, statePath });
      assert.equal(replayA.ok, false, 'a used grant must not revive when its from-version becomes current again');
      assert.equal(replayA.reason, 'grant-mismatch');
      assert.equal(loadState(statePath).current?.releaseVersion, 2, 'the replayed grant mutated nothing');

      const grantC: RollbackGrant = {
        type: 'asl-rollback-grant', version: 1,
        targetVersion: 1, fromVersion: 2, generation: 2,
        reason: 'fresh grant', issuedAt: '2026-10-01T00:00:00.000Z', issuedBy: 'h12-test',
      };
      const fresh = rollbackUpdate(grantC, signRollbackGrant(grantC, PRIVATE_PEM), { publicKeyPem: PUBLIC_PEM, statePath });
      assert.equal(fresh.ok, true, 'a fresh grant at the current generation still works');
      assert.equal(fresh.state?.current?.releaseVersion, 1);
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });

  test('grant refusals are distinct: structure, signature, key, target direction', () => {
    const dir = fixtureRepo();
    const { statePath } = statePathIn();
    try {
      appliedPair(dir, statePath);
      const base: RollbackGrant = {
        type: 'asl-rollback-grant', version: 1,
        targetVersion: 1, fromVersion: 2, generation: 0,
        reason: 'r', issuedAt: '2026-10-01T00:00:00.000Z', issuedBy: 'h12-test',
      };
      const sig = signRollbackGrant(base, PRIVATE_PEM);
      assert.equal(rollbackUpdate({ ...base, type: 'evil' }, sig, { publicKeyPem: PUBLIC_PEM, statePath }).reason, 'not-a-rollback-grant');
      assert.equal(rollbackUpdate({ ...base, targetVersion: '1' }, sig, { publicKeyPem: PUBLIC_PEM, statePath }).reason, 'not-a-rollback-grant');
      assert.equal(rollbackUpdate(base, 'AAAA', { publicKeyPem: PUBLIC_PEM, statePath }).reason, 'bad-grant-signature');
      assert.equal(rollbackUpdate(base, sig, { publicKeyPem: '', statePath }).reason, 'no-verification-key');

      const forward = { ...base, targetVersion: 2 };
      assert.equal(
        rollbackUpdate(forward, signRollbackGrant(forward, PRIVATE_PEM), { publicKeyPem: PUBLIC_PEM, statePath }).reason,
        'grant-mismatch',
        'rollback must go backward — a properly signed but forward grant still refuses',
      );
      const wrongFrom = { ...base, fromVersion: 1 };
      assert.equal(
        rollbackUpdate(wrongFrom, signRollbackGrant(wrongFrom, PRIVATE_PEM), { publicKeyPem: PUBLIC_PEM, statePath }).reason,
        'grant-mismatch',
        'from-version must be the current one',
      );
      assert.equal(loadState(statePath).current?.releaseVersion, 2, 'no refusal mutated the state');
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });
});

describe('Structural invariants (the new trust boundary)', () => {
  test('state, descriptor, and grant carry no key material; refusals echo no secrets', () => {
    const dir = fixtureRepo();
    const { statePath } = statePathIn();
    try {
      const { descriptor } = descriptorFor(dir, { releaseVersion: 1 });
      const sig = signUpdate(descriptor, PRIVATE_PEM);
      applyUpdate(descriptor, sig, { publicKeyPem: PUBLIC_PEM, repoRoot: dir, statePath });

      const stateOnDisk = readFileSync(statePath, 'utf8');
      const grant: RollbackGrant = {
        type: 'asl-rollback-grant', version: 1,
        targetVersion: 1, fromVersion: 1, generation: 0,
        reason: 'x', issuedAt: '2026-10-01T00:00:00.000Z', issuedBy: 'h12-test',
      };
      const grantSig = signRollbackGrant(grant, PRIVATE_PEM);
      for (const [label, blob] of [
        ['state', stateOnDisk],
        ['descriptor', JSON.stringify(descriptor)],
        ['grant', JSON.stringify(grant)],
        ['descriptor-sig', sig],
        ['grant-sig', grantSig],
      ] as const) {
        assert.ok(!blob.includes('PRIVATE KEY'), `${label} must not carry private key material`);
        assert.ok(!blob.includes('BEGIN '), `${label} must not carry PEM headers`);
        assert.ok(!blob.includes(PRIVATE_PEM.slice(40, 120)), `${label} must not carry the private key body`);
      }

      const state = loadState(statePath);
      assert.deepEqual(
        Object.keys(state).sort(),
        ['current', 'highWaterMark', 'rollbackGeneration', 'rollout', 'type', 'version'],
        'state shape is exactly the declared contract',
      );

      const refusals = [
        verifyDescriptor({ type: 'x' }, 'sig', ''),
        verifyUpdate({ type: 'x' }, 'sig', { publicKeyPem: 'bad', repoRoot: dir }),
        rollbackUpdate({ type: 'x' }, 'sig', { publicKeyPem: 'bad', statePath }),
      ];
      for (const r of refusals) {
        const text = `${r.reason ?? ''} ${r.detail ?? ''}`;
        assert.ok(!text.includes('PRIVATE'), `refusal must not echo key material: ${text}`);
        assert.ok(!text.includes('BEGIN'), `refusal must not echo PEM: ${text}`);
      }
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });

  test('a missing state file yields the initial state — first use starts at zero', () => {
    const state = loadState(join(import.meta.dirname, 'no-such-state.json'));
    assert.equal(state.highWaterMark, 0);
    assert.equal(state.current, null);
    assert.equal(state.rollout.status, 'none');
  });
});