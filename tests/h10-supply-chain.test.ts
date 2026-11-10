/**
 * H10 acceptance: signed builds and supply-chain security (ADR-024).
 *
 * The SBOM is deterministic and complete; pins are exact; the lockfile
 * integrity is verified; the drift gate catches any dependency change that
 * was not reviewed into the committed baseline; the tree digest is
 * platform-independent (blob SHAs) and stale-detecting; the build manifest
 * binds source + dependencies + gate result under an Ed25519 signature and
 * verification is fail-closed with distinct reasons.
 *
 * These tests were written BEFORE src/supply-chain.ts existed (red-confirmed)
 * per the H10 kickoff contract.
 */

import { describe, test } from 'node:test';
import assert from 'node:assert/strict';
import { generateKeyPairSync, type KeyObject } from 'node:crypto';
import { mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { git } from './helpers/git.ts';
import { canonicalJson } from '../src/domain.ts';
import {
  ADMITTED_RUNTIME_DEPS,
  computeSbom,
  computeTreeDigest,
  checkPins,
  checkLockfileIntegrity,
  checkRuntimeAllowlist,
  runSupplyChainGate,
  sbomDigest,
  signManifest,
  verifyManifest,
  type BuildManifest,
} from '../src/supply-chain.ts';

const REPO_ROOT = join(import.meta.dirname, '..');

function pemOf(key: KeyObject): string {
  const exported = key.type === 'private'
    ? key.export({ type: 'pkcs8', format: 'pem' })
    : key.export({ type: 'spki', format: 'pem' });
  return typeof exported === 'string' ? exported : exported.toString('utf8');
}

describe('SBOM generation (H10)', () => {
  test('is deterministic: two runs produce identical canonical bytes', () => {
    const a = computeSbom(REPO_ROOT);
    const b = computeSbom(REPO_ROOT);
    assert.equal(canonicalJson(a), canonicalJson(b));
  });

  test('covers direct and transitive dependencies with integrity + registry URLs', () => {
    const sbom = computeSbom(REPO_ROOT);
    assert.equal(sbom.format, 'ASL-SBOM');
    const byName = new Map(sbom.packages.map((p) => [p.name, p]));
    for (const name of ['jose', 'postgres', 'typescript', '@types/node', 'undici-types']) {
      assert.ok(byName.has(name), `sbom must list ${name}`);
    }
    const jose = byName.get('jose')!;
    assert.equal(jose.direct, true, 'jose is a direct runtime dep');
    assert.equal(jose.dev, false);
    const typescript = byName.get('typescript')!;
    assert.equal(typescript.direct, true, 'typescript is a direct dev dep');
    assert.equal(typescript.dev, true);
    const undici = byName.get('undici-types')!;
    assert.equal(undici.direct, false, 'undici-types is transitive');
    for (const entry of sbom.packages) {
      assert.match(entry.integrity, /^sha512-/, `${entry.name} carries a sha512 integrity hash`);
      assert.match(entry.resolved, /^https:\/\/registry\.npmjs\.org\//, `${entry.name} resolves to the registry`);
      assert.match(entry.version, /^\d+\.\d+\.\d+/);
    }
    assert.ok(sbom.packages.length >= 10, 'the lockfile inventory is non-trivial');
  });
});

describe('Pinning + hash verification', () => {
  test('the committed package.json uses exact pins (the rule this milestone introduces)', () => {
    const manifest = JSON.parse(readFileSync(join(REPO_ROOT, 'package.json'), 'utf8'));
    assert.deepEqual(checkPins(manifest), []);
  });

  test('range pins are refused, each violation naming the dependency', () => {
    const violations = checkPins({
      dependencies: { jose: '^6.2.12' },
      devDependencies: { typescript: '~7.0.2', star: '*', ge: '>=1.0.0', wildcard: '1.2.x' },
    });
    assert.equal(violations.length, 5);
    for (const dep of ['jose', 'typescript', 'star', 'ge', 'wildcard']) {
      assert.ok(violations.some((v) => v.includes(`'${dep}'`)), `violation names ${dep}: ${violations.join(' | ')}`);
    }
  });

  test('the committed lockfile passes integrity + registry verification', () => {
    const manifest = JSON.parse(readFileSync(join(REPO_ROOT, 'package.json'), 'utf8'));
    const lockfile = JSON.parse(readFileSync(join(REPO_ROOT, 'package-lock.json'), 'utf8'));
    assert.deepEqual(checkLockfileIntegrity(lockfile, manifest), []);
    assert.deepEqual(checkRuntimeAllowlist(manifest), []);
  });

  test('a stripped integrity hash or a non-registry resolved URL is a violation', () => {
    const manifest = { dependencies: { jose: '6.2.12' }, devDependencies: {} };
    const lockfile = {
      lockfileVersion: 3,
      packages: {
        '': {},
        'node_modules/jose': { version: '9.9.9', resolved: 'https://registry.npmjs.org/jose/-/jose-9.9.9.tgz', integrity: 'sha512-BBB' },
        'node_modules/evil': { version: '1.0.0', integrity: 'sha512-AAA', resolved: 'https://evil.example.com/evil-1.0.0.tgz' },
        'node_modules/naked': { version: '1.0.0', resolved: 'https://registry.npmjs.org/naked/-/naked-1.0.0.tgz' },
      },
    };
    const violations = checkLockfileIntegrity(lockfile, manifest);
    assert.ok(violations.some((v) => v.includes('naked') && v.includes('integrity')));
    assert.ok(violations.some((v) => v.includes('evil') && v.includes('registry')));
    assert.ok(
      violations.some((v) => v.includes('jose') && v.includes('does not match the exact pin')),
      'direct pin vs lockfile version mismatch is caught',
    );
  });

  test('an unadmitted runtime dependency is refused with the ADR instruction', () => {
    const violations = checkRuntimeAllowlist({ dependencies: { lodash: '4.17.21', postgres: '3.4.9' } });
    assert.equal(violations.length, 1);
    assert.match(violations[0]!, /lodash/);
    assert.match(violations[0]!, /ADR/);
    assert.ok(Object.keys(ADMITTED_RUNTIME_DEPS).length === 2, 'the admitted set is exactly the two ADR-admitted deps');
  });
});

describe('Drift gate', () => {
  function fixtureRepo(dir: string, extra?: string): void {
    const deps = { jose: '6.2.12' };
    const packages: Record<string, unknown> = {
      '': { name: 'fixture', version: '0.0.0', dependencies: deps, devDependencies: { typescript: '7.0.2' } },
      'node_modules/jose': { version: '6.2.12', resolved: 'https://registry.npmjs.org/jose/-/jose-6.2.12.tgz', integrity: 'sha512-AAAA' },
      'node_modules/typescript': { version: '7.0.2', resolved: 'https://registry.npmjs.org/typescript/-/typescript-7.0.2.tgz', integrity: 'sha512-BBBB', dev: true },
    };
    if (extra) {
      packages[`node_modules/${extra}`] = { version: '1.0.0', resolved: `https://registry.npmjs.org/${extra}/-/${extra}-1.0.0.tgz`, integrity: 'sha512-CCCC' };
    }
    mkdirSync(dir, { recursive: true });
    writeFileSync(join(dir, 'package.json'), `${JSON.stringify({ name: 'fixture', version: '0.0.0', dependencies: deps, devDependencies: { typescript: '7.0.2' } }, null, 2)}\n`);
    writeFileSync(join(dir, 'package-lock.json'), `${JSON.stringify({ name: 'fixture', version: '0.0.0', lockfileVersion: 3, requires: true, packages }, null, 2)}\n`);
  }

  function gate(dir: string): ReturnType<typeof runSupplyChainGate> {
    return runSupplyChainGate({ repoRoot: dir, baselineSbomPath: join(dir, 'artifacts', 'sbom.json') });
  }

  function writeBaseline(dir: string): void {
    mkdirSync(join(dir, 'artifacts'), { recursive: true });
    writeFileSync(join(dir, 'artifacts', 'sbom.json'), `${JSON.stringify(computeSbom(dir), null, 2)}\n`);
  }

  test('a matching baseline passes the gate', () => {
    const dir = mkdtempSync(join(tmpdir(), 'h10-clean-'));
    try {
      fixtureRepo(dir);
      writeBaseline(dir);
      const result = gate(dir);
      assert.equal(result.ok, true, result.violations.join(' | '));
      assert.equal(result.drift.changed, false);
      assert.match(result.digest, /^sha256-/);
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });

  test('an added dependency fails the gate and names the dep', () => {
    const dir = mkdtempSync(join(tmpdir(), 'h10-add-'));
    try {
      fixtureRepo(dir);
      writeBaseline(dir);
      fixtureRepo(dir, 'lodash');
      const result = gate(dir);
      assert.equal(result.ok, false);
      assert.deepEqual(result.drift.added, ['lodash']);
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });

  test('a removed dependency and a version bump are both caught', () => {
    const dir = mkdtempSync(join(tmpdir(), 'h10-chg-'));
    try {
      fixtureRepo(dir, 'lodash');
      writeBaseline(dir);
      // drop lodash, bump jose: removed + changed in one diff
      const lock = JSON.parse(readFileSync(join(dir, 'package-lock.json'), 'utf8'));
      delete lock.packages['node_modules/lodash'];
      lock.packages['node_modules/jose'].version = '6.3.0';
      writeFileSync(join(dir, 'package-lock.json'), `${JSON.stringify(lock, null, 2)}\n`);
      const result = gate(dir);
      assert.equal(result.ok, false);
      assert.deepEqual(result.drift.removed, ['lodash']);
      assert.equal(result.drift.changed, true);
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });

  test('a missing baseline is a violation with the regeneration instruction', () => {
    const dir = mkdtempSync(join(tmpdir(), 'h10-nobl-'));
    try {
      fixtureRepo(dir);
      const result = gate(dir);
      assert.equal(result.ok, false);
      assert.match(result.violations.join(' '), /baseline/);
      assert.match(result.violations.join(' '), /sbom/);
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });

  test('the committed repository state passes the gate against its committed baseline', () => {
    const result = runSupplyChainGate({
      repoRoot: REPO_ROOT,
      baselineSbomPath: join(REPO_ROOT, 'artifacts', 'sbom.json'),
    });
    assert.equal(result.ok, true, result.violations.join(' | '));
    assert.equal(result.drift.changed, false);
  });
});

describe('Tree digest (blob SHAs — platform-independent)', () => {
  function gitRepo(dir: string): void {
    mkdirSync(join(dir, 'src'), { recursive: true });
    mkdirSync(join(dir, 'artifacts'), { recursive: true });
    writeFileSync(join(dir, 'src', 'a.ts'), 'export const a = 1;\n');
    writeFileSync(join(dir, 'artifacts', 'sbom.json'), '{"format":"ASL-SBOM","version":1,"packages":[]}\n');
    git(['init', '--initial-branch=main'], dir);
    git(['add', '.'], dir);
  }

  test('is deterministic and excludes artifacts/ (outputs, not inputs)', () => {
    const dir = mkdtempSync(join(tmpdir(), 'h10-tree-'));
    try {
      gitRepo(dir);
      const d1 = computeTreeDigest(dir);
      const d2 = computeTreeDigest(dir);
      assert.equal(d1, d2);
      assert.match(d1, /^sha256-[0-9a-f]{64}$/);
      writeFileSync(join(dir, 'artifacts', 'build-manifest.json'), '{"touched":true}\n');
      git(['add', '.'], dir);
      assert.equal(computeTreeDigest(dir), d1, 'changes under artifacts/ do not change the tree digest');
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });

  test('changes when a source file changes (stale detection)', () => {
    const dir = mkdtempSync(join(tmpdir(), 'h10-stale-'));
    try {
      gitRepo(dir);
      const before = computeTreeDigest(dir);
      writeFileSync(join(dir, 'src', 'a.ts'), 'export const a = 2;\n');
      git(['add', '.'], dir);
      assert.notEqual(computeTreeDigest(dir), before);
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });
});

describe('Signed build manifest', () => {
  let dir = '';
  let privatePem = '';
  let otherPublicPem = '';
  let publicPem = '';

  function manifestFor(gate?: BuildManifest['gate']): BuildManifest {
    return {
      type: 'asl-build-manifest',
      version: 1,
      gitHead: null,
      source: { treeDigest: computeTreeDigest(dir) },
      dependencies: { sbomDigest: sbomDigest(computeSbom(dir)), runtimeDeps: ['jose'] },
      gate: gate ?? { typecheck: true, tests: true, supplyChain: true },
      issuedAt: '2026-09-28T00:00:00.000Z',
      issuedBy: 'h10-test',
    };
  }

  test('round trip: a signed manifest verifies against the same repo state', () => {
    dir = mkdtempSync(join(tmpdir(), 'h10-man-'));
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
    git(['init', '--initial-branch=main'], dir);
    git(['add', '.'], dir);

    const kp = generateKeyPairSync('ed25519');
    privatePem = pemOf(kp.privateKey);
    publicPem = pemOf(kp.publicKey);
    otherPublicPem = pemOf(generateKeyPairSync('ed25519').publicKey);

    const manifest = manifestFor();
    const sig = signManifest(manifest, privatePem);
    const verified = verifyManifest(manifest, sig, publicPem, { repoRoot: dir });
    assert.equal(verified.valid, true, verified.reason);
  });

  test('a tampered payload or a wrong verification key refuses with bad-signature', () => {
    const manifest = manifestFor();
    const sig = signManifest(manifest, privatePem);
    const tampered: BuildManifest = { ...manifest, issuedBy: 'attacker' };
    assert.deepEqual(verifyManifest(tampered, sig, publicPem, { repoRoot: dir }), { valid: false, reason: 'bad-signature' });
    assert.equal(verifyManifest(manifest, sig, otherPublicPem, { repoRoot: dir }).reason, 'bad-signature', 'a different key refuses');
    assert.equal(verifyManifest(manifest, 'AAA', publicPem, { repoRoot: dir }).reason, 'bad-signature');
  });

  test('a source change after signing refuses with stale-source', () => {
    const manifest = manifestFor();
    const sig = signManifest(manifest, privatePem);
    writeFileSync(join(dir, 'src', 'a.ts'), 'y\n');
    git(['add', '.'], dir);
    assert.deepEqual(verifyManifest(manifest, sig, publicPem, { repoRoot: dir }), { valid: false, reason: 'stale-source' });
    writeFileSync(join(dir, 'src', 'a.ts'), 'x\n');
    git(['add', '.'], dir);
    assert.equal(verifyManifest(manifest, sig, publicPem, { repoRoot: dir }).valid, true);
  });

  test('a dependency change after signing refuses with stale-dependencies', () => {
    const manifest = manifestFor();
    const sig = signManifest(manifest, privatePem);
    const lock = JSON.parse(readFileSync(join(dir, 'package-lock.json'), 'utf8'));
    lock.packages['node_modules/jose'].version = '6.3.0';
    writeFileSync(join(dir, 'package-lock.json'), `${JSON.stringify(lock, null, 2)}\n`);
    git(['add', '.'], dir);
    const result = verifyManifest(manifest, sig, publicPem, { repoRoot: dir });
    assert.equal(result.valid, false);
    assert.match(result.reason ?? '', /^stale-dependencies/);
  });

  test('a manifest whose gate did not pass refuses with gate-not-passed', () => {
    const manifest = manifestFor({ typecheck: true, tests: true, supplyChain: false });
    const sig = signManifest(manifest, privatePem);
    assert.deepEqual(verifyManifest(manifest, sig, publicPem, { repoRoot: dir }), { valid: false, reason: 'gate-not-passed' });
  });

  test('garbage key material refuses (verify) and throws (sign) — fail closed either way', () => {
    const manifest = manifestFor();
    const sig = signManifest(manifest, privatePem);
    assert.deepEqual(verifyManifest(manifest, sig, 'not a pem', { repoRoot: dir }), { valid: false, reason: 'bad-signature' });
    assert.throws(() => signManifest(manifest, 'not a pem'));
  });
});
