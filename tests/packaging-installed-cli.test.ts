/**
 * Packaging: the installed CLI must start.
 *
 * `bin/aisl.mjs` used to import `src/cli.ts`. Node strips types for a plain
 * `.ts` entry, but refuses to do so under `node_modules`
 * (`ERR_UNSUPPORTED_NODE_MODULES_TYPE_STRIPPING`), so `npm i aisl` installed a
 * CLI that could not start. The package now ships `dist/` (ticket 01,
 * ADR-044).
 *
 * This test stages the installed layout by hand instead of running
 * `npm install`, so it is offline and deterministic: it copies the `files`
 * allowlist, the launcher, the compiled output, and the two runtime
 * dependencies into `<tmp>/node_modules/`, then runs `aisl demo` from there.
 *
 * The staged package gets a `git init` because demo sections 20-21 digest the
 * committed tree (`computeTreeDigest`, ADR-024) and refuse to run outside a
 * repository. That is a property of the demo, not of the package: without a
 * `.git` the CLI still starts, but section 20 reports FAIL and exits 1.
 */

import { describe, test } from 'node:test';
import assert from 'node:assert/strict';
import { cpSync, existsSync, mkdirSync, mkdtempSync, readFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join } from 'node:path';
import { spawnSync } from 'node:child_process';
import { git, gitEnv } from './helpers/git.ts';

const REPO_ROOT = join(import.meta.dirname, '..');
const RUNTIME_DEPS = ['jose', 'postgres'];

const pkg = JSON.parse(readFileSync(join(REPO_ROOT, 'package.json'), 'utf8')) as {
  name: string;
  files: string[];
  version: string;
};

/** Windows keeps a handle on a just-exited child's cwd; EPERM here is noise, not a failure. */
function removeQuietly(dir: string): void {
  try {
    // fs.rm retries EBUSY/EPERM itself; the catch is the last resort.
    rmSync(dir, { recursive: true, force: true, maxRetries: 5, retryDelay: 100 });
  } catch (error) {
    const code = (error as NodeJS.ErrnoException).code;
    if (code !== 'EPERM' && code !== 'EBUSY') throw error;
  }
}

function buildIfNeeded(): void {
  if (existsSync(join(REPO_ROOT, 'dist', 'cli.js'))) return;
  const built = spawnSync('npm', ['run', 'build'], {
    cwd: REPO_ROOT,
    encoding: 'utf8',
    shell: true,
  });
  assert.equal(built.status, 0, `npm run build failed:\n${built.stdout}\n${built.stderr}`);
}

function stageInstall(root: string): string {
  const pkgDir = join(root, 'node_modules', ...pkg.name.split('/'));
  mkdirSync(dirname(pkgDir), { recursive: true });
  // npm always ships package.json even though `files` does not name it.
  cpSync(join(REPO_ROOT, 'package.json'), join(pkgDir, 'package.json'));
  for (const entry of pkg.files) {
    const from = join(REPO_ROOT, entry);
    if (!existsSync(from)) continue;
    cpSync(from, join(pkgDir, entry), { recursive: true });
  }
  for (const dep of RUNTIME_DEPS) {
    cpSync(join(REPO_ROOT, 'node_modules', dep), join(root, 'node_modules', dep), { recursive: true });
  }
  return pkgDir;
}

describe('packaging: installed CLI', () => {
  test('a staged node_modules install runs `aisl demo` to completion', () => {
    buildIfNeeded();
    assert.ok(existsSync(join(REPO_ROOT, 'dist', 'cli.js')), 'dist/cli.js exists before staging');

    const stage = mkdtempSync(join(tmpdir(), 'asl-pack-'));
    try {
      const pkgDir = stageInstall(stage);
      assert.ok(existsSync(join(pkgDir, 'dist', 'cli.js')), 'dist/cli.js is in the staged package');
      git(['init', '--initial-branch=main'], pkgDir);

      const run = spawnSync(process.execPath, [join(pkgDir, 'bin', 'aisl.mjs'), 'demo'], {
        cwd: stage,
        encoding: 'utf8',
        env: gitEnv(),
      });

      assert.equal(run.status, 0, `staged CLI exited ${run.status}:\n${run.stdout}\n${run.stderr}`);
      assert.match(run.stdout, /MVP DEMO/, 'the demo ran from the installed layout');
      assert.match(run.stdout, /20\. H10: supply-chain gate/, 'the run reached the supply-chain section');
      assert.doesNotMatch(run.stderr, /ERR_UNSUPPORTED_NODE_MODULES_TYPE_STRIPPING/);
    } finally {
      removeQuietly(stage);
    }
  });
});
