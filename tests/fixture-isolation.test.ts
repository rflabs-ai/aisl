/**
 * Regression: git fixtures must isolate themselves from the caller.
 *
 * A git hook exports GIT_DIR, GIT_WORK_TREE and GIT_INDEX_FILE. A fixture that
 * shells out to git in a temp directory used to inherit them and operate on the
 * real checkout instead of its own (docs/safety/05-hook-git-dir.md). Every
 * fixture now goes through tests/helpers/git.ts, which strips those variables
 * and sets cwd explicitly.
 */

import { describe, test } from 'node:test';
import assert from 'node:assert/strict';
import { existsSync, mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { GIT_ENV_VARS, git, gitEnv } from './helpers/git.ts';

const REPO_ROOT = join(import.meta.dirname, '..');

describe('git fixture isolation', () => {
  test('a fixture commit lands in its own repo while the caller exports GIT_DIR and GIT_WORK_TREE', () => {
    const poison = mkdtempSync(join(tmpdir(), 'asl-poison-'));
    const repo = mkdtempSync(join(tmpdir(), 'asl-iso-'));
    const saved = { GIT_DIR: process.env.GIT_DIR, GIT_WORK_TREE: process.env.GIT_WORK_TREE };
    const realHeadBefore = git(['rev-parse', 'HEAD'], REPO_ROOT).trim();
    try {
      process.env.GIT_DIR = join(poison, 'bogus.git');
      process.env.GIT_WORK_TREE = join(poison, 'bogus-worktree');

      git(['init', '--initial-branch=main'], repo);
      git(['config', 'user.name', 'test'], repo);
      git(['config', 'user.email', 'test@example.com'], repo);
      writeFileSync(join(repo, 'hello.txt'), 'hello from the isolated fixture\n');
      git(['add', '.'], repo);
      git(['commit', '--no-gpg-sign', '-m', 'isolated fixture commit'], repo);

      assert.match(git(['rev-parse', 'HEAD'], repo).trim(), /^[0-9a-f]{40}$/);
      assert.equal(git(['log', '-1', '--format=%s'], repo).trim(), 'isolated fixture commit');
      assert.equal(existsSync(join(poison, 'bogus.git')), false, 'the poisoned GIT_DIR was never created');
      assert.equal(git(['rev-parse', 'HEAD'], REPO_ROOT).trim(), realHeadBefore, 'the real repository did not move');
    } finally {
      if (saved.GIT_DIR === undefined) delete process.env.GIT_DIR;
      else process.env.GIT_DIR = saved.GIT_DIR;
      if (saved.GIT_WORK_TREE === undefined) delete process.env.GIT_WORK_TREE;
      else process.env.GIT_WORK_TREE = saved.GIT_WORK_TREE;
      rmSync(poison, { recursive: true, force: true });
      rmSync(repo, { recursive: true, force: true });
    }
  });

  test('the helper strips every variable that redirects git at another repository', () => {
    const env = gitEnv({
      ...process.env,
      GIT_DIR: 'x',
      GIT_WORK_TREE: 'x',
      GIT_INDEX_FILE: 'x',
      GIT_OBJECT_DIRECTORY: 'x',
      GIT_ALTERNATE_OBJECT_DIRECTORIES: 'x',
    });
    for (const name of GIT_ENV_VARS) assert.equal(name in env, false, `${name} must not reach the fixture`);
  });
});
