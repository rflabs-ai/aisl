/**
 * Git for test fixtures.
 *
 * A git hook exports GIT_DIR, GIT_WORK_TREE and GIT_INDEX_FILE. A fixture that
 * shells out to git in a temp directory must not inherit them, or it operates
 * on the caller's repository instead of its own (docs/safety/05-hook-git-dir.md).
 * Every fixture goes through this helper: cwd is explicit and the redirecting
 * variables are removed.
 */

import { spawnSync } from 'node:child_process';

export const GIT_ENV_VARS = [
  'GIT_DIR',
  'GIT_WORK_TREE',
  'GIT_INDEX_FILE',
  'GIT_OBJECT_DIRECTORY',
  'GIT_ALTERNATE_OBJECT_DIRECTORIES',
] as const;

/** The caller's environment with every repository-redirecting GIT_* variable removed. */
export function gitEnv(base: NodeJS.ProcessEnv = process.env): NodeJS.ProcessEnv {
  const env: NodeJS.ProcessEnv = { ...base };
  for (const name of GIT_ENV_VARS) delete env[name];
  return env;
}

/** Run git in `cwd` with an isolated environment. Throws on a nonzero exit. */
export function git(args: readonly string[], cwd: string): string {
  const r = spawnSync('git', args, { cwd, encoding: 'utf8', env: gitEnv() });
  if (r.error) throw new Error(`git ${args.join(' ')} failed to run in ${cwd}: ${r.error.message}`);
  if (r.status !== 0) throw new Error(`git ${args.join(' ')} exited ${r.status ?? 'unknown'} in ${cwd}: ${r.stderr}`);
  return r.stdout ?? '';
}
