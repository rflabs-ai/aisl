/**
 * Git for test fixtures.
 *
 * A git hook exports GIT_DIR, GIT_WORK_TREE and GIT_INDEX_FILE. A fixture that
 * shells out to git in a temp directory must not inherit them, or it operates
 * on the caller's repository instead of its own (docs/safety/05-hook-git-dir.md).
 * Every fixture goes through this helper: cwd is explicit and every `GIT_*`
 * variable is removed. The whole prefix, not a list: `GIT_CONFIG_COUNT` and
 * `GIT_CONFIG_KEY_n`/`GIT_CONFIG_VALUE_n` can set `core.hooksPath`, and a list
 * that has to be extended is a list that will be forgotten.
 */

import { spawnSync } from 'node:child_process';

/** The redirecting variables named in the incident report, kept for documentation. */
export const GIT_ENV_VARS = [
  'GIT_DIR',
  'GIT_WORK_TREE',
  'GIT_INDEX_FILE',
  'GIT_OBJECT_DIRECTORY',
  'GIT_ALTERNATE_OBJECT_DIRECTORIES',
  'GIT_COMMON_DIR',
  'GIT_NAMESPACE',
  'GIT_CONFIG_COUNT',
] as const;

/** The caller's environment with every `GIT_*` variable removed. */
export function gitEnv(base: NodeJS.ProcessEnv = process.env): NodeJS.ProcessEnv {
  const env: NodeJS.ProcessEnv = { ...base };
  for (const name of Object.keys(env)) {
    if (name.startsWith('GIT_')) delete env[name];
  }
  return env;
}

/** Run git in `cwd` with an isolated environment. Throws on a nonzero exit. */
export function git(args: readonly string[], cwd: string): string {
  const r = spawnSync('git', args, { cwd, encoding: 'utf8', env: gitEnv() });
  if (r.error) throw new Error(`git ${args.join(' ')} failed to run in ${cwd}: ${r.error.message}`);
  if (r.status !== 0) throw new Error(`git ${args.join(' ')} exited ${r.status ?? 'unknown'} in ${cwd}: ${r.stderr}`);
  return r.stdout ?? '';
}
