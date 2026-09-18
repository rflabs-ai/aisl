/**
 * Stage-0 Git integration: read-only repository access over the installed
 * `git` CLI (ADR-020).
 *
 * Security invariants:
 *   - The verb set is an allowlist enforced at CONFIGURATION time: `log`,
 *     `show`, `diff`, `status`. A write or network verb (commit, push,
 *     fetch, clone, submodule, ...) cannot be constructed — the constructor
 *     refuses it, so the refusal does not depend on call-site discipline.
 *   - The command is an argv array executed WITHOUT a shell (the
 *     `CommandCheck` posture, src/check-command.ts). Nothing is interpolated.
 *   - The repo root is the configured boundary: arguments that name paths
 *     outside it (absolute paths, `..` segments) or escape hatches
 *     (`--no-index`, `--git-dir`, `--work-tree`, `-C`, ...) are refused
 *     before spawn.
 *   - Output is UNTRUSTED content: it returns as a string and enters the
 *     ingestion pipeline (src/ingestion.ts) as a document labeled with the
 *     repository's classification. No path from output text to authority
 *     exists (ADR-011 / invariant 3).
 *
 * ponytail: `..` is refused even inside revision ranges (`A..B`), which is
 * over-broad for that one idiom — the upgrade path is range-aware parsing,
 * not a weaker default.
 */

import { spawnSync } from 'node:child_process';
import { existsSync } from 'node:fs';
import { resolve } from 'node:path';

export type GitVerb = 'log' | 'show' | 'diff' | 'status';

export const GIT_READ_VERBS: readonly GitVerb[] = ['log', 'show', 'diff', 'status'];

export interface GitReaderConfig {
  /** The repository working tree. Traversal outside it is refused. */
  readonly repoRoot: string;
  /**
   * Permitted verbs; every entry must be a read verb. Runtime-validated at
   * construction (the CommandCheck precedent) so a JS caller — or a hostile
   * config object that dodged the TS type — still cannot construct a writer.
   * Default: all read verbs.
   */
  readonly allowlist?: readonly string[];
  /** Kill the process after this long; the read then fails. Default 10s. */
  readonly timeoutMs?: number;
}

/** Flags that redirect git at paths/objects outside the configured root. */
const FORBIDDEN_FLAGS = new Set([
  '--no-index',
  '--git-dir',
  '--work-tree',
  '--exec-path',
  '--super-prefix',
  '--namespace',
  '-C',
  '-c',
]);

function assertSafeArg(arg: string): void {
  if (FORBIDDEN_FLAGS.has(arg)) {
    throw new Error(`git argument refused (root-escape hatch): ${arg}`);
  }
  if (arg.includes('..')) {
    throw new Error(`git argument refused (path traversal): ${arg}`);
  }
  // `rev:path` syntax (git show/log): the part after the first colon is a path too.
  for (const candidate of [arg, ...(/:/.test(arg) ? [arg.slice(arg.indexOf(':') + 1)] : [])]) {
    if (/^([a-zA-Z]:[\\/]|\\\\|\/)/.test(candidate)) {
      throw new Error(`git argument refused (absolute path outside the repository): ${arg}`);
    }
  }
}

export class GitReader {
  readonly repoRoot: string;
  readonly verbs: readonly GitVerb[];
  private readonly timeoutMs: number;

  constructor(cfg: GitReaderConfig) {
    const verbs = cfg.allowlist ?? GIT_READ_VERBS;
    if (verbs.length === 0) throw new Error('git reader: allowlist is empty');
    for (const verb of verbs) {
      if (!GIT_READ_VERBS.includes(verb as GitVerb)) {
        throw new Error(`git reader: verb '${verb}' is not a read verb — refused at configuration time (allowed: ${GIT_READ_VERBS.join(', ')})`);
      }
    }
    this.repoRoot = resolve(cfg.repoRoot);
    // Proven by the loop above: every entry is a member of GIT_READ_VERBS.
    this.verbs = [...verbs] as GitVerb[];
    this.timeoutMs = cfg.timeoutMs ?? 10_000;
  }

  /**
   * Run one allowlisted read verb. Returns stdout as hostile content —
   * the caller feeds it to the ingestion pipeline; it is never authority.
   * Git not installed, a missing repository, or a timeout all throw.
   */
  run(verb: GitVerb, args: readonly string[] = []): string {
    if (!this.verbs.includes(verb)) {
      throw new Error(`git reader: verb '${verb}' is not allowlisted for this reader`);
    }
    for (const arg of args) assertSafeArg(arg);
    if (!existsSync(this.repoRoot)) throw new Error(`git reader: repository root does not exist: ${this.repoRoot}`);

    // Minimal environment: the command must not inherit ambient secrets.
    const env: Record<string, string> = { PATH: process.env.PATH ?? '' };
    if (process.platform === 'win32' && process.env.SYSTEMROOT) env.SYSTEMROOT = process.env.SYSTEMROOT;

    const r = spawnSync('git', [verb, ...args], {
      cwd: this.repoRoot,
      timeout: this.timeoutMs,
      killSignal: 'SIGKILL',
      encoding: 'utf8',
      maxBuffer: 10_485_760,
      env,
    });
    if (r.error) throw new Error(`git reader: ${verb} failed to run: ${r.error.message}`);
    if (r.signal !== null) throw new Error(`git reader: ${verb} timed out after ${this.timeoutMs}ms`);
    if (r.status !== 0) throw new Error(`git reader: ${verb} exited ${r.status ?? 'unknown'}`);
    return r.stdout ?? '';
  }
}
