/**
 * Verification pipeline: command checks over agent-produced artifacts.
 *
 * Authorization answers "may this happen?". A command check answers "did the
 * produced artifact stay inside the lines?" — it runs a configured command
 * against the artifact and its verdict flows through the existing
 * `runVerifications` path (a failed check marks the step errored; no new
 * authority is introduced here).
 *
 * Security invariants:
 *   - The command is an argv array executed WITHOUT a shell. Artifact content
 *     reaches the command via stdin only; it is never interpolated into argv.
 *   - The allowlist is enforced at configuration time: a check naming a
 *     non-allowlisted executable cannot be constructed.
 *   - The command runs with a minimal environment (no ambient secrets) and a
 *     temporary working directory.
 *
 * ponytail: evidence carries exit status only; redacted diagnostics when a
 * deployment needs them.
 */

import { spawnSync } from 'node:child_process';
import { tmpdir } from 'node:os';
import { type Check, type CheckContext, type VerificationResult } from './verification.ts';

export interface CommandCheckConfig {
  readonly name: string;
  /** argv[0] is the executable; the rest are fixed arguments. */
  readonly argv: readonly [string, ...string[]];
  /** Exact executable names permitted. A check outside it is refused at configuration time. */
  readonly allowlist: readonly string[];
  /** Kill the command after this long; the check then fails. Default 10s. */
  readonly timeoutMs?: number;
}

export class CommandCheck implements Check {
  readonly name: string;
  readonly command: string;
  private readonly cfg: CommandCheckConfig;

  constructor(cfg: CommandCheckConfig) {
    if (cfg.argv.length === 0) throw new Error(`command check '${cfg.name}': argv is empty`);
    if (cfg.allowlist.length === 0) throw new Error(`command check '${cfg.name}': allowlist is empty`);
    if (!cfg.allowlist.includes(cfg.argv[0]!)) {
      throw new Error(`command check '${cfg.name}': command '${cfg.argv[0]}' is not allowlisted`);
    }
    this.cfg = cfg;
    this.name = cfg.name;
    this.command = JSON.stringify([...cfg.argv]);
  }

  run(ctx: CheckContext): { readonly result: VerificationResult; readonly evidence: string } {
    const timeoutMs = this.cfg.timeoutMs ?? 10_000;
    const artifact = typeof ctx.output === 'string' ? ctx.output : JSON.stringify(ctx.output ?? null);
    // Minimal environment: the command must not inherit ambient secrets.
    const env: Record<string, string> = { PATH: process.env.PATH ?? '' };
    if (process.platform === 'win32' && process.env.SYSTEMROOT) env.SYSTEMROOT = process.env.SYSTEMROOT;

    const r = spawnSync(this.cfg.argv[0]!, [...this.cfg.argv.slice(1)], {
      input: artifact,
      timeout: timeoutMs,
      killSignal: 'SIGKILL',
      encoding: 'utf8',
      cwd: tmpdir(),
      env,
    });

    if (r.status === 0) return { result: 'pass', evidence: 'exit=0' };
    if (r.status !== null) return { result: 'fail', evidence: `exit=${r.status}` };
    if (r.signal !== null) return { result: 'fail', evidence: `timed out after ${timeoutMs}ms (signal ${r.signal})` };
    return { result: 'error', evidence: 'command not found' };
  }
}
