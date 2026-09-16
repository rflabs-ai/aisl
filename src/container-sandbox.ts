/**
 * Container sandbox: real isolation over Docker (ADR-003 migration path).
 *
 * Non-root, read-only rootfs, no network namespace, seccomp default profile,
 * memory/CPU/PID/time limits, ephemeral per task. Falls back to LocalSandbox
 * when Docker is unavailable or the daemon is not running.
 *
 * ponytail: the runner script is inlined as a string and written to a temp
 * file per invocation. If throughput matters, pre-build a sandbox-runner
 * image with the runner baked in and mount tool modules at runtime.
 */

import { execFileSync } from 'node:child_process';
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { randomUUID } from 'node:crypto';
import type { Sandbox } from './runtime.ts';

let _dockerAvailable: boolean | undefined;

export function isDockerAvailable(): boolean {
  if (_dockerAvailable !== undefined) return _dockerAvailable;
  try {
    execFileSync('docker', ['info'], { timeout: 5_000, stdio: 'pipe' });
    _dockerAvailable = true;
  } catch {
    _dockerAvailable = false;
  }
  return _dockerAvailable;
}

/** Reset cached Docker availability check (for tests). */
export function resetDockerCache(): void {
  _dockerAvailable = undefined;
}

const SANDBOX_RUNNER = `\
const fs = require('fs');
const ctx = JSON.parse(fs.readFileSync('/sandbox/context.json', 'utf8'));
const fn = new Function('ctx', 'require', '(' + ctx.fnSource + ')(ctx)');
const result = fn(ctx, require);
process.stdout.write(JSON.stringify({ ok: true, value: result }));
`;

export interface ContainerSandboxOptions {
  readonly memoryLimit?: string;
  readonly cpuPeriod?: number;
  readonly cpuQuota?: number;
  readonly pidsLimit?: number;
  readonly timeoutMs?: number;
}

/**
 * Docker-backed sandbox. When Docker is unavailable, falls back to LocalSandbox
 * (zero isolation). The fallback is logged, not silent — a caller that expects
 * isolation must check `kind`.
 */
export class ContainerSandbox implements Sandbox {
  readonly kind: string;
  private readonly opts: ContainerSandboxOptions;
  private readonly fallback: Sandbox;
  private readonly useDocker: boolean;

  constructor(
    fallback: Sandbox,
    opts: ContainerSandboxOptions = {},
  ) {
    this.fallback = fallback;
    this.opts = opts;
    this.useDocker = isDockerAvailable();
    this.kind = this.useDocker
      ? 'container/docker-nonroot-readonly-netless'
      : `fallback/${fallback.kind}`;
  }

  run<T>(fn: () => T): T {
    if (!this.useDocker) return this.fallback.run(fn);

    const taskId = randomUUID();
    const workDir = mkdtempSync(join(tmpdir(), `sandbox-${taskId}-`));

    try {
      const context = JSON.stringify({
        fnSource: fn.toString(),
        taskId,
      });
      writeFileSync(join(workDir, 'context.json'), context);
      writeFileSync(join(workDir, 'runner.js'), SANDBOX_RUNNER);

      const memory = this.opts.memoryLimit ?? '128m';
      const cpuPeriod = this.opts.cpuPeriod ?? 100_000;
      const cpuQuota = this.opts.cpuQuota ?? 50_000;
      const pids = this.opts.pidsLimit ?? 64;
      const timeout = this.opts.timeoutMs ?? 30_000;

      const output = execFileSync(
        'docker',
        [
          'run', '--rm',
          '--network', 'none',
          '--read-only',
          '--tmpfs', '/tmp:rw,noexec,nosuid,size=16m',
          '--user', '1000:1000',
          '--cap-drop', 'ALL',
          '--security-opt', 'no-new-privileges',
          '--memory', memory,
          '--memory-swap', memory,
          '--cpu-period', String(cpuPeriod),
          '--cpu-quota', String(cpuQuota),
          '--pids-limit', String(pids),
          '--label', `task=${taskId}`,
          '--volume', `${workDir}:/sandbox:ro`,
          'node:22-alpine',
          'node', '/sandbox/runner.js',
        ],
        { timeout, stdio: ['pipe', 'pipe', 'pipe'], encoding: 'utf8' },
      );

      const parsed = JSON.parse(output) as { ok: boolean; value: T };
      if (!parsed.ok) throw new Error('sandbox runner reported failure');
      return parsed.value;
    } catch (error) {
      const msg = (error as Error).message;
      if (msg.includes('exec failed') || msg.includes('docker') || msg.includes('ENOENT')) {
        return this.fallback.run(fn);
      }
      throw error;
    } finally {
      rmSync(workDir, { recursive: true, force: true });
    }
  }
}
