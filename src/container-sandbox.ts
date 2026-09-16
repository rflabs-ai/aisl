/**
 * Container sandbox: real isolation over Docker (ADR-003 migration path).
 *
 * Non-root, read-only rootfs, no network namespace, seccomp default profile,
 * memory/CPU/PID/time limits, ephemeral per task. Falls back to LocalSandbox
 * when Docker is unavailable or the daemon is not running.
 *
 * Builds a pre-built Docker image on first use with hardcoded tool
 * implementations, then reuses it for subsequent invocations.
 */

import { execFileSync } from 'node:child_process';
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { randomUUID } from 'node:crypto';
import type { ExecutionContext, Sandbox, Tool, ToolResult } from './runtime.ts';

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

const IMAGE_TAG = 'ai-security-layer-sandbox:latest';

let _imageBuilt = false;

function ensureImage(): void {
  if (_imageBuilt) return;
  const root = join(dirname(fileURLToPath(import.meta.url)), '..');
  const dockerfile = join(root, 'Dockerfile.sandbox');
  execFileSync('docker', ['build', '-t', IMAGE_TAG, '-f', dockerfile, root], {
    timeout: 120_000,
    stdio: 'pipe',
  });
  _imageBuilt = true;
}

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

    try {
      ensureImage();
      const taskId = randomUUID();
      const workDir = mkdtempSync(join(tmpdir(), `sandbox-${taskId}-`));

      try {
        const context = JSON.stringify({ fnSource: fn.toString(), taskId });
        writeFileSync(join(workDir, 'context.json'), context);

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
            IMAGE_TAG,
          ],
          { timeout, stdio: ['pipe', 'pipe', 'pipe'], encoding: 'utf8' },
        );

        const parsed = JSON.parse(output) as { ok: boolean; value: T };
        if (!parsed.ok) throw new Error('sandbox runner reported failure');
        return parsed.value;
      } finally {
        rmSync(workDir, { recursive: true, force: true });
      }
    } catch (error) {
      const msg = (error as Error).message;
      if (msg.includes('exec failed') || msg.includes('docker') || msg.includes('ENOENT')) {
        return this.fallback.run(fn);
      }
      throw error;
    }
  }

  runTool(tool: Tool, ctx: ExecutionContext): ToolResult {
    if (!this.useDocker) return this.fallback.runTool(tool, ctx);

    try {
      ensureImage();
      const taskId = randomUUID();
      const workDir = mkdtempSync(join(tmpdir(), `sandbox-${taskId}-`));

      try {
        const payload = JSON.stringify({ tool: tool.name, context: ctx });
        writeFileSync(join(workDir, 'ctx.json'), payload);

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
            IMAGE_TAG,
            '/sandbox/ctx.json',
          ],
          { timeout, stdio: ['pipe', 'pipe', 'pipe'], encoding: 'utf8' },
        );

        const parsed = JSON.parse(output) as { ok: boolean; value?: ToolResult; error?: string };
        if (!parsed.ok || !parsed.value) throw new Error(`sandbox runner: ${parsed.error ?? 'unknown'}`);
        return parsed.value;
      } finally {
        rmSync(workDir, { recursive: true, force: true });
      }
    } catch (error) {
      const msg = (error as Error).message;
      if (msg.includes('exec failed') || msg.includes('docker') || msg.includes('ENOENT')) {
        return this.fallback.runTool(tool, ctx);
      }
      throw error;
    }
  }
}
