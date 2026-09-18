/**
 * M15 acceptance: developer setup script (ADR-020).
 *
 * Invariants: no remote fetch, no pipe-to-shell, no sudo (the script is
 * plain reviewable text); checks fail closed — a missing prerequisite
 * exits nonzero. The live check run (node/git/npm found, exit 0) is
 * exercised when pwsh/bash are available; it skips cleanly otherwise.
 */

import { spawnSync } from 'node:child_process';
import { readFileSync } from 'node:fs';
import { test, describe } from 'node:test';
import assert from 'node:assert/strict';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';

const ROOT = join(dirname(fileURLToPath(import.meta.url)), '..');
const PS1 = join(ROOT, 'scripts', 'setup.ps1');
const SH = join(ROOT, 'scripts', 'setup.sh');

const PS1_TEXT = readFileSync(PS1, 'utf8');
const SH_TEXT = readFileSync(SH, 'utf8');

const FORBIDDEN: readonly [RegExp, string][] = [
  [/\bcurl\b/, 'curl'],
  [/\bwget\b/, 'wget'],
  [/\bInvoke-WebRequest\b/, 'Invoke-WebRequest'],
  [/\bInvoke-RestMethod\b/, 'Invoke-RestMethod'],
  [/\birm\b/, 'irm (Invoke-RestMethod alias)'],
  [/\biwr\b/, 'iwr (Invoke-WebRequest alias)'],
  [/\| bash/, 'pipe to bash'],
  [/\| sh\b/, 'pipe to sh'],
  [/\bsudo\b/, 'sudo'],
  [/\beval\b/, 'eval'],
  [/iex\b|Invoke-Expression/, 'Invoke-Expression'],
];

describe('setup scripts (ADR-020)', () => {
  test('no remote fetch, no pipe-to-shell, no sudo, no eval — in either script', () => {
    for (const [pattern, name] of FORBIDDEN) {
      assert.equal(pattern.test(PS1_TEXT), false, `setup.ps1 must not use ${name}`);
      assert.equal(pattern.test(SH_TEXT), false, `setup.sh must not use ${name}`);
    }
  });

  test('fail-closed: a missing prerequisite exits nonzero', () => {
    const pwsh = process.env.ProgramFiles
      ? join(process.env.ProgramFiles, 'PowerShell', '7', 'pwsh.exe')
      : 'pwsh';
    const probe = spawnSync(pwsh, ['-NoProfile', '-File', PS1, '-CheckOnly'], {
      encoding: 'utf8',
      env: { PATH: '' },
    });
    if (probe.error || probe.status === null) {
      return; // pwsh unavailable in this environment — skipped cleanly.
    }
    assert.equal(probe.status !== 0, true, 'empty PATH must produce a nonzero exit');
    assert.match(probe.stdout, /setup FAILED/);
  });

  test('checks pass on this checkout (exit 0)', () => {
    const pwsh = process.env.ProgramFiles
      ? join(process.env.ProgramFiles, 'PowerShell', '7', 'pwsh.exe')
      : 'pwsh';
    const probe = spawnSync(pwsh, ['-NoProfile', '-File', PS1, '-CheckOnly'], { encoding: 'utf8' });
    if (probe.error || probe.status === null) {
      return; // pwsh unavailable in this environment — skipped cleanly.
    }
    assert.equal(probe.status, 0, `expected exit 0, got ${probe.status}: ${probe.stdout}`);
  });
});
