/**
 * M15 acceptance: basic Git integration, read-only (ADR-020).
 *
 * A write verb is refused at CONFIGURATION time; traversal outside the
 * configured repo root is refused before spawn; output flows through the
 * ingestion path with the repository's classification. Runs the real git CLI
 * against a throwaway repository in the temp dir.
 */

import { test, describe, before, after } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { git as runGit } from './helpers/git.ts';
import { GIT_READ_VERBS, GitReader } from '../src/git-reader.ts';
import { DocumentIngester } from '../src/ingestion.ts';
import { ResourceRegistry, defineResource } from '../src/registry.ts';
import { EventLog } from '../src/events.ts';
import { keyIdForTenant } from '../src/seal.ts';
import { TENANT_A } from '../src/scenario.ts';

let repoDir = '';

function git(argv: readonly string[]): void {
  runGit(argv, repoDir);
}

before(() => {
  repoDir = mkdtempSync(join(tmpdir(), 'm15-git-'));
  git(['init', '--initial-branch=main']);
  git(['config', 'user.name', 'test']);
  git(['config', 'user.email', 'test@example.com']);
  writeFileSync(join(repoDir, 'hello.txt'), 'hello from the fixture repo\n');
  git(['add', '.']);
  git(['commit', '--no-gpg-sign', '-m', 'initial commit']);
});

after(() => {
  rmSync(repoDir, { recursive: true, force: true });
});

describe('GitReader configuration-time refusal', () => {
  test('only the four read verbs exist; a write verb cannot be constructed', () => {
    assert.deepEqual(GIT_READ_VERBS, ['log', 'show', 'diff', 'status']);
    assert.throws(() => new GitReader({ repoRoot: repoDir, allowlist: ['push'] }), /not a read verb/);
    assert.throws(() => new GitReader({ repoRoot: repoDir, allowlist: ['commit', 'log'] }), /not a read verb/);
    assert.throws(() => new GitReader({ repoRoot: repoDir, allowlist: ['fetch'] }), /not a read verb/);
  });

  test('a verb outside the instance allowlist is refused at run time', () => {
    const reader = new GitReader({ repoRoot: repoDir, allowlist: ['status'] });
    assert.throws(() => reader.run('log'), /not allowlisted/);
  });
});

describe('GitReader traversal + escape-hatch refusal', () => {
  const reader = new GitReader({ repoRoot: repoDir });

  test('absolute paths are refused', () => {
    const outside = join(repoDir, '..', 'outside.txt');
    assert.throws(() => reader.run('diff', ['--no-index', 'a', 'b']), /escape hatch/);
    assert.throws(() => reader.run('show', [`HEAD:${outside}`]), /absolute path/);
    assert.throws(() => reader.run('log', ['--git-dir', 'elsewhere']), /escape hatch/);
    assert.throws(() => reader.run('status', ['-C', '..']), /escape hatch/);
  });

  test('`..` segments are refused (over-broad for A..B ranges by design)', () => {
    assert.throws(() => reader.run('show', ['HEAD:../../../etc/passwd']), /traversal/);
    assert.throws(() => reader.run('log', ['main..other']), /traversal/);
  });

  test('an existing root is required', () => {
    const missing = new GitReader({ repoRoot: join(repoDir, 'does-not-exist') });
    assert.throws(() => missing.run('status'), /does not exist/);
  });
});

describe('GitReader reads a real repository', () => {
  const reader = new GitReader({ repoRoot: repoDir });

  test('log, show, status, diff return the expected content', () => {
    assert.match(reader.run('log'), /initial commit/);
    assert.match(reader.run('show', ['HEAD:hello.txt']), /hello from the fixture repo/);
    assert.match(reader.run('status', ['--porcelain']), /^\s*$/); // clean tree
    assert.equal(reader.run('diff').length, 0);
  });

  test('output enters the ingestion path labeled with the repo classification, sealed, plaintext-free', () => {
    const registry = new ResourceRegistry();
    const eventLog = new EventLog();
    const canary = 'REPO-OUTPUT-CANARY-9f2b';
    writeFileSync(join(repoDir, 'secret.txt'), `${canary}\n`);
    git(['add', '.']);
    git(['commit', '--no-gpg-sign', '-m', 'add secret file']);
    const output = reader.run('show', ['HEAD:secret.txt']);

    const repo = registry.add(
      defineResource({ id: 'repo:acme/repo-a', type: 'repository', tenantId: TENANT_A, classification: 'internal' }),
    );
    const ingester = new DocumentIngester({ registry, eventLog, actorId: 'user:alice', actorKind: 'user' });
    const result = ingester.ingest({ document: repo, content: output });

    const chunk = registry.require(result.chunks[0]!.id);
    assert.equal(chunk.id, 'doc/repo:acme/repo-a/chunk/0');
    assert.equal(chunk.classification, 'internal');
    assert.equal(chunk.attributes.derivedFrom, 'repo:acme/repo-a');
    const ev = eventLog.all().filter((e) => e.action === 'document.ingest')[0]!;
    assert.equal((ev.metadata?.sealed as { keyId: string }).keyId, keyIdForTenant(TENANT_A, 'internal'));
    assert.equal(JSON.stringify(eventLog.all()).includes(canary), false);
  });
});
