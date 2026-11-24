import { test } from 'node:test';
import assert from 'node:assert/strict';
import { hasSecretInArgv } from '../src/argv-guard.ts';

test('refuses a PEM-shaped flag value', () => {
  const pemHeader = ['-----BEGIN', 'PRIVATE KEY-----'].join(' ');
  assert.equal(hasSecretInArgv(['incident', 'engage', 'global', '--reason', pemHeader]), true);
});

test('refuses a JWT-shaped flag value', () => {
  const jwt = 'eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U';
  assert.equal(hasSecretInArgv(['--reason', jwt]), true);
});

test('refuses a URL with an inline password', () => {
  assert.equal(hasSecretInArgv(['--reason', 'postgres://app:secret@db.internal/prod']), true);
});

test('allows an ordinary reason', () => {
  assert.equal(hasSecretInArgv(['--reason', 'freeze season 2026, customer reported burst pipe']), false);
});

test('allows a URL without a password', () => {
  assert.equal(hasSecretInArgv(['--reason', 'see https://example.com/incident/42']), false);
});
