import { test } from 'node:test';
import assert from 'node:assert/strict';
import { ContainerSandbox, isDockerAvailable } from '../src/container-sandbox.ts';
import { LocalSandbox } from '../src/runtime.ts';

test('a mid-run Docker failure flips kind to fallback before delegating', (t) => {
  if (!isDockerAvailable()) {
    t.skip('docker is not available; the constructor already reports fallback');
    return;
  }
  const sandbox = new ContainerSandbox(new LocalSandbox(), { forceDockerFailure: true });
  assert.match(sandbox.kind, /^container\//);
  assert.equal(sandbox.run(() => 42), 42);
  assert.match(sandbox.kind, /^fallback\//);
});
