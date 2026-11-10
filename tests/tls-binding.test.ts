/**
 * TLS at the edge (safety ticket 04, item 3).
 *
 * The rule is one line: no plaintext on a reachable interface. Loopback may run
 * without TLS; anything else must present a certificate or refuse to start.
 * The refusal happens before a socket exists.
 */

import { test, describe } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { request as httpsRequest } from 'node:https';
import { RestApi } from '../src/rest-api.ts';
import { testWorld, createMockIdP } from '../src/testing.ts';

const __dirname = dirname(fileURLToPath(import.meta.url));
const CERT = readFileSync(join(__dirname, 'fixtures', 'tls', 'localhost-cert.pem'), 'utf8');
const KEY = readFileSync(join(__dirname, 'fixtures', 'tls', 'localhost-key.pem'), 'utf8');

async function makeApi(overrides: Partial<ConstructorParameters<typeof RestApi>[0]> = {}): Promise<RestApi> {
  const world = testWorld();
  const mockIdp = await createMockIdP();
  const idp = await mockIdp.createIdP();
  return new RestApi({
    authorization: world.authorization,
    idp,
    eventLog: world.eventLog,
    resolvePrincipal: () => undefined,
    ...overrides,
  });
}

function httpsGet(port: number, path: string): Promise<number> {
  return new Promise((resolve, reject) => {
    const req = httpsRequest(
      { host: '127.0.0.1', port, path, method: 'GET', rejectUnauthorized: false },
      (res) => {
        res.resume();
        resolve(res.statusCode ?? 0);
      },
    );
    req.on('error', reject);
    req.end();
  });
}

describe('TLS: no plaintext on a reachable interface', () => {
  test('a public bind without TLS is refused before a socket exists', async () => {
    const api = await makeApi({ host: '0.0.0.0' });
    await assert.rejects(() => api.start(), /without TLS/);
    assert.equal(api.getPort(), undefined, 'no port was bound');
  });

  test('a specific non-loopback address is refused too', async () => {
    const api = await makeApi({ host: '192.0.2.10' });
    await assert.rejects(() => api.start(), /without TLS/);
  });

  test('loopback without TLS still works (the default)', async () => {
    const api = await makeApi();
    const port = await api.start();
    try {
      const res = await fetch(`http://127.0.0.1:${port}/healthz`);
      assert.equal(res.status, 200);
    } finally {
      api.stop();
    }
  });

  test('a public bind with TLS serves HTTPS', async () => {
    const api = await makeApi({ host: '127.0.0.1', tls: { key: KEY, cert: CERT } });
    const port = await api.start();
    try {
      assert.equal(await httpsGet(port, '/healthz'), 200);
    } finally {
      api.stop();
    }
  });

  test('the refusal names the fix', async () => {
    const api = await makeApi({ host: '0.0.0.0' });
    await assert.rejects(
      () => api.start(),
      (err: Error) => err.message.includes('tls.key') && err.message.includes('127.0.0.1'),
    );
  });
});
