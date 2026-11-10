/**
 * Safety ticket 04 item 2: fail closed on missing durable keys.
 *
 * Ephemeral keys are correct for the demo and the test suite. A long-lived
 * instance (the REST server, a persistent event store) must refuse to start
 * without them, because a restart would silently invalidate everything it
 * wrote. The override is explicit and warns.
 */

import { test, describe } from 'node:test';
import assert from 'node:assert/strict';
import { existsSync, mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import {
  assertDurableKeys,
  DURABLE_KEY_VARS,
  EPHEMERAL_KEYS_OVERRIDE,
  MissingDurableKeysError,
} from '../src/key-policy.ts';
import { buildWorld } from '../src/scenario.ts';
import { RestApi } from '../src/rest-api.ts';
import { createMockIdP, testWorld } from '../src/testing.ts';

const ALL_KEYS = DURABLE_KEY_VARS;
const EVIDENCE_KEYS = ['EVENT_SIGNING_PRIVATE_KEY_PEM', 'EVENT_SIGNING_PUBLIC_KEY_PEM', 'EVIDENCE_SEALING_KEY'] as const;

function envWith(keys: readonly string[]): Record<string, string> {
  return Object.fromEntries(keys.map((name) => [name, 'set-for-test']));
}

/** Run fn with every durable key and the override removed from process.env, then restore. */
function withoutKeys<T>(fn: () => T): T {
  const saved = new Map<string, string | undefined>();
  for (const name of [...ALL_KEYS, EPHEMERAL_KEYS_OVERRIDE]) {
    saved.set(name, process.env[name]);
    delete process.env[name];
  }
  try {
    return fn();
  } finally {
    for (const [name, value] of saved) {
      if (value === undefined) delete process.env[name];
      else process.env[name] = value;
    }
  }
}

async function withoutKeysAsync<T>(fn: () => Promise<T>): Promise<T> {
  const saved = new Map<string, string | undefined>();
  for (const name of [...ALL_KEYS, EPHEMERAL_KEYS_OVERRIDE]) {
    saved.set(name, process.env[name]);
    delete process.env[name];
  }
  try {
    return await fn();
  } finally {
    for (const [name, value] of saved) {
      if (value === undefined) delete process.env[name];
      else process.env[name] = value;
    }
  }
}

describe('key policy: the decision', () => {
  test('demo mode allows ephemeral keys, silently', () => {
    const warnings: string[] = [];
    assert.doesNotThrow(() => assertDurableKeys('demo', { env: {}, warn: (m) => warnings.push(m) }));
    assert.deepEqual(warnings, []);
  });

  test('server mode names every missing key and says how to fix it', () => {
    assert.throws(
      () => assertDurableKeys('server', { env: {} }),
      (error: unknown) => {
        assert.ok(error instanceof MissingDurableKeysError);
        assert.equal(error.name, 'MissingDurableKeysError');
        assert.equal(error.mode, 'server');
        assert.deepEqual([...error.missing], [...ALL_KEYS]);
        for (const name of ALL_KEYS) assert.match(error.message, new RegExp(name));
        assert.match(error.message, /refusing to start the REST server/);
        assert.match(error.message, /process environment/);
        assert.match(error.message, new RegExp(`${EPHEMERAL_KEYS_OVERRIDE}=1`));
        return true;
      },
    );
  });

  test('persistent mode requires the keys old evidence is verified and decrypted with', () => {
    assert.throws(
      () => assertDurableKeys('persistent', { env: {} }),
      (error: unknown) => {
        assert.ok(error instanceof MissingDurableKeysError);
        assert.equal(error.mode, 'persistent');
        assert.deepEqual([...error.missing], [...EVIDENCE_KEYS]);
        assert.match(error.message, /refusing to open a persistent event store/);
        return true;
      },
    );
    assert.doesNotThrow(() => assertDurableKeys('persistent', { env: envWith(EVIDENCE_KEYS) }));
  });

  test('an empty value counts as missing', () => {
    const env = { ...envWith(ALL_KEYS), CAPABILITY_SIGNING_KEY: '' };
    assert.throws(() => assertDurableKeys('server', { env }), /CAPABILITY_SIGNING_KEY/);
  });

  test('all keys set means no throw and no warning', () => {
    const warnings: string[] = [];
    assert.doesNotThrow(() =>
      assertDurableKeys('server', { env: envWith(ALL_KEYS), warn: (m) => warnings.push(m) }),
    );
    assert.deepEqual(warnings, []);
  });

  test('the override is explicit, warns once, and is not the default', () => {
    const warnings: string[] = [];
    assert.doesNotThrow(() =>
      assertDurableKeys('server', {
        env: { [EPHEMERAL_KEYS_OVERRIDE]: '1' },
        warn: (m) => warnings.push(m),
      }),
    );
    assert.equal(warnings.length, 1);
    assert.match(warnings[0]!, new RegExp(`${EPHEMERAL_KEYS_OVERRIDE}=1`));
    assert.match(warnings[0]!, /will not be verifiable or decryptable after a restart/);

    // Only the exact value '1' opts in: a stray 'true' must still fail closed.
    assert.throws(
      () => assertDurableKeys('server', { env: { [EPHEMERAL_KEYS_OVERRIDE]: 'true' } }),
      MissingDurableKeysError,
    );
  });
});

describe('key policy: the seams', () => {
  test('a persistent event store refuses to open with no keys, before touching disk', () => {
    const dir = mkdtempSync(join(tmpdir(), 'aisl-key-policy-'));
    const path = join(dir, 'events.sqlite');
    try {
      withoutKeys(() => {
        assert.throws(
          () => buildWorld({ sqlitePath: path }),
          (error: unknown) => {
            assert.ok(error instanceof MissingDurableKeysError);
            assert.match(error.message, /EVENT_SIGNING_PRIVATE_KEY_PEM/);
            return true;
          },
        );
      });
      assert.equal(existsSync(path), false, 'the store must not be created when the policy refuses');
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });

  test('an in-memory world still runs with no keys (the demo path)', () => {
    withoutKeys(() => {
      const world = buildWorld();
      try {
        assert.ok(world.eventLog.all().length > 0, 'the world bootstrapped and appended evidence');
      } finally {
        world.eventLog.close();
      }
    });
  });

  test('the REST server refuses to start with no keys', async () => {
    const world = testWorld();
    const mockIdp = await createMockIdP();
    const idp = await mockIdp.createIdP();
    const api = new RestApi({
      authorization: world.authorization,
      idp,
      eventLog: world.eventLog,
      resolvePrincipal: (auth) => (auth.subject === world.user.id ? world.user : undefined),
    });
    try {
      await withoutKeysAsync(async () => {
        await assert.rejects(api.start(), (error: unknown) => {
          assert.ok(error instanceof MissingDurableKeysError);
          assert.equal(error.mode, 'server');
          return true;
        });
      });
      assert.equal(api.getPort(), undefined, 'no port was bound');
    } finally {
      api.stop();
      world.eventLog.close();
    }
  });

  test('the REST server starts when every key is set', async () => {
    const world = testWorld();
    const mockIdp = await createMockIdP();
    const idp = await mockIdp.createIdP();
    const api = new RestApi({
      authorization: world.authorization,
      idp,
      eventLog: world.eventLog,
      resolvePrincipal: (auth) => (auth.subject === world.user.id ? world.user : undefined),
    });
    try {
      const port = await api.start();
      assert.ok(port > 0);
    } finally {
      api.stop();
      world.eventLog.close();
    }
  });
});
