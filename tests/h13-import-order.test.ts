/**
 * H13 audit 03 regression: the incident-store-pg ↔ event-store-pg import
 * cycle. `incident-store-pg.ts` must be importable FIRST — with an inline
 * `{ type }` import it kept a runtime edge back to event-store-pg.ts and
 * crashed with `Cannot access 'INCIDENT_MIGRATION' before initialization`.
 *
 * The first repo import in this file is deliberately the channel module; node
 * runs each test file in its own process, so this order is the regression.
 */

import { PostgresRevocationChannel } from '../src/incident-store-pg.ts';
import { test } from 'node:test';
import assert from 'node:assert/strict';

test('incident-store-pg loads when imported before event-store-pg (no TDZ crash)', () => {
  assert.equal(typeof PostgresRevocationChannel, 'function');
});
