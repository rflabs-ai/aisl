/** Shared test wiring. Test-only: pins a signing key so results are reproducible. */

import { buildWorld, type World } from './scenario.ts';
import type { PolicyRule } from './policy.ts';

export function testWorld(options: { policies?: readonly PolicyRule[]; sqlitePath?: string } = {}): World {
  process.env.CAPABILITY_SIGNING_KEY ??= 'test-signing-key-not-for-production';
  return buildWorld(options);
}
