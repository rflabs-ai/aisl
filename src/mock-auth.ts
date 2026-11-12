/**
 * Mock auth context for demo and CLI paths.
 *
 * Side-effect free on purpose: `src/testing.ts` pins durable keys into
 * `process.env` when imported, so nothing under `src/` that ships may import
 * it. This module is what the CLI uses; the test wiring re-exports it.
 */

import { type AuthContext } from './domain.ts';

/** Mock AuthContext — represents a fully authenticated human with MFA. */
export function mockAuth(overrides: Partial<AuthContext> = {}): AuthContext {
  return {
    issuer: 'https://idp.test.example.com',
    subject: overrides.subject ?? 'user:test-subject',
    audience: 'test-audience',
    expiresAt: overrides.expiresAt ?? Date.now() + 3_600_000,
    issuedAt: overrides.issuedAt ?? Date.now(),
    tokenId: overrides.tokenId ?? 'tok_test_001',
    authTime: overrides.authTime ?? Date.now(),
    amr: overrides.amr ?? ['pwd', 'mfa'],
    acr: overrides.acr ?? 'urn:mace:incommon:iap:silver',
    claims: overrides.claims ?? {},
    verifiedAt: overrides.verifiedAt ?? Date.now(),
  };
}
