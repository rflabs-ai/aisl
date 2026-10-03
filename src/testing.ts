/** Shared test wiring. Test-only: pins a signing key so results are reproducible. */

import { buildWorld, type World, type WorldOptions } from './scenario.ts';
import { type AuthContext, type Principal } from './domain.ts';
import { hasMfa, IdentityProvider, type IdPConfig } from './identity.ts';
import { exportJWK, SignJWT, generateKeyPair, type JWK } from 'jose';

export function testWorld(options: WorldOptions = {}): World {
  process.env.CAPABILITY_SIGNING_KEY ??= 'test-signing-key-not-for-production';
  return buildWorld(options);
}

/** Mock AuthContext for tests — represents a fully authenticated human with MFA. */
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

/** Create an authenticated user principal for tests. */
export function testUser(id: string, tenantId: string, authOverrides: Partial<AuthContext> = {}): Principal {
  return {
    id,
    kind: 'user',
    tenantId,
    roles: [],
    attributes: {},
    auth: mockAuth({ subject: id, ...authOverrides }),
  };
}

/** Create an authenticated agent principal for tests (derived from a human session). */
export function testAgent(id: string, tenantId: string, authOverrides: Partial<AuthContext> = {}): Principal {
  return {
    id,
    kind: 'agent',
    tenantId,
    roles: [],
    attributes: {},
    auth: mockAuth({ subject: id, ...authOverrides }),
  };
}

/** Create an unauthenticated principal for negative tests. */
export function unauthPrincipal(id: string, kind: 'user' | 'agent' = 'agent', tenantId = 'acme'): Principal {
  return { id, kind, tenantId, roles: [], attributes: {} };
}

/** Assert the principal has valid MFA in its auth context. */
export function assertMfaVerified(p: Principal): void {
  if (!p.auth) throw new Error(`principal ${p.id} has no auth context`);
  if (!hasMfa(p.auth)) throw new Error(`principal ${p.id} auth lacks MFA`);
}

/**
 * Mock OIDC server: generates real RSA keys, signs real JWTs, exposes a JWKS
 * endpoint. IdentityProvider.verifyToken() goes through the full jose
 * verification path against these keys — no mocking of crypto.
 */
export interface MockIdP {
  /** The issuer URL (file:// based, no network) */
  readonly issuer: string;
  /** The audience (client id) */
  readonly audience: string;
  /** Sign a JWT with the mock IdP's private key */
  signJWT(claims: {
    readonly sub: string;
    readonly amr?: readonly string[];
    readonly acr?: string;
    readonly exp?: number;
    readonly iat?: number;
    readonly jti?: string;
    readonly auth_time?: number;
    /** H2: omit standard claims to exercise the admission contract (e.g. ['exp']). */
    readonly omit?: readonly ('exp' | 'iat' | 'jti' | 'sub')[];
    readonly [key: string]: unknown;
  }): Promise<string>;
  /** Create an IdentityProvider configured to trust this mock IdP */
  createIdP(options?: {
    readonly jwksUri?: string;
    readonly algorithms?: readonly string[];
    readonly clockToleranceSec?: number;
    readonly maxTokenLifetimeSec?: number;
  }): Promise<IdentityProvider>;
  /** Get the JWKS public keys as a JWK Set */
  getJWKS(): Promise<{ readonly keys: readonly JWK[] }>;
}

/**
 * Create a mock OIDC IdP for tests. Uses file:// URLs for the well-known
 * and JWKS endpoints so no network server is needed — the fetch function
 * is overridden to serve from memory.
 */
export async function createMockIdP(issuer = 'https://idp.test.example.com', audience = 'test-audience'): Promise<MockIdP> {
  const { privateKey, publicKey } = await generateKeyPair('RS256', { modulusLength: 2048 });
  const publicJwk = await exportJWK(publicKey);
  publicJwk.kid = 'test-key-001';
  publicJwk.alg = 'RS256';
  publicJwk.use = 'sig';

  const jwks = { keys: [publicJwk] };

  // Override fetch to serve JWKS from memory
  const mockFetch: typeof globalThis.fetch = async (input: string | URL | Request) => {
    const url = typeof input === 'string' ? input : input instanceof URL ? input.href : input.url;
    if (url.includes('/.well-known/openid-configuration')) {
      return new Response(JSON.stringify({
        issuer,
        jwks_uri: `${issuer}/jwks`,
        token_endpoint: `${issuer}/token`,
        supported_signing_algorithms: ['RS256'],
      }), { status: 200, headers: { 'content-type': 'application/json' } });
    }
    if (url.includes('/jwks')) {
      return new Response(JSON.stringify(jwks), { status: 200, headers: { 'content-type': 'application/json' } });
    }
    return new Response('Not Found', { status: 404 });
  };

  return {
    issuer,
    audience,
    async signJWT(claims) {
      const { sub, amr, acr, jti, auth_time, exp, iat, omit = [], ...rest } = claims;
      const payload: Record<string, unknown> = {
        iss: issuer,
        aud: audience,
        amr: amr ?? ['pwd', 'mfa'],
        acr: acr ?? 'urn:mace:incommon:iap:silver',
        auth_time: auth_time ?? Math.floor(Date.now() / 1000),
        ...rest,
      };
      if (!omit.includes('sub')) payload.sub = sub;
      if (!omit.includes('jti')) payload.jti = jti ?? `tok-${Date.now()}-${Math.random().toString(36).slice(2)}`;
      // Default exp is iat-relative (not wall-relative): the declared lifetime
      // is exactly 3600s even if a second boundary is crossed between reads,
      // so the H2 ceiling is not flaky.
      const issuedAtSec = iat ?? Math.floor(Date.now() / 1000);
      let jwt = new SignJWT(payload).setProtectedHeader({ alg: 'RS256', kid: 'test-key-001' });
      if (!omit.includes('iat')) jwt = jwt.setIssuedAt(issuedAtSec);
      if (!omit.includes('exp')) jwt = jwt.setExpirationTime(exp ? Math.floor(exp / 1000) : issuedAtSec + 3600);
      return jwt.sign(privateKey);
    },
    async createIdP(options) {
      return new IdentityProvider(
        {
          issuer,
          audience,
          jwksUri: options?.jwksUri ?? `${issuer}/jwks`,
          algorithms: options?.algorithms,
          clockToleranceSec: options?.clockToleranceSec,
          maxTokenLifetimeSec: options?.maxTokenLifetimeSec,
        },
        mockFetch,
      );
    },
    async getJWKS() {
      return jwks;
    },
  };
}
