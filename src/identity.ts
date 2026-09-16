/**
 * Identity: OIDC token verification and principal authentication.
 *
 * M2 structural guarantee: the PDP only accepts principals carrying a valid
 * AuthContext. This module is the only code path that produces AuthContext
 * values. Hand-rolling JWT verification is a defect by the bar in
 * SECURITY_PRINCIPLES.md — this module uses `jose` (ADR-015).
 *
 * Invariant 13: no path to a Principal without authentication.
 * Invariant 14: IdP outage produces operator-visible degraded state.
 */

import { importJWK, jwtVerify, type JWTPayload, type CryptoKey } from 'jose';
import { type AuthContext, type Principal } from './domain.ts';

export type IdPStatus = 'healthy' | 'degraded' | 'unreachable';

export interface IdPHealth {
  readonly status: IdPStatus;
  readonly lastChecked: number;
  readonly lastError?: string;
}

export interface IdPConfig {
  /** OIDC issuer URL (e.g. https://accounts.google.com) */
  readonly issuer: string;
  /** Expected audience (client ID) */
  readonly audience: string;
  /** JWKS endpoint URL. If omitted, discovered from issuer/.well-known/openid-configuration */
  readonly jwksUri?: string;
  /** Algorithms to accept. Default: RS256, ES256 */
  readonly algorithms?: readonly string[];
  /** Clock tolerance in seconds for exp/nbf checks. Default: 30 */
  readonly clockToleranceSec?: number;
}

interface CachedJWK {
  readonly keys: Map<string, CryptoKey>;
  readonly fetchedAt: number;
}

const JWKS_CACHE_TTL_MS = 600_000; // 10 minutes

/**
 * OIDC Identity Provider adapter.
 *
 * Verifies JWTs issued by a trusted IdP and produces AuthContext values.
 * Caches JWKS keys with a TTL. Tracks IdP health for degraded-mode signaling.
 * Supports token revocation (in-memory set) and circuit breaker for IdP outages.
 */
export class IdentityProvider {
  private readonly config: Required<IdPConfig>;
  private jwkCache: CachedJWK | undefined;
  private health: IdPHealth = { status: 'healthy', lastChecked: 0 };
  private readonly fetchFn: typeof fetch;

  /** Token revocation set: token ids that must not be accepted. */
  private readonly revokedTokens = new Set<string>();

  /** Circuit breaker: tracks consecutive JWKS fetch failures. */
  private consecutiveFailures = 0;
  private circuitOpenUntil = 0;
  private readonly circuitBreakerThreshold: number;
  private readonly circuitBreakerCooldownMs: number;

  constructor(
    config: IdPConfig,
    fetchImpl: typeof fetch = globalThis.fetch,
    options?: {
      readonly circuitBreakerThreshold?: number;
      readonly circuitBreakerCooldownMs?: number;
    },
  ) {
    this.config = {
      issuer: config.issuer,
      audience: config.audience,
      jwksUri: config.jwksUri ?? `${config.issuer}/.well-known/openid-configuration`,
      algorithms: config.algorithms ?? ['RS256', 'ES256'],
      clockToleranceSec: config.clockToleranceSec ?? 30,
    };
    this.fetchFn = fetchImpl;
    this.circuitBreakerThreshold = options?.circuitBreakerThreshold ?? 5;
    this.circuitBreakerCooldownMs = options?.circuitBreakerCooldownMs ?? 60_000;
  }

  /** Current IdP health status. Updated on each verify() call. */
  getIdPHealth(): IdPHealth {
    return this.health;
  }

  /**
   * Revoke a token by its jti (token id). Revoked tokens are rejected by
   * verifyToken even if their signature and expiry are valid.
   */
  revokeToken(tokenId: string): void {
    this.revokedTokens.add(tokenId);
  }

  /** Check if a token id has been revoked. */
  isTokenRevoked(tokenId: string): boolean {
    return this.revokedTokens.has(tokenId);
  }

  /**
   * Verify a JWT access token and produce an AuthContext.
   * Returns undefined on any verification failure — never throws to callers.
   * Checks: signature, expiry, audience, issuer, revocation.
   */
  async verifyToken(token: string): Promise<AuthContext | undefined> {
    try {
      const payload = await this.verifyJwt(token);
      if (!payload) return undefined;

      // Check revocation
      const jti = payload.jti ?? '';
      if (jti && this.revokedTokens.has(jti)) {
        return undefined;
      }

      const authContext: AuthContext = {
        issuer: this.config.issuer,
        subject: payload.sub ?? '',
        audience: this.config.audience,
        expiresAt: typeof payload.exp === 'number' ? payload.exp * 1000 : 0,
        issuedAt: typeof payload.iat === 'number' ? payload.iat * 1000 : 0,
        tokenId: jti,
        authTime: typeof payload.auth_time === 'number' ? payload.auth_time * 1000 : 0,
        amr: Array.isArray(payload.amr) ? payload.amr : [],
        acr: typeof payload.acr === 'string' ? payload.acr : undefined,
        claims: payload,
        verifiedAt: Date.now(),
      };

      this.consecutiveFailures = 0;
      this.health = { status: 'healthy', lastChecked: Date.now() };
      return authContext;
    } catch {
      return undefined;
    }
  }

  /**
   * Create an authenticated principal from an AuthContext.
   * This is the ONLY way to produce an AuthenticatedPrincipal.
   */
  static authenticatedPrincipal(
    auth: AuthContext,
    tenantId: string,
    roles: readonly string[] = [],
    attributes: Readonly<Record<string, string | number | boolean>> = {},
  ): Principal {
    return {
      id: auth.subject,
      kind: 'user',
      tenantId,
      roles,
      attributes,
      auth,
    };
  }

  /**
   * Create a session-scoped agent principal derived from an authenticated human.
   * Agent identity is never a global credential — it is derived per session
   * from the launching human (M2 scope: agent and workload identity).
   */
  static sessionAgent(
    auth: AuthContext,
    agentId: string,
    tenantId: string,
    roles: readonly string[] = [],
  ): Principal {
    return {
      id: agentId,
      kind: 'agent',
      tenantId,
      roles,
      attributes: { derivedFrom: auth.subject },
      auth,
    };
  }

  private async verifyJwt(token: string): Promise<JWTPayload | undefined> {
    // Circuit breaker: if too many consecutive failures, stop trying
    if (this.consecutiveFailures >= this.circuitBreakerThreshold) {
      if (Date.now() < this.circuitOpenUntil) {
        this.health = {
          status: 'unreachable',
          lastChecked: Date.now(),
          lastError: `circuit breaker open, retries blocked until ${new Date(this.circuitOpenUntil).toISOString()}`,
        };
        return undefined;
      }
      // Cooldown expired, allow one retry
      this.consecutiveFailures = this.circuitBreakerThreshold - 1;
    }

    const keys = await this.getSigningKeys();
    if (!keys) {
      this.consecutiveFailures++;
      if (this.consecutiveFailures >= this.circuitBreakerThreshold) {
        this.circuitOpenUntil = Date.now() + this.circuitBreakerCooldownMs;
        this.health = {
          status: 'unreachable',
          lastChecked: Date.now(),
          lastError: `circuit breaker opened after ${this.consecutiveFailures} consecutive failures`,
        };
      }
      return undefined;
    }

    const verifyOptions = {
      issuer: this.config.issuer,
      audience: this.config.audience,
      algorithms: [...this.config.algorithms],
      clockToleranceSec: this.config.clockToleranceSec,
    };

    // Try each signing key
    for (const key of keys.values()) {
      try {
        const { payload } = await jwtVerify(token, key, verifyOptions);
        return payload;
      } catch {
        continue;
      }
    }

    return undefined;
  }

  private async getSigningKeys(): Promise<Map<string, CryptoKey> | undefined> {
    // Return cached keys if still valid
    if (this.jwkCache && Date.now() - this.jwkCache.fetchedAt < JWKS_CACHE_TTL_MS) {
      return this.jwkCache.keys;
    }

    try {
      let jwksUrl: string;

      // If jwksUri was provided directly, use it
      if (this.config.jwksUri !== `${this.config.issuer}/.well-known/openid-configuration`) {
        jwksUrl = this.config.jwksUri;
      } else {
        // Discover from OIDC well-known endpoint
        const discoveryResp = await this.fetchFn(`${this.config.issuer}/.well-known/openid-configuration`);
        if (!discoveryResp.ok) {
          this.health = { status: 'unreachable', lastChecked: Date.now(), lastError: `discovery failed: ${discoveryResp.status}` };
          return undefined;
        }
        const discovery = await discoveryResp.json() as { jwks_uri?: string };
        const discoveredUri = discovery.jwks_uri;
        if (!discoveredUri) {
          this.health = { status: 'unreachable', lastChecked: Date.now(), lastError: 'no jwks_uri in discovery' };
          return undefined;
        }
        jwksUrl = discoveredUri;
      }

      const jwksResp = await this.fetchFn(jwksUrl);
      if (!jwksResp.ok) {
        this.health = { status: 'unreachable', lastChecked: Date.now(), lastError: `JWKS fetch failed: ${jwksResp.status}` };
        return undefined;
      }
      const { keys: jwkKeys } = await jwksResp.json() as { keys: readonly Record<string, unknown>[] };

      const keys = new Map<string, CryptoKey>();
      for (const jwk of jwkKeys) {
        if (jwk.kid && jwk.kty) {
          try {
            const key = await importJWK(jwk as Parameters<typeof importJWK>[0], jwk.alg as string | undefined);
            if (key instanceof Uint8Array) continue; // symmetric keys not used for JWT verification
            keys.set(jwk.kid as string, key as CryptoKey);
          } catch {
            // Skip keys we cannot import
          }
        }
      }

      this.jwkCache = { keys, fetchedAt: Date.now() };
      this.health = { status: 'healthy', lastChecked: Date.now() };
      return keys;
    } catch (error) {
      this.health = {
        status: 'unreachable',
        lastChecked: Date.now(),
        lastError: error instanceof Error ? error.message : String(error),
      };
      return undefined;
    }
  }
}

/**
 * Verify MFA was used for this authentication.
 * Checks for 'mfa' or 'otp' in the AMR (Authentication Methods References).
 */
export function hasMfa(auth: AuthContext): boolean {
  return auth.amr.some((m) => m === 'mfa' || m === 'otp' || m === 'swk');
}

/**
 * IdP outage degraded mode: the PDP denies with a specific reason and the
 * operator receives a health signal. This is NOT silent universal denial —
 * the deny reason is distinct, and the health status is operator-visible.
 */
export const IDP_UNAVAILABLE_DENY = 'idp-unavailable' as const;
