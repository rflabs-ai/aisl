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

/** H2 (ADR-028): default maximum accepted token lifetime (`exp - iat`), seconds. */
export const DEFAULT_MAX_TOKEN_LIFETIME_SEC = 3_600;
/**
 * H2 (ADR-028): the configured lifetime ceiling is itself capped so
 * "short-lived" cannot be configured away.
 */
export const MAX_TOKEN_LIFETIME_CEILING_SEC = 86_400;
/** H2 (ADR-028): default clock tolerance for exp/iat checks, seconds. */
export const DEFAULT_CLOCK_TOLERANCE_SEC = 30;
/**
 * H2 (ADR-028): hard cap on clock tolerance — skew may shift the boundary by
 * at most this much, it may not extend a credential's declared life.
 */
export const MAX_CLOCK_SKEW_SEC = 60;
/** H2 (ADR-028): default ceiling for derived workload contexts, seconds. */
export const DEFAULT_MAX_WORKLOAD_LIFETIME_SEC = 900;

/** Configuration that fails closed is refused at construction, loudly. */
export class IdentityConfigError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'IdentityConfigError';
  }
}

export interface TokenClaimLimits {
  readonly maxTokenLifetimeSec: number;
  readonly clockToleranceSec: number;
}

export type TokenClaimRejection =
  | 'claims-missing-sub'
  | 'claims-missing-exp'
  | 'claims-missing-iat'
  | 'claims-missing-jti'
  | 'claims-lifetime-not-positive'
  | 'claims-lifetime-exceeds-ceiling'
  | 'claims-issued-in-future'
  | 'claims-expired';

export type TokenClaimValidation =
  | {
      readonly ok: true;
      readonly subject: string;
      readonly tokenId: string;
      readonly issuedAt: number;
      readonly expiresAt: number;
      readonly lifetimeSec: number;
    }
  | { readonly ok: false; readonly reason: TokenClaimRejection };

/**
 * H2 (ADR-028): the credential admission contract. A token is honored only
 * when it names a subject, declares a positive lifetime within the configured
 * ceiling, carries a revocation handle (`jti`), and was issued/expires within
 * the bounded clock tolerance. Pure and exported so the expiry fuzz matrix can
 * pin the predicate without minting a JWT per case.
 */
export function validateTokenClaims(
  payload: Readonly<Record<string, unknown>>,
  nowMs: number,
  limits: TokenClaimLimits,
): TokenClaimValidation {
  const sub = payload.sub;
  if (typeof sub !== 'string' || sub.length === 0) return { ok: false, reason: 'claims-missing-sub' };
  const exp = payload.exp;
  if (typeof exp !== 'number' || !Number.isFinite(exp)) return { ok: false, reason: 'claims-missing-exp' };
  const iat = payload.iat;
  if (typeof iat !== 'number' || !Number.isFinite(iat)) return { ok: false, reason: 'claims-missing-iat' };
  const jti = payload.jti;
  if (typeof jti !== 'string' || jti.length === 0) return { ok: false, reason: 'claims-missing-jti' };

  const lifetimeSec = exp - iat;
  if (!(lifetimeSec > 0)) return { ok: false, reason: 'claims-lifetime-not-positive' };
  if (lifetimeSec > limits.maxTokenLifetimeSec) return { ok: false, reason: 'claims-lifetime-exceeds-ceiling' };

  const toleranceMs = limits.clockToleranceSec * 1000;
  const issuedAt = iat * 1000;
  const expiresAt = exp * 1000;
  if (issuedAt > nowMs + toleranceMs) return { ok: false, reason: 'claims-issued-in-future' };
  if (expiresAt < nowMs - toleranceMs) return { ok: false, reason: 'claims-expired' };
  return { ok: true, subject: sub, tokenId: jti, issuedAt, expiresAt, lifetimeSec };
}

/**
 * H2 (ADR-028): the consumer view of the H13 revocation channel — `since` is a
 * synchronous local read (the channel port's design) and `refresh` fires an
 * async backend's mirror update. `RevocationChannel` satisfies this
 * structurally; identity.ts does not import incident.ts.
 */
export interface TokenRevocationFeed {
  refresh(): void;
  since(cursor: number): readonly TokenRevocationRecord[];
}

export interface TokenRevocationRecord {
  readonly seq: number;
  readonly action: string;
  readonly targetId?: string;
}

function assertBound(name: string, value: number, min: number, max: number): void {
  if (!Number.isFinite(value) || value < min || value > max) {
    throw new IdentityConfigError(`${name} must be a finite number between ${min} and ${max}; got ${String(value)}`);
  }
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
  /**
   * H2 (ADR-028): maximum accepted token lifetime (`exp - iat`), seconds.
   * Default 3600 (1 h). A token whose declared lifetime exceeds this is
   * refused at the verification seam; the configured value is capped at
   * 86 400 (24 h).
   */
  readonly maxTokenLifetimeSec?: number;
  /**
   * H2 (ADR-028): clock tolerance for `exp`/`iat` checks, seconds.
   * Default 30. Capped at 60 so a skewed clock cannot extend credential life
   * materially.
   */
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
 * Verifies JWTs issued by a trusted IdP and produces AuthContext values. The
 * H2 (ADR-028) admission contract is enforced here: a token must declare a
 * bounded lifetime (`exp - iat` <= the configured ceiling), name a subject,
 * carry a revocation handle (`jti`), and fall inside the bounded clock
 * tolerance. Caches JWKS keys with a TTL. Tracks IdP health for degraded-mode
 * signaling. Supports token revocation (in-memory set, optionally fed by the
 * H13 revocation channel) and a circuit breaker for IdP outages.
 */
export class IdentityProvider {
  private readonly config: Required<IdPConfig>;
  private jwkCache: CachedJWK | undefined;
  private health: IdPHealth = { status: 'healthy', lastChecked: 0 };
  private readonly fetchFn: typeof fetch;

  /**
   * Token revocation set: token ids that must not be accepted.
   * ponytail: revoked jtis are kept for the process lifetime; bounded by the
   * 24h token ceiling and revocation volume. upgrade: store (jti, exp) and
   * prune on expiry if revocation volume strains memory.
   */
  private readonly revokedTokens = new Set<string>();
  /** H2 (ADR-028): optional H13 channel feed; revocation propagates across nodes. */
  private revocationFeed: TokenRevocationFeed | undefined;
  private revocationCursor = -1;
  private revocationSyncIntervalMs = 1_000;
  private revocationLastSyncAt = Number.NEGATIVE_INFINITY;

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
    const clockToleranceSec = config.clockToleranceSec ?? DEFAULT_CLOCK_TOLERANCE_SEC;
    const maxTokenLifetimeSec = config.maxTokenLifetimeSec ?? DEFAULT_MAX_TOKEN_LIFETIME_SEC;
    assertBound('clockToleranceSec', clockToleranceSec, 0, MAX_CLOCK_SKEW_SEC);
    assertBound('maxTokenLifetimeSec', maxTokenLifetimeSec, 1, MAX_TOKEN_LIFETIME_CEILING_SEC);
    this.config = {
      issuer: config.issuer,
      audience: config.audience,
      jwksUri: config.jwksUri ?? `${config.issuer}/.well-known/openid-configuration`,
      algorithms: config.algorithms ?? ['RS256', 'ES256'],
      clockToleranceSec,
      maxTokenLifetimeSec,
    };
    this.fetchFn = fetchImpl;
    this.circuitBreakerThreshold = options?.circuitBreakerThreshold ?? 5;
    this.circuitBreakerCooldownMs = options?.circuitBreakerCooldownMs ?? 60_000;
  }

  /**
   * H2 (ADR-028): consume the H13 revocation channel. `revoke-token` records
   * add their `jti` to the local revoked set on the next `verifyToken`
   * (throttled; the first call always syncs). A feed read failure never fails
   * verification — the token's own short expiry is the floor, and channel
   * health is H13's operator signal.
   */
  attachRevocationFeed(feed: TokenRevocationFeed, options?: { readonly syncIntervalMs?: number }): void {
    const syncIntervalMs = options?.syncIntervalMs ?? 1_000;
    if (!Number.isFinite(syncIntervalMs) || syncIntervalMs < 0) {
      throw new IdentityConfigError(`syncIntervalMs must be a finite number >= 0; got ${String(syncIntervalMs)}`);
    }
    this.revocationFeed = feed;
    this.revocationSyncIntervalMs = syncIntervalMs;
    this.revocationLastSyncAt = Number.NEGATIVE_INFINITY;
  }

  /** True once a feed is attached; the production assembly's health signal. */
  hasRevocationFeed(): boolean {
    return this.revocationFeed !== undefined;
  }

  private syncRevocations(): void {
    const feed = this.revocationFeed;
    if (!feed) return;
    const now = Date.now();
    if (now - this.revocationLastSyncAt < this.revocationSyncIntervalMs) return;
    this.revocationLastSyncAt = now;
    try {
      feed.refresh();
    } catch {
      // Async backends report failures through channel health(); verification
      // keeps working from local state.
    }
    let records: readonly TokenRevocationRecord[];
    try {
      records = feed.since(this.revocationCursor);
    } catch {
      return;
    }
    for (const record of records) {
      if (record.action === 'revoke-token' && typeof record.targetId === 'string' && record.targetId.length > 0) {
        this.revokedTokens.add(record.targetId);
      }
      if (record.seq > this.revocationCursor) this.revocationCursor = record.seq;
    }
  }

  /** Current IdP health status. Updated on each verify() call. */
  getIdPHealth(): IdPHealth {
    return this.health;
  }

  /**
   * Revoke a token by its jti (token id). Revoked tokens are rejected by
   * verifyToken even if their signature and expiry are valid. This is the
   * local-first half of `IncidentService.revokeToken` (ADR-028); cross-node
   * propagation rides the H13 revocation channel via `attachRevocationFeed`.
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
   * Checks: signature, issuer, audience, the H2 admission contract
   * (exp/iat/jti/sub + lifetime ceiling + bounded skew), revocation.
   */
  async verifyToken(token: string): Promise<AuthContext | undefined> {
    try {
      // H2 (ADR-028): converge on the revocation channel before honoring the
      // credential — the REST verify step mints a principal before any PDP
      // decision-path sync runs, so the feed must be consumed here.
      this.syncRevocations();

      const payload = await this.verifyJwt(token);
      if (!payload) return undefined;

      // H2 (ADR-028): a credential without a bounded lifetime and a
      // revocation handle is not honored — same fail-closed result as a bad
      // signature (no reason oracle to the caller).
      const claims = validateTokenClaims(payload, Date.now(), this.config);
      if (!claims.ok) return undefined;

      // Check revocation
      if (this.revokedTokens.has(claims.tokenId)) {
        return undefined;
      }

      const verifiedAt = Date.now();
      const authContext: AuthContext = {
        issuer: this.config.issuer,
        subject: claims.subject,
        audience: this.config.audience,
        expiresAt: claims.expiresAt,
        issuedAt: claims.issuedAt,
        tokenId: claims.tokenId,
        authTime: typeof payload.auth_time === 'number' ? payload.auth_time * 1000 : 0,
        amr: Array.isArray(payload.amr) ? payload.amr : [],
        acr: typeof payload.acr === 'string' ? payload.acr : undefined,
        claims: payload,
        verifiedAt,
      };

      this.consecutiveFailures = 0;
      this.health = { status: 'healthy', lastChecked: verifiedAt };
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
   * H2 (ADR-028): derive a bounded workload identity from a verified parent.
   * The derived context never outlives the parent, drops the parent's raw
   * payload and MFA methods, and records the derivation. It is a context, not
   * a credential: minted in-process from an already-verified parent, and the
   * PDP treats it exactly like any other AuthContext (expiry still gates).
   */
  static workloadAuth(
    parent: AuthContext,
    workloadId: string,
    now: number,
    options?: { readonly maxLifetimeSec?: number },
  ): AuthContext {
    if (!workloadId || workloadId.length === 0) {
      throw new IdentityConfigError('workloadId must be a non-empty string');
    }
    const maxLifetimeSec = options?.maxLifetimeSec ?? DEFAULT_MAX_WORKLOAD_LIFETIME_SEC;
    assertBound('maxLifetimeSec', maxLifetimeSec, 1, MAX_TOKEN_LIFETIME_CEILING_SEC);
    return {
      issuer: parent.issuer,
      subject: workloadId,
      audience: parent.audience,
      expiresAt: Math.min(parent.expiresAt, now + maxLifetimeSec * 1000),
      issuedAt: now,
      tokenId: `wl:${workloadId}:${parent.tokenId}`,
      authTime: parent.authTime,
      amr: [],
      claims: {},
      verifiedAt: now,
      derivedFrom: { subject: parent.subject, tokenId: parent.tokenId },
    };
  }

  /**
   * Create a session-scoped agent principal derived from an authenticated human.
   * Agent identity is never a global credential — it is derived per session
   * from the launching human (ADR-016) and routed through `workloadAuth`
   * (ADR-028): time-capped, claim-minimal, and explicitly marked as derived.
   */
  static sessionAgent(
    auth: AuthContext,
    agentId: string,
    tenantId: string,
    roles: readonly string[] = [],
    now: number = Date.now(),
  ): Principal {
    return {
      id: agentId,
      kind: 'agent',
      tenantId,
      roles,
      attributes: { derivedFrom: auth.subject },
      auth: IdentityProvider.workloadAuth(auth, agentId, now),
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
      // H2 (ADR-028): `clockTolerance` is jose's option name (seconds). The
      // previous `clockToleranceSec` key was silently ignored, so the
      // configured tolerance had never applied.
      clockTolerance: this.config.clockToleranceSec,
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
