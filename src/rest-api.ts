/**
 * REST API over node:http (ADR-019): a whitelist router of literal method+path
 * pairs, JWT-bearer authn middleware for /v1/* routes, and whitelist body
 * parsing. Unhandled method+path combinations get NO response — the connection
 * is destroyed, nothing is advertised. Identity comes ONLY from
 * `IdentityProvider.verifyToken` + `resolvePrincipal`; request headers other
 * than `authorization` are never read. Routes outside /v1/* (healthz only)
 * receive an anonymous sentinel context — no principal is ever derived from a
 * request.
 */

import { createServer, type IncomingMessage, type ServerResponse, type Server } from 'node:http';
import { readFileSync } from 'node:fs';
import type { AuthContext, Principal, Action } from './domain.ts';
import type { AuthorizationService } from './pdp.ts';
import type { IdentityProvider } from './identity.ts';
import type { EventStore } from './events.ts';
import { registerSessionRoutes, type SessionRouteDeps } from './rest-sessions.ts';
import { registerAuditRoutes, type AuditRouteDeps } from './rest-audit.ts';
import { registerAnchorRoutes, type AnchorRouteDeps } from './rest-anchors.ts';

const DEFAULT_MAX_BODY_BYTES = 1_048_576;

const FORBIDDEN_PARAM_KEYS = new Set(['__proto__', 'constructor', 'prototype']);

const BEARER_RE = /^Bearer ([^\s]+)$/;

export type RestResponse = { readonly status: number; readonly body: unknown; readonly contentType?: string };

export interface RestRequestContext {
  readonly principal: Principal;
  readonly auth: AuthContext;
  readonly params: Readonly<Record<string, string>>;
  readonly query: Readonly<Record<string, string>>;
  readonly body: unknown;
}

export type RouteHandler = (ctx: RestRequestContext) => RestResponse | Promise<RestResponse>;

/** Structured rejection a handler throws; dispatcher maps it to a fixed-shape error body. */
export class RestRejection extends Error {
  readonly status: number;
  readonly code: string;
  constructor(status: number, code: string, message?: string) {
    super(message ?? code);
    this.name = 'RestRejection';
    this.status = status;
    this.code = code;
  }
}

/** Whitelist string field. Throws RestRejection(400, 'invalid-body') when wrong-typed or empty. */
export function str(value: unknown, field: string): string {
  if (typeof value !== 'string' || value.length === 0) {
    throw new RestRejection(400, 'invalid-body', `field '${field}' must be a non-empty string`);
  }
  return value;
}

/** Whitelist string-array field (array of non-empty strings). Throws RestRejection(400,'invalid-body'). */
export function strArray(value: unknown, field: string): string[] {
  if (!Array.isArray(value)) throw new RestRejection(400, 'invalid-body', `field '${field}' must be an array of strings`);
  const out: string[] = [];
  for (const item of value) {
    if (typeof item !== 'string' || item.length === 0) {
      throw new RestRejection(400, 'invalid-body', `field '${field}' must be an array of non-empty strings`);
    }
    out.push(item);
  }
  return out;
}

/** Whitelist optional-string field; undefined passthrough. */
export function optStr(value: unknown, field: string): string | undefined {
  if (value === undefined) return undefined;
  if (typeof value !== 'string') throw new RestRejection(400, 'invalid-body', `field '${field}' must be a string`);
  return value;
}

/**
 * Plain-object copy that skips prototype-pollution keys: hostile JSON keys like
 * `__proto__` can never reach a fresh record via assignment.
 */
function copyOwnRecord(raw: object): Record<string, unknown> {
  const src = raw as Record<string, unknown>;
  const out: Record<string, unknown> = {};
  for (const key of Object.keys(src)) {
    if (FORBIDDEN_PARAM_KEYS.has(key)) continue;
    out[key] = src[key];
  }
  return out;
}

function isPlainRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}

function parseQuery(queryString: string): Record<string, string> {
  const out: Record<string, string> = {};
  if (queryString === '') return out;
  for (const [key, value] of new URLSearchParams(queryString)) {
    if (FORBIDDEN_PARAM_KEYS.has(key)) continue;
    out[key] = value;
  }
  return out;
}

function respond(res: ServerResponse, status: number, body: unknown, contentType = 'application/json'): void {
  res.writeHead(status, { 'content-type': contentType });
  res.end(contentType === 'application/json' ? JSON.stringify(body) : body);
}

const ANONYMOUS_PRINCIPAL: Principal = {
  id: 'rest-anonymous',
  kind: 'tool',
  tenantId: '',
  roles: [],
  attributes: {},
};

const ANONYMOUS_AUTH: AuthContext = {
  issuer: '',
  subject: 'rest-anonymous',
  audience: '',
  expiresAt: 0,
  issuedAt: 0,
  tokenId: '',
  authTime: 0,
  amr: [],
  claims: {},
  verifiedAt: 0,
};

interface CompiledRoute {
  readonly method: string;
  readonly pattern: string;
  readonly segments: readonly string[];
  readonly needsAuth: boolean;
  readonly handler: RouteHandler;
}

export interface RestApiDeps {
  readonly authorization: AuthorizationService;
  readonly idp: IdentityProvider;
  readonly eventLog: EventStore;
  /** Verbatim contract: maps a VERIFIED AuthContext to a registered Principal, or undefined. This is the ONLY principal source; HTTP headers are never consulted. */
  readonly resolvePrincipal: (auth: AuthContext) => Principal | undefined;
  /** store status for /healthz. Default: () => 'ok' */
  readonly storeHealth?: () => 'ok' | 'unavailable';
  /** Body size cap in bytes. Default: 1_048_576 (1 MiB). */
  readonly maxBodyBytes?: number;
  /**
   * Static pages (ADR-020 minimal UI): exact GET routes served as-is — no
   * directory listing, no parametrized path, so traversal does not exist by
   * construction. Pages contain no secrets; the UI authorizes like any other
   * client (bearer JWT typed by the operator at runtime).
   */
  readonly staticPages?: readonly StaticPage[];
  /**
   * H13 (ADR-026): pull revocation-channel records once per authorized
   * request, so a running server converges inside the poll interval even when
   * the traffic is session/audit-only (the PDP path syncs itself). Optional —
   * without it the M14 surface is unchanged.
   */
  readonly incidentSync?: () => void;
}

export interface StaticPage {
  readonly route: string;
  readonly body: string;
  readonly contentType: string;
}

/** Load one static page from disk at assembly time (embedder calls this, not the request path). */
export function staticPageFromFile(route: string, filePath: string, contentType: string): StaticPage {
  return { route, body: readFileSync(filePath, 'utf8'), contentType };
}

export interface RestApiFullDeps extends RestApiDeps, SessionRouteDeps, AuditRouteDeps, AnchorRouteDeps {}

/** Assembly point for the full ADR-019 route table (core routes + sessions + capability requests + audit + tasks + federation anchors). */
export function createRestApi(deps: RestApiFullDeps): RestApi {
  const api = new RestApi(deps);
  registerSessionRoutes(api, deps);
  registerAuditRoutes(api, deps);
  registerAnchorRoutes(api, deps);
  return api;
}

export class RestApi {
  private readonly authorization: AuthorizationService;
  private readonly idp: IdentityProvider;
  private readonly eventLog: EventStore;
  private readonly resolvePrincipalFn: (auth: AuthContext) => Principal | undefined;
  private readonly storeHealth: () => 'ok' | 'unavailable';
  private readonly maxBodyBytes: number;
  private readonly incidentSync?: () => void;
  private readonly routes = new Map<string, CompiledRoute>();
  private server: Server | undefined;
  private port: number | undefined;

  constructor(deps: RestApiDeps) {
    this.authorization = deps.authorization;
    this.idp = deps.idp;
    this.eventLog = deps.eventLog;
    this.resolvePrincipalFn = deps.resolvePrincipal;
    this.storeHealth = deps.storeHealth ?? (() => 'ok');
    this.maxBodyBytes = deps.maxBodyBytes ?? DEFAULT_MAX_BODY_BYTES;
    this.incidentSync = deps.incidentSync;

    this.addRoute('GET', '/healthz', () => ({
      status: 200,
      body: { idp: this.idp.getIdPHealth().status, store: this.storeHealth() },
    }));
    this.addRoute('POST', '/v1/authorize', (ctx) => this.authorizeRoute(ctx));
    for (const page of deps.staticPages ?? []) {
      this.addRoute('GET', page.route, () => ({ status: 200, body: page.body, contentType: page.contentType }));
    }
  }

  /** Register a route. Path is '/'-segments; a segment starting with ':' captures one param. Throws on duplicate method+pattern or a hostile param name. */
  addRoute(method: string, path: string, handler: RouteHandler): void {
    const normalizedMethod = method.toUpperCase();
    const segments = path.split('/').filter((s) => s.length > 0);
    for (const segment of segments) {
      if (segment.startsWith(':') && FORBIDDEN_PARAM_KEYS.has(segment.slice(1))) {
        throw new Error(`route param name is not permitted: ${segment}`);
      }
    }
    const key = `${normalizedMethod} ${path}`;
    if (this.routes.has(key)) throw new Error(`route already registered: ${key}`);
    this.routes.set(key, {
      method: normalizedMethod,
      pattern: path,
      segments,
      needsAuth: segments[0] === 'v1',
      handler,
    });
  }

  /** Bind 127.0.0.1 ephemeral port; resolves with the port (mirror EgressProxy.start()). */
  async start(): Promise<number> {
    this.server = createServer((req, res) => this.handleRequest(req, res));
    await new Promise<void>((resolve, reject) => {
      this.server?.listen(0, '127.0.0.1', resolve);
      this.server?.on('error', reject);
    });
    const addr = this.server.address();
    if (addr && typeof addr === 'object') {
      this.port = addr.port;
    }
    return this.port ?? 0;
  }

  stop(): void {
    this.server?.close();
    this.server = undefined;
    this.port = undefined;
  }

  getPort(): number | undefined {
    return this.port;
  }

  private handleRequest(req: IncomingMessage, res: ServerResponse): void {
    this.dispatch(req, res).catch(() => {
      res.destroy();
    });
  }

  private async dispatch(req: IncomingMessage, res: ServerResponse): Promise<void> {
    const method = (req.method ?? '').toUpperCase();
    const target = req.url ?? '/';
    const queryStart = target.indexOf('?');
    const path = queryStart === -1 ? target : target.slice(0, queryStart);
    const query = parseQuery(queryStart === -1 ? '' : target.slice(queryStart + 1));

    const match = this.matchRoute(method, path);
    if (match === undefined) {
      res.destroy();
      return;
    }
    const { route, params } = match;

    let principal: Principal;
    let auth: AuthContext;
    if (route.needsAuth) {
      const header = req.headers.authorization;
      const bearer = typeof header === 'string' ? BEARER_RE.exec(header) : null;
      if (bearer === null) {
        respond(res, 401, { denyReason: 'unauthenticated-principal' });
        return;
      }
      const verified = await this.idp.verifyToken(bearer[1]!);
      if (verified === undefined) {
        respond(res, 403, { denyReason: 'unauthenticated-principal' });
        return;
      }
      const resolved = this.resolvePrincipalFn(verified);
      if (resolved === undefined) {
        respond(res, 403, { denyReason: 'unauthenticated-principal' });
        return;
      }
      principal = resolved;
      auth = verified;
    } else {
      principal = ANONYMOUS_PRINCIPAL;
      auth = ANONYMOUS_AUTH;
    }

    // H13: converge on the revocation channel once per authorized request.
    // Unauthenticated floods do not reach this line, and a sync failure never
    // blocks the request (the PDP's own fail-closed paths still apply).
    if (route.needsAuth) {
      try {
        this.incidentSync?.();
      } catch {
        // Surfaced via incident status counters, not request failure.
      }
    }

    let body: unknown = undefined;
    if (method === 'POST') {
      const read = await this.readBody(req, res);
      if (!read.ok) return;
      const parsed = this.parseBody(read.data, res);
      if (!parsed.ok) return;
      body = parsed.value;
    }

    try {
      const response = await route.handler({ principal, auth, params, query, body });
      respond(res, response.status, response.body, response.contentType);
    } catch (error) {
      if (error instanceof RestRejection) {
        respond(res, error.status, { error: error.code });
        return;
      }
      this.eventLog.append({
        tenantId: principal.tenantId ?? '',
        principal: principal.id,
        actor: principal.id,
        actorKind: principal.kind,
        action: 'rest.request',
        resourceId: route.pattern,
        decision: 'deny',
        denyReason: 'evaluation-error',
        result: 'denied',
        metadata: { phase: 'rest-api', method, path: route.pattern },
      });
      respond(res, 500, { error: 'internal-error' });
    }
  }

  private matchRoute(method: string, path: string): { route: CompiledRoute; params: Record<string, string> } | undefined {
    const parts = path.split('/').filter((s) => s.length > 0);
    for (const route of this.routes.values()) {
      if (route.method !== method || route.segments.length !== parts.length) continue;
      const params: Record<string, string> = {};
      let ok = true;
      for (let i = 0; i < route.segments.length; i++) {
        const patternSegment = route.segments[i]!;
        const actual = parts[i]!;
        if (patternSegment.startsWith(':')) {
          const name = patternSegment.slice(1);
          if (name.length === 0 || FORBIDDEN_PARAM_KEYS.has(name)) {
            ok = false;
            break;
          }
          params[name] = actual;
        } else if (patternSegment !== actual) {
          ok = false;
          break;
        }
      }
      if (ok) return { route, params };
    }
    return undefined;
  }

  private readBody(req: IncomingMessage, res: ServerResponse): Promise<{ ok: true; data: Buffer } | { ok: false }> {
    return new Promise((resolve) => {
      const chunks: Buffer[] = [];
      let total = 0;
      let done = false;
      const finish = (result: { ok: true; data: Buffer } | { ok: false }) => {
        if (done) return;
        done = true;
        resolve(result);
      };
      req.on('data', (chunk: Buffer) => {
        if (done) return;
        total += chunk.length;
        if (total > this.maxBodyBytes) {
          respond(res, 413, { error: 'body-too-large' });
          req.resume();
          finish({ ok: false });
          return;
        }
        chunks.push(chunk);
      });
      req.on('end', () => finish({ ok: true, data: Buffer.concat(chunks) }));
      req.on('error', () => finish({ ok: false }));
    });
  }

  private parseBody(data: Buffer, res: ServerResponse): { ok: true; value: unknown } | { ok: false } {
    let parsed: unknown;
    try {
      parsed = JSON.parse(data.toString('utf8'));
    } catch {
      respond(res, 400, { error: 'invalid-json' });
      return { ok: false };
    }
    if (parsed === null || typeof parsed !== 'object') {
      respond(res, 400, { error: 'invalid-json' });
      return { ok: false };
    }
    return { ok: true, value: parsed };
  }

  private authorizeRoute(ctx: RestRequestContext): RestResponse {
    if (!isPlainRecord(ctx.body)) {
      throw new RestRejection(400, 'invalid-body', 'authorize body must be a JSON object');
    }
    const action = str(ctx.body.action, 'action');
    const resourceId = str(ctx.body.resourceId, 'resourceId');
    const params = isPlainRecord(ctx.body.params) ? copyOwnRecord(ctx.body.params) : undefined;

    const decision = this.authorization.authorize({
      principal: ctx.principal,
      action,
      resourceId,
      params,
    });
    if (decision.decision === 'allow') return { status: 200, body: { decision: decision.decision, reason: decision.reason } };
    return { status: 403, body: { denyReason: decision.denyReason ?? 'no-capability', reason: decision.reason } };
  }
}
