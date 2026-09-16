/**
 * Real egress proxy: intercepts HTTP(S) traffic and routes every request
 * through the PDP before forwarding. Sessions have no route out except through
 * this proxy (sandbox `--network none` + HTTP_PROXY env).
 *
 * ponytail: HTTP only for now. HTTPS CONNECT tunneling is the next step.
 * IP literals are blocked at the proxy layer.
 *
 * KNOWN GAP (see ROADMAP H7, Claim 10): an allowlisted hostname may resolve to
 * a private or link-local address (cloud metadata at 169.254.169.254), and
 * there is no body-size or time limit on forwarded requests. Until DNS results
 * are pinned and range-checked, treat egress allowlisting as necessary but not
 * sufficient against SSRF.
 */

import { createServer, type IncomingMessage, type ServerResponse, type Server } from 'node:http';
import { request as httpRequest, type RequestOptions } from 'node:http';
import type { AuthorizationService } from './pdp.ts';
import type { ResourceRegistry } from './registry.ts';
import type { EventLog } from './events.ts';
import type { Principal } from './domain.ts';
import { defineResource } from './registry.ts';

function normalizeHost(host: string): string {
  return host.trim().toLowerCase().replace(/\.$/, '');
}

const IP_LITERAL_RE = /^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$/;

export interface ProxyResult {
  readonly allowed: boolean;
  readonly host: string;
  readonly reason: string;
  readonly port?: number;
}

export class EgressProxy {
  private readonly authorization: AuthorizationService;
  private readonly registry: ResourceRegistry;
  private readonly eventLog: EventLog;
  private readonly principal: Principal;
  private server: Server | undefined;
  private port: number | undefined;

  /**
   * @param principal the identity this proxy serves. One proxy per session.
   *   It is bound at construction and can never come from the request: the
   *   caller is sandboxed, possibly hostile code, and a client-supplied
   *   principal is a complete authorization bypass.
   */
  constructor(
    principal: Principal,
    authorization: AuthorizationService,
    registry: ResourceRegistry,
    eventLog: EventLog,
  ) {
    this.principal = principal;
    this.authorization = authorization;
    this.registry = registry;
    this.eventLog = eventLog;
  }

  /**
   * Start the proxy on a random loopback port. Resolves with the port.
   * The port is only known after the `listening` event — reading
   * `server.address()` before it yields null and silently advertises port 0.
   */
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

  /** Environment variables that force HTTP traffic through this proxy. */
  proxyEnv(): Record<string, string> {
    const port = this.port ?? 0;
    return {
      HTTP_PROXY: `http://127.0.0.1:${port}`,
      HTTPS_PROXY: `http://127.0.0.1:${port}`,
      http_proxy: `http://127.0.0.1:${port}`,
      https_proxy: `http://127.0.0.1:${port}`,
      NO_PROXY: 'localhost,127.0.0.1',
      no_proxy: 'localhost,127.0.0.1',
    };
  }

  /** Check whether a request would be allowed. Does not forward. */
  check(host: string): ProxyResult {
    return this.authorizeRequest(host);
  }

  private handleRequest(req: IncomingMessage, res: ServerResponse): void {
    const url = req.url ?? '/';
    const hostHeader = req.headers.host;
    if (!hostHeader) {
      res.writeHead(400);
      res.end('missing Host header');
      return;
    }

    const [hostname, portStr] = hostHeader.split(':');
    const host = normalizeHost(hostname ?? '');
    const port = portStr ? Number(portStr) : 80;

    const principal = this.principal;
    const result = this.authorizeRequest(host);

    this.eventLog.append({
      tenantId: principal.tenantId,
      principal: principal.id,
      actor: principal.id,
      actorKind: principal.kind,
      action: 'network.egress',
      resourceId: `net:${host}`,
      decision: result.allowed ? 'allow' : 'deny',
      result: result.allowed ? 'success' : 'denied',
      metadata: { phase: 'egress-proxy', host, port, allowed: result.allowed, reason: result.reason },
    });

    if (!result.allowed) {
      res.writeHead(403);
      res.end(`denied: ${result.reason}`);
      return;
    }

    const opts: RequestOptions = {
      hostname: host,
      port,
      path: url,
      method: req.method,
      headers: { ...req.headers, host: hostHeader },
    };

    const proxyReq = httpRequest(opts, (proxyRes) => {
      res.writeHead(proxyRes.statusCode ?? 502, proxyRes.headers);
      proxyRes.pipe(res);
    });

    proxyReq.on('error', () => {
      res.writeHead(502);
      res.end('upstream unreachable');
    });

    req.pipe(proxyReq);
  }

  private authorizeRequest(host: string): ProxyResult {
    const principal = this.principal;
    if (IP_LITERAL_RE.test(host)) {
      return { allowed: false, host, reason: 'IP literal blocked; use DNS hostname' };
    }

    const resourceId = `net:${host}`;
    if (!this.registry.get(resourceId)) {
      this.registry.add(
        defineResource({
          id: resourceId,
          type: 'network-destination',
          tenantId: principal.tenantId,
          classification: 'restricted',
          attributes: { host },
        }),
      );
    }

    const decision = this.authorization.authorize({
      principal,
      action: 'network.egress',
      resourceId,
      networkHost: host,
    });

    return { allowed: decision.decision === 'allow', host, reason: decision.reason };
  }
}
