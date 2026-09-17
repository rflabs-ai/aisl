/**
 * Real egress proxy: intercepts HTTP(S) traffic and routes every request
 * through the PDP before forwarding. Sessions have no route out except through
 * this proxy (sandbox `--network none` + HTTP_PROXY env).
 *
 * ponytail: HTTP only for now. HTTPS CONNECT tunneling is the next step.
 * IP literals are blocked; DNS is pinned (resolved IPs checked against
 * private/link-local ranges); deny by default.
 */

import { createServer, type IncomingMessage, type ServerResponse, type Server } from 'node:http';
import { request as httpRequest, type RequestOptions } from 'node:http';
import { resolve as dnsResolve } from 'node:dns';
import type { AuthorizationService } from './pdp.ts';
import type { ResourceRegistry } from './registry.ts';
import type { EventStore } from './events.ts';
import type { Principal } from './domain.ts';
import { defineResource } from './registry.ts';

function normalizeHost(host: string): string {
  return host.trim().toLowerCase().replace(/\.$/, '');
}

const IP_LITERAL_RE = /^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$/;

function isPrivateOrReserved(ip: string): boolean {
  if (ip === '127.0.0.1' || ip === '::1' || ip === '0.0.0.0') return true;
  if (ip.startsWith('10.')) return true;
  if (ip.startsWith('192.168.')) return true;
  if (ip.startsWith('172.')) {
    const second = Number(ip.split('.')[1]);
    if (second >= 16 && second <= 31) return true;
  }
  if (ip.startsWith('169.254.')) return true;
  if (ip.startsWith('fc') || ip.startsWith('fd') || ip.startsWith('fe80')) return true;
  return false;
}

function resolveDns(host: string): Promise<string[]> {
  return new Promise((resolve) => {
    dnsResolve(host, 'A', (err, addresses) => {
      if (err) resolve([]);
      else resolve(addresses ?? []);
    });
  });
}

export interface ProxyResult {
  readonly allowed: boolean;
  readonly host: string;
  readonly reason: string;
  readonly resolvedIp?: string;
  readonly port?: number;
}

export class EgressProxy {
  private readonly authorization: AuthorizationService;
  private readonly registry: ResourceRegistry;
  private readonly eventLog: EventStore;
  private readonly principal: Principal;
  private readonly dnsPin: boolean;
  private server: Server | undefined;
  private port: number | undefined;

  constructor(
    principal: Principal,
    authorization: AuthorizationService,
    registry: ResourceRegistry,
    eventLog: EventStore,
    opts: { dnsPin?: boolean } = {},
  ) {
    this.principal = principal;
    this.authorization = authorization;
    this.registry = registry;
    this.eventLog = eventLog;
    this.dnsPin = opts.dnsPin ?? true;
  }

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

  async check(host: string): Promise<ProxyResult> {
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

    this.authorizeRequest(host).then((result) => {
      this.eventLog.append({
        tenantId: this.principal.tenantId,
        principal: this.principal.id,
        actor: this.principal.id,
        actorKind: this.principal.kind,
        action: 'network.egress',
        resourceId: `net:${host}`,
        decision: result.allowed ? 'allow' : 'deny',
        result: result.allowed ? 'success' : 'denied',
        metadata: { phase: 'egress-proxy', host, port, allowed: result.allowed, reason: result.reason, resolvedIp: result.resolvedIp ?? null },
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
    });
  }

  private async authorizeRequest(host: string): Promise<ProxyResult> {
    const principal = this.principal;
    if (IP_LITERAL_RE.test(host)) {
      return { allowed: false, host, reason: 'IP literal blocked; use DNS hostname' };
    }

    // DNS pinning: resolve and reject private/link-local IPs.
    let resolvedIp: string | undefined;
    if (this.dnsPin) {
      const ips = await resolveDns(host);
      if (ips.length === 0) {
        return { allowed: false, host, reason: 'DNS resolution failed' };
      }
      const blocked = ips.filter(isPrivateOrReserved);
      if (blocked.length > 0) {
        return { allowed: false, host, reason: `DNS resolved to private/reserved IP: ${blocked.join(', ')}`, resolvedIp: blocked[0] };
      }
      resolvedIp = ips[0];
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

    return { allowed: decision.decision === 'allow', host, reason: decision.reason, resolvedIp };
  }
}
