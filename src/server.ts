/**
 * Production assembly (ticket 06): one function that builds the persistent
 * world, attaches the H13 revocation feed to the identity service, and starts
 * the REST server.
 *
 * Before this module, `IdentityProvider.attachRevocationFeed` existed only in
 * tests: a running server could verify a JWT whose `jti` another node had
 * revoked and never learn about it. The factory (`buildWorldAsync`) constructs
 * the channel and calls the attach; this module owns the composition so an
 * embedder cannot forget it. When the attach fails, the gap is not swallowed:
 * `/healthz` reports `revocation: "unavailable"` and a process warning names
 * the reason. Verification keeps working from local state (the token's own
 * short expiry is the floor), which is why this degrades rather than refuses
 * to start.
 */

import type { AuthContext, Principal } from './domain.ts';
import type { IdentityProvider } from './identity.ts';
import type { RevocationChannel } from './incident.ts';
import { buildWorldAsync, type World } from './scenario.ts';
import { createRestApi, type RestApi, type StaticPage } from './rest-api.ts';
import { CapabilityRequestService } from './capability-request.ts';

export interface RestServerOptions {
  readonly idp: IdentityProvider;
  /** Maps a VERIFIED AuthContext to a registered Principal; the only principal source. */
  readonly resolvePrincipal: (auth: AuthContext) => Principal | undefined;
  /** H13: inject the shared channel (tests/federation); default follows the event store. */
  readonly channel?: RevocationChannel;
  readonly revocationSyncIntervalMs?: number;
  /** Default false: a server must not mint fixture capabilities into the evidence chain. */
  readonly bootstrap?: boolean;
  readonly sqlitePath?: string;
  readonly host?: string;
  readonly tls?: { readonly key: string; readonly cert: string };
  readonly staticPages?: readonly StaticPage[];
}

export interface RestServer {
  readonly api: RestApi;
  readonly world: World;
  readonly port: number;
}

export async function startRestServer(options: RestServerOptions): Promise<RestServer> {
  const world = await buildWorldAsync({
    ...(options.sqlitePath !== undefined ? { sqlitePath: options.sqlitePath } : {}),
    ...(options.channel !== undefined ? { channel: options.channel } : {}),
    ...(options.revocationSyncIntervalMs !== undefined
      ? { revocationSyncIntervalMs: options.revocationSyncIntervalMs }
      : {}),
    identity: options.idp,
    bootstrap: options.bootstrap ?? false,
  });

  if (world.revocationAttachError !== undefined) {
    process.emitWarning?.(`revocation feed not attached: ${world.revocationAttachError}`);
  }

  const api = createRestApi({
    authorization: world.authorization,
    idp: options.idp,
    eventLog: world.eventLog,
    resolvePrincipal: options.resolvePrincipal,
    sessions: world.sessions,
    requests: new CapabilityRequestService(world.eventLog, world.authorization, world.root, world.clock.now),
    audit: world.audit,
    health: world.health,
    // H13: converge on the channel once per authorized request, like the
    // embedder-wired hook the incident runbook describes.
    incidentSync: () => {
      world.incident.sync();
    },
    revocationHealth: () =>
      world.revocationAttached && world.revocation.health().errors === 0 ? 'ok' : 'unavailable',
    ...(options.host !== undefined ? { host: options.host } : {}),
    ...(options.tls !== undefined ? { tls: options.tls } : {}),
    ...(options.staticPages !== undefined ? { staticPages: options.staticPages } : {}),
  });

  const port = await api.start();
  return { api, world, port };
}
