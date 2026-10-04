/**
 * Federation anchor route (ADR-022 / M17): `POST /v1/anchors` accepts a foreign
 * evidence-plane head-hash — the M3 anchor pattern applied across repos. The
 * digest is recorded in ASL's OWN append-only signed event log, so an external
 * attestation of the client's log exists independent of the client.
 *
 * Trust boundary: the tenant comes from the verified principal, never trusted
 * from the body (a mismatched `tenant` field is refused, not silently ignored).
 * The payload is a hash + counts only — no project plaintext crosses in.
 *
 * H11 (ADR-031): the accepted head per tenant is rehydrated from the durable
 * `anchor.register` events on construction — mismatch detection survives a
 * restart (the M17 in-memory marker is closed).
 */

import { randomUUID } from 'node:crypto';
import type { Principal } from './domain.ts';
import type { EventStore } from './events.ts';
import { RestRejection, optStr, str, type RestApi, type RestResponse } from './rest-api.ts';

const SHA256_HEX = /^[0-9a-f]{64}$/;

export interface AnchorInput {
  readonly tenant: string;
  readonly headHash: string;
  readonly eventCount: number;
  readonly previousHeadHash?: string;
  readonly anchoredAt: number;
}

export interface RecordedAnchor {
  readonly id: string;
  readonly acceptedAt: number;
  readonly tamper: boolean;
}

export class AnchorRegistry {
  private readonly lastHeadByTenant = new Map<string, string>();
  private readonly eventLog: EventStore;
  private readonly now: () => number;

  constructor(eventLog: EventStore, now: () => number = Date.now) {
    this.eventLog = eventLog;
    this.now = now;
    this.rehydrateAcceptedHeads();
  }

  /**
   * H11 (ADR-031): rebuild the accepted head per tenant from the append-only
   * event log — the durable record is the `anchor.register` event itself. A
   * restarted registry therefore still distinguishes "first anchor" from
   * "lost predecessor" (closes the M17 in-memory ponytail marker).
   */
  private rehydrateAcceptedHeads(): void {
    for (const event of this.eventLog.all()) {
      if (event.action !== 'anchor.register') continue;
      const metadata = event.metadata;
      if (!metadata || metadata.phase !== 'federation-anchor') continue;
      const headHash = metadata.headHash;
      if (typeof headHash === 'string') this.lastHeadByTenant.set(event.tenantId, headHash);
    }
  }

  /**
   * Record one accepted anchor. `tamper` is true when the client's claimed
   * previous head disagrees with the last head we accepted for the tenant —
   * the signal that the client's log was edited after its prior anchor. A
   * mismatch is recorded as evidence and acceptance still returns 201 (the
   * client owns its own fail-closed policy; ASL never blocks on advisory state).
   */
  record(principal: Principal, input: AnchorInput): RecordedAnchor {
    const previous = this.lastHeadByTenant.get(input.tenant);
    const tamper =
      input.previousHeadHash !== undefined && previous !== undefined && input.previousHeadHash !== previous;
    const id = randomUUID();
    const acceptedAt = this.now();

    this.eventLog.append({
      tenantId: input.tenant,
      principal: principal.id,
      actor: principal.id,
      actorKind: principal.kind,
      action: 'anchor.register',
      resourceId: `audit-log:${input.tenant}`,
      result: 'success',
      metadata: {
        phase: 'federation-anchor',
        headHash: input.headHash,
        eventCount: input.eventCount,
        anchoredAt: input.anchoredAt,
        ...(input.previousHeadHash !== undefined ? { previousHeadHash: input.previousHeadHash } : {}),
        ...(tamper ? { tamper: true, expectedHeadHash: previous } : {}),
      },
    });

    // Advance only after the append landed (session-audit ticket 01): a throwing
    // event log must not leave the registry claiming a head the evidence plane
    // never accepted — otherwise the next honest anchor is flagged tamper.
    this.lastHeadByTenant.set(input.tenant, input.headHash);

    return { id, acceptedAt, tamper };
  }
}

function intField(value: unknown, field: string): number {
  if (typeof value !== 'number' || !Number.isInteger(value) || value < 0) {
    throw new RestRejection(400, 'invalid-body', `field '${field}' must be a non-negative integer`);
  }
  return value;
}

function sha256Field(value: unknown, field: string): string {
  const hash = str(value, field);
  if (!SHA256_HEX.test(hash)) throw new RestRejection(400, 'invalid-body', `field '${field}' must be a sha256 hex digest`);
  return hash;
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}

export interface AnchorRouteDeps {
  readonly eventLog: EventStore;
}

export function registerAnchorRoutes(api: RestApi, deps: AnchorRouteDeps): void {
  const registry = new AnchorRegistry(deps.eventLog);

  api.addRoute('POST', '/v1/anchors', (ctx): RestResponse => {
    if (!isRecord(ctx.body)) throw new RestRejection(400, 'invalid-body', 'body must be a JSON object');
    const tenant = str(ctx.body.tenant, 'tenant');
    if (tenant !== ctx.principal.tenantId) throw new RestRejection(403, 'tenant-mismatch');
    const headHash = sha256Field(ctx.body.headHash, 'headHash');
    const rawPrevious = optStr(ctx.body.previousHeadHash, 'previousHeadHash');
    const previousHeadHash = rawPrevious !== undefined ? sha256Field(rawPrevious, 'previousHeadHash') : undefined;
    const eventCount = intField(ctx.body.eventCount, 'eventCount');
    const anchoredAt = intField(ctx.body.anchoredAt, 'anchoredAt');

    const recorded = registry.record(ctx.principal, {
      tenant,
      headHash,
      eventCount,
      ...(previousHeadHash !== undefined ? { previousHeadHash } : {}),
      anchoredAt,
    });

    return {
      status: 201,
      body: {
        id: recorded.id,
        acceptedAt: recorded.acceptedAt,
        ...(recorded.tamper ? { tamper: true } : {}),
      },
    };
  });
}
