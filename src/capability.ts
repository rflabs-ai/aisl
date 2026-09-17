/**
 * Capability model.
 *
 * A capability IS authority. It can only come into existence through
 * `issueCapability`, which structurally refuses to accept a model, a tool, or
 * a document as the issuer. Nothing in this module can parse text into
 * authority — there is no such code path, by construction.
 */

import { createHmac, randomBytes, randomUUID, timingSafeEqual } from 'node:crypto';
import {
  CAPABILITY_ISSUER_KINDS,
  type Action,
  type Classification,
  type DenyReason,
  type Principal,
  type Role,
  classificationRank,
  canonicalJson,
} from './domain.ts';

export type Constraint =
  | { readonly kind: 'network-host'; readonly hosts: readonly string[] }
  | { readonly kind: 'param-equals'; readonly key: string; readonly value: string | number | boolean };

export type CapabilitySource =
  | 'session-bootstrap'
  | 'human-approval'
  | 'policy-grant'
  | 'delegation';

export interface Provenance {
  readonly source: CapabilitySource;
  readonly approvedBy?: string;
  readonly sessionId?: string;
  readonly taskId?: string;
  readonly note?: string;
}

export interface Capability {
  readonly id: string;
  /** Principal id that minted this capability. Never a model, tool, or document. */
  readonly issuer: string;
  readonly issuerKind: string;
  readonly subject: string;
  readonly tenantId: string;
  readonly resourceIds: readonly string[];
  readonly actions: readonly Action[];
  readonly maxClassification: Classification;
  readonly issuedAt: number;
  readonly expiresAt: number;
  readonly singleUse: boolean;
  readonly usedAt?: number;
  readonly constraints: readonly Constraint[];
  readonly provenance: Provenance;
  readonly signature: string;
}

export interface IssueRequest {
  readonly subject: string;
  readonly tenantId: string;
  readonly resourceIds: readonly string[];
  readonly actions: readonly Action[];
  readonly maxClassification: Classification;
  readonly expiresAt: number;
  readonly singleUse?: boolean;
  readonly constraints?: readonly Constraint[];
  readonly provenance: Provenance;
}

/** Authority held by a non-root issuer; used for attenuation checks. */
export interface IssuerAuthority {
  readonly resourceIds: readonly string[];
  readonly actions: readonly Action[];
  readonly maxClassification: Classification;
  readonly expiresAt: number;
}

export class CapabilityIssuanceError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'CapabilityIssuanceError';
  }
}

/**
 * Signing key. Production must supply a KMS/HSM-backed key (ADR-008). Without
 * one we generate an ephemeral key and lose cross-process verification — the
 * system still fails closed, but capabilities are not portable.
 */
let cachedKey: Buffer | undefined;
export function capabilitySigningKey(): Buffer {
  if (cachedKey) return cachedKey;
  const fromEnv = process.env.CAPABILITY_SIGNING_KEY;
  if (fromEnv && fromEnv.length > 0) {
    cachedKey = Buffer.from(fromEnv, 'utf8');
  } else {
    cachedKey = randomBytes(32);
    process.emitWarning?.(
      'CAPABILITY_SIGNING_KEY unset: using ephemeral capability signing key (not durable across restarts)',
    );
  }
  return cachedKey;
}

function signingBody(cap: Omit<Capability, 'signature'>): string {
  return canonicalJson(cap);
}

export function signCapability(cap: Omit<Capability, 'signature'>): string {
  return createHmac('sha256', capabilitySigningKey()).update(signingBody(cap)).digest('hex');
}

function signatureValid(cap: Capability): boolean {
  const expected = signCapability(stripSignature(cap));
  const a = Buffer.from(expected, 'utf8');
  const b = Buffer.from(cap.signature, 'utf8');
  return a.length === b.length && timingSafeEqual(a, b);
}

function stripSignature(cap: Capability): Omit<Capability, 'signature'> {
  const { signature: _signature, ...rest } = cap;
  return rest;
}

/**
 * Mint authority. Invariants 2, 3, 4 and 6 are enforced here and nowhere else.
 */
export function issueCapability(
  issuer: Principal,
  request: IssueRequest,
  now: number,
  issuerAuthority?: IssuerAuthority,
): Capability {
  if (!CAPABILITY_ISSUER_KINDS.includes(issuer.kind)) {
    throw new CapabilityIssuanceError(
      `principal ${issuer.id} of kind '${issuer.kind}' may not issue capabilities`,
    );
  }
  if (issuer.tenantId !== request.tenantId) {
    throw new CapabilityIssuanceError('issuer may not mint capabilities in another tenant');
  }
  if (request.resourceIds.length === 0 || request.actions.length === 0) {
    throw new CapabilityIssuanceError('capability must name at least one resource and action');
  }
  if (request.expiresAt <= now) {
    throw new CapabilityIssuanceError('capability expiry must be in the future');
  }

  // Attenuation: a non-root issuer can only hand out what it already holds.
  if (authorityRequired(issuer)) {
    if (!issuerAuthority) {
      throw new CapabilityIssuanceError(
        `issuer ${issuer.id} (${issuer.kind}) must present its own authority to mint capabilities`,
      );
    }
    const overreach = findOverreach(request, issuerAuthority);
    if (overreach) {
      throw new CapabilityIssuanceError(
        `capability exceeds issuer authority: ${overreach}`,
      );
    }
  }

  const body: Omit<Capability, 'signature'> = {
    id: randomUUID(),
    issuer: issuer.id,
    issuerKind: issuer.kind,
    subject: request.subject,
    tenantId: request.tenantId,
    resourceIds: [...request.resourceIds],
    actions: [...request.actions],
    maxClassification: request.maxClassification,
    issuedAt: now,
    expiresAt: request.expiresAt,
    singleUse: request.singleUse ?? false,
    constraints: request.constraints ?? [],
    provenance: request.provenance,
  };

  return { ...body, signature: signCapability(body) };
}

const ROOT_KIND = 'authorization';
function authorityRequired(issuer: Principal): boolean {
  return issuer.kind !== ROOT_KIND;
}

/** Options for role-templated issuance; the role supplies the ceiling unless the request narrows it. */
export interface RoleIssuanceRequest {
  readonly actions: readonly Action[];
  readonly maxClassification?: Classification;
  readonly expiresAt: number;
  readonly singleUse?: boolean;
  readonly constraints?: readonly Constraint[];
  readonly provenance: Provenance;
}

/**
 * M11: build an IssueRequest bounded by a role. Roles narrow authority — they
 * never mint it, so an over-privileged request throws instead of being capped.
 * The returned request still flows through issueCapability unchanged: issuer
 * kinds, tenant match, and attenuation all apply there and nowhere else.
 */
export function issueRequestForRole(
  roles: readonly Role[],
  issuer: Principal,
  roleId: string,
  subject: string,
  resourceIds: readonly string[],
  request: RoleIssuanceRequest,
): IssueRequest {
  const role = roles.find((r) => r.id === roleId && (r.tenantId === issuer.tenantId || r.tenantId === '*'));
  if (!role) {
    throw new CapabilityIssuanceError(
      `role '${roleId}' is not visible to issuer ${issuer.id} in tenant '${issuer.tenantId}'`,
    );
  }
  if (request.actions.length === 0) {
    throw new CapabilityIssuanceError(`issuance against role '${roleId}' requires at least one action`);
  }
  const outside = request.actions.find((a) => !role.actions.includes(a));
  if (outside !== undefined) {
    throw new CapabilityIssuanceError(`action '${outside}' is not held by role '${roleId}'`);
  }
  if (
    request.maxClassification !== undefined &&
    classificationRank(request.maxClassification) > classificationRank(role.maxClassification)
  ) {
    throw new CapabilityIssuanceError(
      `classification '${request.maxClassification}' exceeds role '${roleId}' ceiling '${role.maxClassification}'`,
    );
  }
  return {
    subject,
    tenantId: issuer.tenantId,
    resourceIds: [...resourceIds],
    actions: [...request.actions],
    maxClassification: request.maxClassification ?? role.maxClassification,
    expiresAt: request.expiresAt,
    singleUse: request.singleUse,
    constraints: request.constraints,
    provenance: request.provenance,
  };
}

function findOverreach(request: IssueRequest, authority: IssuerAuthority): string | undefined {
  const missingResource = request.resourceIds.find((r) => !authority.resourceIds.includes(r));
  if (missingResource) return `resource ${missingResource} not held by issuer`;

  const missingAction = request.actions.find((a) => !authority.actions.includes(a));
  if (missingAction) return `action ${missingAction} not held by issuer`;

  if (classificationRank(request.maxClassification) > classificationRank(authority.maxClassification)) {
    return `classification ${request.maxClassification} exceeds issuer ceiling ${authority.maxClassification}`;
  }
  if (request.expiresAt > authority.expiresAt) {
    return 'expiry exceeds issuer expiry';
  }
  return undefined;
}

export interface VerificationContext {
  readonly subject: string;
  readonly tenantId: string;
  readonly action: Action;
  readonly resourceId: string;
  readonly classification: Classification;
  readonly now: number;
  readonly params?: Readonly<Record<string, unknown>>;
  readonly networkHost?: string;
}

export type CapabilityCheck = { readonly ok: true } | { readonly ok: false; readonly reason: DenyReason; readonly detail: string };

export function verifyCapability(cap: Capability, ctx: VerificationContext): CapabilityCheck {
  if (!signatureValid(cap)) {
    return { ok: false, reason: 'capability-signature-invalid', detail: 'signature mismatch' };
  }
  if (cap.subject !== ctx.subject) {
    return { ok: false, reason: 'capability-scope', detail: 'capability issued to another subject' };
  }
  if (cap.tenantId !== ctx.tenantId) {
    return { ok: false, reason: 'capability-tenant-mismatch', detail: 'capability tenant mismatch' };
  }
  if (ctx.now >= cap.expiresAt) {
    return { ok: false, reason: 'capability-expired', detail: `expired at ${new Date(cap.expiresAt).toISOString()}` };
  }
  if (cap.singleUse && cap.usedAt !== undefined) {
    return { ok: false, reason: 'capability-consumed', detail: 'single-use capability already consumed' };
  }
  if (!cap.resourceIds.includes(ctx.resourceId)) {
    return { ok: false, reason: 'capability-scope', detail: `resource ${ctx.resourceId} outside capability scope` };
  }
  if (!cap.actions.includes(ctx.action)) {
    // M6 (Claim 21): a capability holding query.audit also authorizes audit.export;
    // policy still lists both actions explicitly. Mirror of the candidate filter in
    // src/pdp.ts evaluate() — keep the two in sync.
    if (!(ctx.action === 'audit.export' && cap.actions.includes('query.audit'))) {
      return { ok: false, reason: 'capability-scope', detail: `action ${ctx.action} outside capability scope` };
    }
  }
  if (classificationRank(ctx.classification) > classificationRank(cap.maxClassification)) {
    return {
      ok: false,
      reason: 'classification-ceiling',
      detail: `resource classification ${ctx.classification} exceeds capability ceiling ${cap.maxClassification}`,
    };
  }
  for (const c of cap.constraints) {
    if (c.kind === 'network-host') {
      if (ctx.networkHost === undefined || !c.hosts.includes(ctx.networkHost)) {
        return {
          ok: false,
          reason: 'capability-scope',
          detail: `network destination ${ctx.networkHost ?? '(none)'} not permitted`,
        };
      }
    } else if (ctx.params?.[c.key] !== c.value) {
      return { ok: false, reason: 'capability-scope', detail: `constraint ${c.key} not satisfied` };
    }
  }
  return { ok: true };
}

export function markUsed(cap: Capability, now: number): Capability {
  const stripped = stripSignature(cap);
  const next: Omit<Capability, 'signature'> = { ...stripped, usedAt: now };
  return { ...next, signature: signCapability(next) };
}
