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

/** Single source of truth: the type is derived from the list, never duplicated. */
export const CAPABILITY_SOURCES = [
  'session-bootstrap',
  'human-approval',
  'policy-grant',
  'delegation',
] as const;

export type CapabilitySource = (typeof CAPABILITY_SOURCES)[number];

export interface Provenance {
  readonly source: CapabilitySource;
  readonly approvedBy?: string;
  readonly sessionId?: string;
  readonly taskId?: string;
  readonly note?: string;
  /** H1 (ADR-023): set by issueCapability from the parent capability — never caller-supplied. */
  readonly delegatedFrom?: DelegatedFrom;
}

/** H1 (ADR-023): the recorded chain link — the parent's id and its signature. */
export interface DelegatedFrom {
  readonly id: string;
  readonly signature: string;
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

/** H1 (ADR-023): attenuation authority, DERIVED from the issuer's own signed capability. */
interface HeldAuthority {
  readonly resourceIds: readonly string[];
  readonly actions: readonly Action[];
  readonly maxClassification: Classification;
  readonly expiresAt: number;
  readonly singleUse: boolean;
  readonly constraints: readonly Constraint[];
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
 *
 * H1 (ADR-023): a non-root issuer attenuates against `parent` — its own SIGNED
 * capability — never against a declared object. Authority is derived from the
 * parent; the chain link is recorded in the child's provenance.
 */
export function issueCapability(
  issuer: Principal,
  request: IssueRequest,
  now: number,
  parent?: Capability,
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
  const requestError = issueRequestError(request);
  if (requestError !== undefined) {
    throw new CapabilityIssuanceError(requestError);
  }

  // H1 (ADR-023, audit 02): ANY presented parent must be a live, held,
  // same-tenant, signed capability — regardless of issuer kind. Root's minting
  // power is unchanged; it simply never records a chain link it did not
  // validate.
  if (parent) {
    const parentError = parentValidityError(parent, issuer, now);
    if (parentError) {
      throw new CapabilityIssuanceError(parentError);
    }
  }

  // Attenuation (H1, ADR-023): a non-root issuer can only hand out what it
  // HOLDS, proven by a valid signed capability issued to itself.
  if (authorityRequired(issuer)) {
    if (!parent) {
      throw new CapabilityIssuanceError(
        `issuer ${issuer.id} (${issuer.kind}) must present its own authority — its signed capability — to mint capabilities`,
      );
    }
    const overreach = findOverreach(request, {
      resourceIds: parent.resourceIds,
      actions: parent.actions,
      maxClassification: parent.maxClassification,
      expiresAt: parent.expiresAt,
      singleUse: parent.singleUse,
      constraints: parent.constraints,
    });
    if (overreach) {
      throw new CapabilityIssuanceError(
        `capability exceeds issuer authority: ${overreach}`,
      );
    }
  }

  const provenance: Provenance = parent
    ? { ...request.provenance, delegatedFrom: { id: parent.id, signature: parent.signature } }
    : request.provenance;

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
    provenance,
  };

  return { ...body, signature: signCapability(body) };
}

/**
 * H1 (ADR-023): the parent must be a live, held, same-tenant capability.
 * Order matters: the signature is verified before any field is trusted.
 */
function parentValidityError(parent: Capability, issuer: Principal, now: number): string | undefined {
  if (!signatureValid(parent)) {
    return 'parent capability signature invalid — a delegation parent must be an unmodified signed capability';
  }
  if (parent.subject !== issuer.id) {
    return `parent capability ${parent.id} is held by ${parent.subject}, not issuer ${issuer.id}`;
  }
  if (parent.tenantId !== issuer.tenantId) {
    return 'parent capability is bound to another tenant';
  }
  if (parent.expiresAt <= now) {
    return `parent capability ${parent.id} is expired`;
  }
  if (parent.usedAt !== undefined) {
    return `parent capability ${parent.id} is single-use and already consumed`;
  }
  return undefined;
}

const ROOT_KIND = 'authorization';
function authorityRequired(issuer: Principal): boolean {
  return issuer.kind !== ROOT_KIND;
}

/** Constraint kinds this issuer can evaluate. Anything else would be signed unread. */
const CONSTRAINT_KINDS: ReadonlySet<string> = new Set(['network-host', 'param-equals']);

/**
 * Issuance-time shape check. The type is the contract; a caller that bypasses
 * it (cast, JSON, another language) must still be refused here rather than
 * signing a value the verifier cannot evaluate. A `constraints` entry with an
 * unknown kind is the dangerous case: verifyCapability falls through to the
 * param branch and silently satisfies it.
 */
function issueRequestError(request: IssueRequest): string | undefined {
  if (typeof request.subject !== 'string' || request.subject.trim().length === 0) {
    return 'capability subject must be a non-empty principal id';
  }
  if (request.singleUse !== undefined && typeof request.singleUse !== 'boolean') {
    return 'capability singleUse must be a boolean when present';
  }
  for (const c of request.constraints ?? []) {
    if (!CONSTRAINT_KINDS.has(c.kind)) {
      return `unknown capability constraint kind '${String(c.kind)}'`;
    }
  }
  if (request.provenance === undefined || !CAPABILITY_SOURCES.includes(request.provenance.source)) {
    return `unknown capability provenance source '${String(request.provenance?.source)}'`;
  }
  return undefined;
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

function findOverreach(request: IssueRequest, authority: HeldAuthority): string | undefined {
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

  // H1 (audit 01): the parent's constraints narrow what it holds — a child
  // may narrow further but may not drop any. Network hosts compare as the
  // intersection of the parent's network-host constraints; a child without a
  // network-host constraint is unconstrained where the parent was not.
  const parentHosts = effectiveHostSet(authority.constraints);
  if (parentHosts !== undefined) {
    const childHosts = effectiveHostSet(request.constraints ?? []);
    if (childHosts === undefined) {
      return 'network constraint not held by issuer';
    }
    const escaped = [...childHosts].find((h) => !parentHosts.has(h));
    if (escaped !== undefined) {
      return `network destination ${escaped} not held by issuer`;
    }
  }
  for (const pc of authority.constraints) {
    if (pc.kind !== 'param-equals') continue;
    const held = (request.constraints ?? []).some(
      (c) => c.kind === 'param-equals' && c.key === pc.key && c.value === pc.value,
    );
    if (!held) return `constraint ${pc.key} not held by issuer`;
  }

  // H1 (audit 01): a single-use capability is a leaf authority — it exists to
  // be consumed once, so it cannot delegate at all.
  if (authority.singleUse) {
    return 'single-use capability cannot delegate';
  }
  return undefined;
}

/** Intersection of every network-host constraint's host set; undefined = unconstrained. */
function effectiveHostSet(constraints: readonly Constraint[]): Set<string> | undefined {
  let acc: Set<string> | undefined;
  for (const c of constraints) {
    if (c.kind !== 'network-host') continue;
    acc = acc === undefined ? new Set(c.hosts) : new Set([...acc].filter((h) => c.hosts.includes(h)));
  }
  return acc;
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
