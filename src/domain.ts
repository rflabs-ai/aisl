/**
 * Shared domain vocabulary.
 *
 * The single most important type-level rule in this file:
 *   `ActionRequest` (what a model, document, or tool may produce) has NO field
 *   that carries authority. `Capability` (authority) can only be constructed by
 *   `issueCapability` in ./capability.ts. The two types are never convertible.
 */

export type PrincipalKind =
  | 'user'
  | 'service'
  | 'authorization'
  | 'agent'
  | 'model'
  | 'tool';

/** Principals permitted to *issue* authority. Everything else is structurally excluded. */
export const CAPABILITY_ISSUER_KINDS: readonly PrincipalKind[] = [
  'authorization',
  'user',
  'service',
];

/** Principals that may act but may never mint authority. */
export const NON_AUTHORITY_KINDS: readonly PrincipalKind[] = ['model', 'tool', 'agent'];

/**
 * Authentication context: proof that this principal authenticated via a trusted
 * IdP. Produced ONLY by IdentityProvider.verifyToken or derived from a verified
 * parent by IdentityProvider.workloadAuth (src/identity.ts).
 * M2 structural guarantee: the PDP rejects any principal whose auth field is
 * undefined.
 */
export interface AuthContext {
  /** OIDC issuer URL */
  readonly issuer: string;
  /** Subject identifier from the IdP (sub claim) */
  readonly subject: string;
  /** Expected audience */
  readonly audience: string;
  /** Token expiry as epoch milliseconds */
  readonly expiresAt: number;
  /** Token issuance time as epoch milliseconds */
  readonly issuedAt: number;
  /** Unique token identifier (jti claim) */
  readonly tokenId: string;
  /** Time the user authenticated (auth_time claim) */
  readonly authTime: number;
  /** Authentication Methods References — must include MFA for approvals */
  readonly amr: readonly string[];
  /** Authentication Context Class Reference */
  readonly acr?: string;
  /** Full JWT payload for extensibility */
  readonly claims: Readonly<Record<string, unknown>>;
  /** When this token was verified by the runtime */
  readonly verifiedAt: number;
  /**
   * H2 (ADR-028): set when this context was derived from a verified parent
   * (workload identity). Absent on IdP-verified contexts.
   */
  readonly derivedFrom?: {
    readonly subject: string;
    readonly tokenId: string;
  };
}

export interface Principal {
  readonly id: string;
  readonly kind: PrincipalKind;
  readonly tenantId: string;
  readonly roles: readonly string[];
  readonly attributes: Readonly<Record<string, string | number | boolean>>;
  /**
   * M2: authentication context from the IdP. Undefined means unauthenticated.
   * The PDP MUST reject principals where auth is undefined — this is enforced
   * in pdp.ts authorize() as a single guard, not per-caller.
   */
  readonly auth?: AuthContext;
}

/** Type guard: principal carries a valid, non-expired AuthContext. */
export function isAuthenticated(p: Principal, now: number): p is Principal & { readonly auth: AuthContext } {
  return p.auth !== undefined && p.auth.expiresAt > now;
}

/**
 * A role is data, not code: a named bundle of actions bounded by a
 * classification ceiling. Roles narrow authority — they never mint it.
 */
export interface Role {
  readonly id: string;
  /** '*' = tenant-agnostic baseline role */
  readonly tenantId: string;
  readonly description?: string;
  readonly actions: readonly Action[];
  readonly maxClassification: Classification;
}

/** Single source of truth: the type is derived from the list, never duplicated. */
export const KNOWN_CLASSIFICATIONS = [
  'public',
  'internal',
  'confidential',
  'restricted',
  'pii',
  'phi',
  'privileged-legal',
  'financial',
  'trade-secret',
] as const;

export type KnownClassification = (typeof KNOWN_CLASSIFICATIONS)[number];

/** Extensible: orgs may define `x-nato`, `x-customer-acme`, ... */
export type Classification = KnownClassification | (string & {});

/**
 * Fail-closed ranking. Any classification we do not explicitly know is ranked
 * at the ceiling, so a typo or a new org-specific label can never silently
 * downgrade a resource to "less sensitive".
 */
const CLASSIFICATION_RANK: Record<string, number> = {
  public: 0,
  internal: 1,
  confidential: 2,
  financial: 3,
  pii: 3,
  'privileged-legal': 4,
  'trade-secret': 4,
  phi: 4,
  restricted: 5,
};

export const UNKNOWN_CLASSIFICATION_RANK = 100;

export function classificationRank(c: Classification): number {
  return CLASSIFICATION_RANK[c] ?? UNKNOWN_CLASSIFICATION_RANK;
}

export type ResourceType =
  | 'repository'
  | 'file'
  | 'document'
  | 'database'
  | 'api'
  | 'secret'
  | 'network-destination'
  | 'system'
  | 'audit-log';

export interface Resource {
  readonly id: string;
  readonly type: ResourceType;
  readonly tenantId: string;
  readonly classification: Classification;
  readonly attributes: Readonly<Record<string, string | number | boolean>>;
}

/** Single source of truth: the type is derived from the list, never duplicated. */
export const KNOWN_ACTIONS = [
  'read',
  'write',
  'delete',
  'execute',
  'invoke',
  'export',
  'network.egress',
  'secret.use',
  'capability.issue',
  'task.approve',
  'evidence.decrypt',
  'query.audit',
  'audit.export',
  'anchor.register',
  'evidence.hold',
  'evidence.release',
] as const;

export type KnownAction = (typeof KNOWN_ACTIONS)[number];

export type Action = KnownAction | (string & {});

/**
 * A request for an action. Produced by models, derived from documents, emitted
 * by tools. Carries intent only — never authority.
 */
export interface ActionRequest {
  readonly action: Action;
  readonly resourceId: string;
  readonly params?: Readonly<Record<string, unknown>>;
  readonly justification?: string;
}

export type Decision = 'allow' | 'deny';

export type DenyReason =
  | 'no-capability'
  | 'capability-expired'
  | 'capability-consumed'
  | 'capability-scope'
  | 'capability-signature-invalid'
  | 'capability-tenant-mismatch'
  | 'classification-ceiling'
  /** H7: content-level egress DLP refused the payload (canary, volume). */
  | 'dlp-refused'
  /** Safety gate: the daily provider budget is spent; refuse before billing. */
  | 'budget-exhausted'
  | 'policy-deny'
  | 'tenant-mismatch'
  | 'evaluation-error'
  | 'evidence-write-failure'
  | 'store-unavailable'
  | 'clock-unavailable'
  | 'issuer-not-permitted'
  | 'issuer-insufficient-authority'
  | 'unknown-resource'
  | 'unauthenticated-principal'
  | 'idp-unavailable'
  | 'session-revoked'
  | 'approval-mfa-required'
  | 'approval-session-bound'
  | 'capability-revoked'
  | 'capability-request-denied'
  | 'incident-frozen';

export interface AuthorizationDecision {
  readonly decision: Decision;
  readonly reason: string;
  readonly denyReason?: DenyReason;
  readonly policyId?: string;
  readonly capabilityId?: string;
  readonly principal: string;
  readonly action: Action;
  readonly resourceId: string;
  readonly evaluatedAt: number;
}

export function deny(
  principal: string,
  action: Action,
  resourceId: string,
  denyReason: DenyReason,
  reason: string,
  evaluatedAt: number,
  policyId?: string,
): AuthorizationDecision {
  return {
    decision: 'deny',
    reason,
    denyReason,
    policyId,
    principal,
    action,
    resourceId,
    evaluatedAt,
  };
}

export function allow(
  principal: string,
  action: Action,
  resourceId: string,
  reason: string,
  evaluatedAt: number,
  capabilityId: string,
  policyId: string,
): AuthorizationDecision {
  return {
    decision: 'allow',
    reason,
    policyId,
    capabilityId,
    principal,
    action,
    resourceId,
    evaluatedAt,
  };
}

/** Deterministic JSON so hashes are stable across runs and platforms. */
export function canonicalJson(value: unknown): string {
  if (value === null || typeof value !== 'object') return JSON.stringify(value) ?? 'null';
  if (Array.isArray(value)) return `[${value.map(canonicalJson).join(',')}]`;
  const obj = value as Record<string, unknown>;
  const keys = Object.keys(obj).sort();
  return `{${keys.map((k) => `${JSON.stringify(k)}:${canonicalJson(obj[k])}`).join(',')}}`;
}
