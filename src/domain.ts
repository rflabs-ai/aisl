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

export interface Principal {
  readonly id: string;
  readonly kind: PrincipalKind;
  readonly tenantId: string;
  readonly roles: readonly string[];
  readonly attributes: Readonly<Record<string, string | number | boolean>>;
}

export type KnownClassification =
  | 'public'
  | 'internal'
  | 'confidential'
  | 'restricted'
  | 'pii'
  | 'phi'
  | 'privileged-legal'
  | 'financial'
  | 'trade-secret';

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
  | 'system';

export interface Resource {
  readonly id: string;
  readonly type: ResourceType;
  readonly tenantId: string;
  readonly classification: Classification;
  readonly attributes: Readonly<Record<string, string | number | boolean>>;
}

export type KnownAction =
  | 'read'
  | 'write'
  | 'delete'
  | 'execute'
  | 'invoke'
  | 'export'
  | 'network.egress'
  | 'secret.use'
  | 'capability.issue'
  | 'task.approve';

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
  | 'policy-deny'
  | 'tenant-mismatch'
  | 'evaluation-error'
  | 'evidence-write-failure'
  | 'issuer-not-permitted'
  | 'issuer-insufficient-authority'
  | 'unknown-resource';

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
