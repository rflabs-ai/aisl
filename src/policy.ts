/**
 * Policy engine (PDP core).
 *
 * ADR-001: policy-as-data evaluated by a pure, in-process, side-effect-free
 * function. See DECISIONS.md for the Cedar / OPA comparison and the migration
 * path. Two properties matter more than expressiveness here:
 *   1. default deny  — no matching allow rule means deny, always.
 *   2. deny overrides — one matching deny rule beats every matching allow rule.
 */

import {
  type Action,
  type AuthContext,
  type Classification,
  type Principal,
  type PrincipalKind,
  type Resource,
  type ResourceType,
  type Role,
  classificationRank,
} from './domain.ts';

export interface PrincipalMatch {
  readonly kinds?: readonly PrincipalKind[];
  readonly ids?: readonly string[];
  readonly roles?: readonly string[];
}

/** Bumped whenever the baseline role table changes shape. */
export const ROLE_TABLE_VERSION = 1;

/**
 * Baseline roles. Tenant-agnostic ('*'): they bound what a holder may be
 * granted — never what they hold. Roles narrow authority; they do not mint it.
 */
export const BASELINE_ROLES: readonly Role[] = [
  {
    id: 'worker',
    tenantId: '*',
    description: 'Read/write work over internal-and-below material.',
    actions: ['read', 'write'],
    maxClassification: 'internal',
  },
  {
    id: 'reader',
    tenantId: '*',
    description: 'Read-only over internal-and-below material.',
    actions: ['read'],
    maxClassification: 'internal',
  },
  {
    id: 'reviewer',
    tenantId: '*',
    description: 'Human approval over restricted-and-below material.',
    actions: ['task.approve'],
    maxClassification: 'restricted',
  },
];

/**
 * Hierarchical resource matching (M5).
 *
 * Pattern grammar (compiled once when the engine is built, cached by string):
 *
 *   `tenant/...`   recursive — any id strictly under `tenant/` (slash is the boundary).
 *                  `acme/...` matches `acme/foo`, `acme/foo/bar`; it does NOT match
 *                  `acme-other` (no slash) or `acme` (no children).
 *   `prefix*`      single-segment glob — `*` matches a run of non-slash characters.
 *                  `acme/*` matches `acme/foo` but NOT `acme/foo/bar`.
 *   `prefix?`      single-character wildcard — `?` matches one non-slash character.
 *   literal        exact match (no wildcard).
 *
 * Patterns wider than 64 chars, with nested wildcards (`**`), or with unsupported
 * characters throw `PolicyCompilationError` at engine construction. The hot path
 * never compiles; on a defensive cache miss it falls back to literal match and
 * emits one stderr warning.
 *
 * Hierarchical matching widens which RULES apply. It does NOT widen which
 * resources a CAPABILITY may reach — capabilities still list explicit ids
 * (`Capability.resourceIds`).
 */
export interface ResourceMatch {
  readonly types?: readonly ResourceType[];
  readonly ids?: readonly string[];
  /** Hierarchical match patterns. A pattern matches a resource id when any
   *  of the listed patterns matches. Patterns are tried in order; first match wins.
   *  See the grammar in the header comment above. */
  readonly idPatterns?: readonly string[];
  /** Resource classification is at or below this ceiling. */
  readonly maxClassification?: Classification;
}

export type IdPatternMatcher =
  | { readonly kind: 'literal'; readonly value: string }
  | { readonly kind: 'recursive'; readonly prefix: string }
  | { readonly kind: 'glob'; readonly regex: RegExp };

export class PolicyCompilationError extends Error {
  readonly pattern: string;
  constructor(message: string, pattern: string) {
    super(message);
    this.name = 'PolicyCompilationError';
    this.pattern = pattern;
  }
}

const MAX_PATTERN_LEN = 64;
const PATTERN_ALLOWED = /^[A-Za-z0-9._\-/*?]+$/;

export function compileIdPattern(pattern: string): IdPatternMatcher {
  if (pattern.length === 0) throw new PolicyCompilationError('pattern must be non-empty', pattern);
  if (pattern.length > MAX_PATTERN_LEN) throw new PolicyCompilationError(`pattern exceeds ${MAX_PATTERN_LEN} chars (got ${pattern.length})`, pattern);
  if (pattern.includes('**')) throw new PolicyCompilationError('nested wildcards (**) are not supported', pattern);
  if (!PATTERN_ALLOWED.test(pattern)) throw new PolicyCompilationError(`pattern contains unsupported characters: "${pattern}"`, pattern);

  if (pattern.endsWith('...')) {
    const prefix = pattern.slice(0, -3);
    if (!prefix.endsWith('/')) throw new PolicyCompilationError(`recursive pattern must end with '/' before '...': "${pattern}"`, pattern);
    return { kind: 'recursive', prefix };
  }

  if (pattern.includes('*') || pattern.includes('?')) {
    let re = '^';
    for (const ch of pattern) {
      if (ch === '*') re += '[^/]*';
      else if (ch === '?') re += '[^/]';
      else re += ch.replace(/[.+^${}()|[\]\\]/g, '\\$&');
    }
    re += '$';
    return { kind: 'glob', regex: new RegExp(re) };
  }

  return { kind: 'literal', value: pattern };
}

export function matchesIdPattern(resourceId: string, matcher: IdPatternMatcher): boolean {
  switch (matcher.kind) {
    case 'literal':
      return resourceId === matcher.value;
    case 'recursive':
      return resourceId.length > matcher.prefix.length && resourceId.startsWith(matcher.prefix);
    case 'glob':
      return matcher.regex.test(resourceId);
  }
}

export type Condition =
  | { readonly kind: 'before'; readonly iso: string }
  | { readonly kind: 'after'; readonly iso: string }
  | { readonly kind: 'param-equals'; readonly key: string; readonly value: string | number | boolean }
  | { readonly kind: 'approval-present' }
  | { readonly kind: 'network-host-in'; readonly hosts: readonly string[] };

export interface PolicyRule {
  readonly id: string;
  readonly description?: string;
  readonly effect: 'allow' | 'deny';
  readonly principals: PrincipalMatch;
  /** Exact action names, or '*' for all. */
  readonly actions: readonly (Action | '*')[];
  readonly resources: ResourceMatch;
  readonly conditions?: readonly Condition[];
  /** Subject may not exceed this classification even if the rule otherwise matches. */
  readonly maxClassification?: Classification;
  /** Requires a separate human approval record in the evaluation context. */
  readonly requiresApproval?: boolean;
}

/**
 * M2 Approval: an approval is a non-repudiable record bound to an authenticated
 * human who passed MFA. The reviewerAuth field is required — an approval without
 * an authenticated reviewer is structurally invalid.
 */
export interface Approval {
  readonly id: string;
  /** Principal id of the human who approved */
  readonly approvedBy: string;
  /** The authenticated human's AuthContext — proves identity and MFA */
  readonly reviewerAuth: AuthContext;
  /** Principal that is being approved to act */
  readonly principalId: string;
  readonly action: Action;
  readonly resourceId: string;
  readonly expiresAt: number;
  /** Session id this approval is bound to (empty for unbound) */
  readonly sessionId?: string;
  /** Link to the originating capability request */
  readonly capabilityRequestId?: string;
}

export interface EvaluationContext {
  readonly principal: Principal;
  readonly resource: Resource;
  readonly action: Action;
  readonly now: number;
  readonly params?: Readonly<Record<string, unknown>>;
  readonly approvals?: readonly Approval[];
  readonly networkHost?: string;
}

export interface PolicyResult {
  readonly effect: 'allow' | 'deny';
  readonly ruleId: string | undefined;
  readonly reason: string;
}

export interface PolicyEngine {
  readonly id: string;
  evaluate(ctx: EvaluationContext): PolicyResult;
}

/**
 * The subset of an evaluation context a rule matcher actually reads. `Principal`
 * and `EvaluationContext` satisfy it structurally, so the runtime passes the
 * full context and the analyzer passes a synthetic one - no casts, no second
 * matcher, and therefore no way for the analyzer's notion of "matches" to
 * diverge from the engine's.
 */
export interface RuleMatchInput {
  readonly principal: Pick<Principal, 'id' | 'kind' | 'tenantId' | 'roles'>;
  readonly resource: Pick<Resource, 'id' | 'type' | 'tenantId' | 'classification'>;
  readonly action: Action;
  readonly now: number;
  readonly params?: Readonly<Record<string, unknown>>;
  readonly approvals?: readonly Approval[];
  readonly networkHost?: string;
}

function matchesPrincipal(m: PrincipalMatch, p: RuleMatchInput['principal']): boolean {
  if (m.kinds && !m.kinds.includes(p.kind)) return false;
  if (m.ids && !m.ids.includes(p.id)) return false;
  if (m.roles && !m.roles.some((r) => p.roles.includes(r))) return false;
  return true;
}

function matchesResource(
  m: ResourceMatch,
  r: RuleMatchInput['resource'],
  cache: Map<string, IdPatternMatcher>,
): boolean {
  if (m.types && !m.types.includes(r.type)) return false;
  if (m.ids !== undefined || m.idPatterns !== undefined) {
    let idMatch = false;
    if (m.ids !== undefined && m.ids.includes(r.id)) idMatch = true;
    if (!idMatch && m.idPatterns !== undefined) {
      for (const p of m.idPatterns) {
        const matcher = cache.get(p) ?? compileOnCacheMiss(p, cache);
        if (matchesIdPattern(r.id, matcher)) {
          idMatch = true;
          break;
        }
      }
    }
    if (!idMatch) return false;
  }
  if (m.maxClassification !== undefined) {
    if (classificationRank(r.classification) > classificationRank(m.maxClassification)) return false;
  }
  return true;
}

// ponytail: defensive cache miss on hot path. Should never fire — rules are
// compiled at engine construction. Falls back to literal so a bad rule cannot
// widen matches; emits one warning so the bug is visible in logs.
function compileOnCacheMiss(pattern: string, cache: Map<string, IdPatternMatcher>): IdPatternMatcher {
  process.stderr.write(`warning: idPattern cache miss for "${pattern}", falling back to literal match\n`);
  const fallback: IdPatternMatcher = { kind: 'literal', value: pattern };
  cache.set(pattern, fallback);
  return fallback;
}

function matchesAction(rule: PolicyRule, action: Action): boolean {
  return rule.actions.includes('*') || rule.actions.includes(action);
}

function approvalApplies(approvals: readonly Approval[], ctx: RuleMatchInput): boolean {
  return approvals.some(
    (a) =>
      a.principalId === ctx.principal.id &&
      a.action === ctx.action &&
      a.resourceId === ctx.resource.id &&
      a.expiresAt > ctx.now,
  );
}

function conditionHolds(c: Condition, ctx: RuleMatchInput): boolean {
  switch (c.kind) {
    case 'before':
      return ctx.now < Date.parse(c.iso);
    case 'after':
      return ctx.now > Date.parse(c.iso);
    case 'param-equals':
      return ctx.params?.[c.key] === c.value;
    case 'approval-present':
      return approvalApplies(ctx.approvals ?? [], ctx);
    case 'network-host-in':
      return ctx.networkHost !== undefined && c.hosts.includes(ctx.networkHost);
  }
}

const NO_MATCH: PolicyResult = {
  effect: 'deny',
  ruleId: undefined,
  reason: 'no matching allow rule; default deny',
};

/**
 * Does this rule apply to this context? The single matcher used by both the
 * engine's hot path and `analyzePolicy` (H3, ADR-034). Behaviour-preserving
 * extraction: `evaluate` below applies the effect, this decides applicability.
 */
export function matchesRule(
  rule: PolicyRule,
  ctx: RuleMatchInput,
  cache: Map<string, IdPatternMatcher>,
): boolean {
  if (!matchesPrincipal(rule.principals, ctx.principal)) return false;
  if (!matchesAction(rule, ctx.action)) return false;
  if (!matchesResource(rule.resources, ctx.resource, cache)) return false;
  if (rule.requiresApproval && !approvalApplies(ctx.approvals ?? [], ctx)) return false;
  if (rule.conditions && !rule.conditions.every((c) => conditionHolds(c, ctx))) return false;
  if (rule.maxClassification !== undefined) {
    // The resource must sit at or beneath the ceiling this rule grants.
    if (classificationRank(ctx.resource.classification) > classificationRank(rule.maxClassification)) return false;
  }
  return true;
}

/**
 * Compile every idPattern in a rule set, once. The cache is deliberately
 * required by `matchesRule`: without one, a pattern silently degrades to a
 * literal comparison (the `compileOnCacheMiss` fallback exists so a bad rule
 * cannot *widen* matches), which would make analysis report on a policy nobody
 * runs. Callers that evaluate rules must obtain their cache here.
 */
export function compileRulePatterns(rules: readonly PolicyRule[]): Map<string, IdPatternMatcher> {
  const cache = new Map<string, IdPatternMatcher>();
  for (const rule of rules) {
    for (const p of rule.resources.idPatterns ?? []) {
      if (!cache.has(p)) cache.set(p, compileIdPattern(p));
    }
  }
  return cache;
}

/**
 * M11: allow rules that reference roles are cross-validated against the role
 * table at construction — a rule may never grant what the role does not hold.
 * A wildcard allow cannot be verified against a finite role action set and is
 * rejected outright. Deny rules and roles not in the table (possibly
 * org-defined elsewhere) are not validated. Fail closed, never widen.
 */
function validateRulesAgainstRoles(rules: readonly PolicyRule[], roles: readonly Role[]): void {
  for (const rule of rules) {
    if (rule.effect !== 'allow') continue;
    const roleRefs = rule.principals.roles;
    if (!roleRefs || roleRefs.length === 0) continue;
    for (const roleId of roleRefs) {
      const role = roles.find((r) => r.id === roleId);
      if (!role) continue;
      if (rule.actions.includes('*')) {
        throw new PolicyCompilationError(
          `rule '${rule.id}' grants wildcard actions to role '${roleId}': a wildcard allow cannot be verified against the role's finite action set`,
          roleId,
        );
      }
      const overAction = rule.actions.find((a) => !role.actions.includes(a));
      if (overAction !== undefined) {
        throw new PolicyCompilationError(
          `rule '${rule.id}' grants action '${overAction}' not held by role '${roleId}'`,
          roleId,
        );
      }
      if (
        rule.maxClassification !== undefined &&
        classificationRank(rule.maxClassification) > classificationRank(role.maxClassification)
      ) {
        throw new PolicyCompilationError(
          `rule '${rule.id}' grants classification '${rule.maxClassification}' above role '${roleId}' ceiling '${role.maxClassification}'`,
          roleId,
        );
      }
    }
  }
}

export function createPolicyEngine(
  rules: readonly PolicyRule[],
  id = 'in-process-rego-free-v1',
  roles: readonly Role[] = BASELINE_ROLES,
): PolicyEngine & { _compileCacheSize(): number } {
  const cache = compileRulePatterns(rules);
  validateRulesAgainstRoles(rules, roles);

  return {
    id,
    _compileCacheSize: () => cache.size,
    evaluate(ctx: EvaluationContext): PolicyResult {
      // Hard boundary, independent of any customer-authored rule.
      if (ctx.principal.tenantId !== ctx.resource.tenantId) {
        return { effect: 'deny', ruleId: '@tenant-isolation', reason: 'cross-tenant access denied' };
      }

      let allowed: PolicyRule | undefined;

      for (const rule of rules) {
        if (!matchesRule(rule, ctx, cache)) continue;
        if (rule.effect === 'deny') {
          return { effect: 'deny', ruleId: rule.id, reason: `denied by rule ${rule.id}` };
        }
        allowed ??= rule;
      }

      if (!allowed) return NO_MATCH;
      return { effect: 'allow', ruleId: allowed.id, reason: `allowed by rule ${allowed.id}` };
    },
  };
}

/**
 * Baseline MVP policy set. Allowlist-first: anything not named here is denied.
 * Deliberately contains NO allow rule for `secret.use` or `network.egress`.
 */
export const BASELINE_POLICY: readonly PolicyRule[] = [
  {
    id: 'allow-agent-read-low',
    description: 'Agents may read internal-and-below resources they hold a capability for.',
    effect: 'allow',
    principals: { kinds: ['agent'] },
    actions: ['read'],
    resources: { maxClassification: 'internal' },
  },
  {
    id: 'allow-agent-read-sensitive-with-approval',
    description: 'Reads above internal require a separate human approval record.',
    effect: 'allow',
    principals: { kinds: ['agent'] },
    actions: ['read'],
    resources: {},
    requiresApproval: true,
  },
  {
    id: 'deny-export-restricted',
    description: 'Export of restricted material is never permitted by policy alone.',
    effect: 'deny',
    principals: { kinds: ['agent', 'user', 'service'] },
    actions: ['export'],
    resources: { maxClassification: 'restricted' },
  },
  {
    id: 'allow-user-approve',
    description: 'Humans may record approvals; approval is not execution.',
    effect: 'allow',
    principals: { kinds: ['user'] },
    actions: ['task.approve'],
    resources: {},
  },
];
