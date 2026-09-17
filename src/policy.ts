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
  classificationRank,
} from './domain.ts';

export interface PrincipalMatch {
  readonly kinds?: readonly PrincipalKind[];
  readonly ids?: readonly string[];
  readonly roles?: readonly string[];
}

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

function matchesPrincipal(m: PrincipalMatch, p: Principal): boolean {
  if (m.kinds && !m.kinds.includes(p.kind)) return false;
  if (m.ids && !m.ids.includes(p.id)) return false;
  if (m.roles && !m.roles.some((r) => p.roles.includes(r))) return false;
  return true;
}

function matchesResource(m: ResourceMatch, r: Resource, cache: Map<string, IdPatternMatcher>): boolean {
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

function approvalApplies(approvals: readonly Approval[], ctx: EvaluationContext): boolean {
  return approvals.some(
    (a) =>
      a.principalId === ctx.principal.id &&
      a.action === ctx.action &&
      a.resourceId === ctx.resource.id &&
      a.expiresAt > ctx.now,
  );
}

function conditionHolds(c: Condition, ctx: EvaluationContext): boolean {
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

export function createPolicyEngine(rules: readonly PolicyRule[], id = 'in-process-rego-free-v1'): PolicyEngine & { _compileCacheSize(): number } {
  const cache = new Map<string, IdPatternMatcher>();
  for (const rule of rules) {
    const patterns = rule.resources.idPatterns;
    if (!patterns) continue;
    for (const p of patterns) {
      if (!cache.has(p)) cache.set(p, compileIdPattern(p));
    }
  }

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
        if (!matchesPrincipal(rule.principals, ctx.principal)) continue;
        if (!matchesAction(rule, ctx.action)) continue;
        if (!matchesResource(rule.resources, ctx.resource, cache)) continue;

        if (rule.requiresApproval && !approvalApplies(ctx.approvals ?? [], ctx)) continue;
        if (rule.conditions && !rule.conditions.every((c) => conditionHolds(c, ctx))) continue;
        if (rule.maxClassification !== undefined) {
          // The resource must sit at or beneath the ceiling this rule grants.
          if (classificationRank(ctx.resource.classification) > classificationRank(rule.maxClassification)) {
            continue;
          }
        }

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
