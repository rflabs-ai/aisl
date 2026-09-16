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

export interface ResourceMatch {
  readonly types?: readonly ResourceType[];
  readonly ids?: readonly string[];
  /** Resource classification is at or below this ceiling. */
  readonly maxClassification?: Classification;
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

export interface Approval {
  readonly id: string;
  readonly approvedBy: string;
  readonly principalId: string;
  readonly action: Action;
  readonly resourceId: string;
  readonly expiresAt: number;
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

function matchesResource(m: ResourceMatch, r: Resource): boolean {
  if (m.types && !m.types.includes(r.type)) return false;
  if (m.ids && !m.ids.includes(r.id)) return false;
  if (m.maxClassification !== undefined) {
    if (classificationRank(r.classification) > classificationRank(m.maxClassification)) return false;
  }
  return true;
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

export function createPolicyEngine(rules: readonly PolicyRule[], id = 'in-process-rego-free-v1'): PolicyEngine {
  return {
    id,
    evaluate(ctx: EvaluationContext): PolicyResult {
      // Hard boundary, independent of any customer-authored rule.
      if (ctx.principal.tenantId !== ctx.resource.tenantId) {
        return { effect: 'deny', ruleId: '@tenant-isolation', reason: 'cross-tenant access denied' };
      }

      let allowed: PolicyRule | undefined;

      for (const rule of rules) {
        if (!matchesPrincipal(rule.principals, ctx.principal)) continue;
        if (!matchesAction(rule, ctx.action)) continue;
        if (!matchesResource(rule.resources, ctx.resource)) continue;

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
