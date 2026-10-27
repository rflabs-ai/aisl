/**
 * Static analysis of a policy rule set (H3, ADR-034).
 *
 * Three findings, all computed over a bounded set of representative points
 * derived from the rules themselves:
 *
 *   unreachable      a rule matches no representative point — dead policy
 *   shadowed         every point an allow rule matches is also denied by
 *                    another rule, so the allow can never take effect
 *   ambiguous-allow  two allow rules match the same point, so *which* rule is
 *                    credited (ruleId + reason in the evidence log) follows
 *                    declaration order
 *
 * This is a sampler, not a decision procedure: it can miss a conflict that
 * only exists at a point it never generates, and it can never prove absence.
 * Its value is that it catches the deadly and the dead — a typo'd action, a
 * rule that grants nothing, an allow entombed under a deny.
 *
 * It uses `matchesRule` from the engine, never a re-implementation: an
 * analyzer with its own matcher would report on a policy nobody runs.
 */

import {
  KNOWN_ACTIONS,
  KNOWN_CLASSIFICATIONS,
  classificationRank,
  type Action,
  type Classification,
  type ResourceType,
} from './domain.ts';
import {
  compileRulePatterns,
  matchesRule,
  type Approval,
  type PolicyRule,
  type RuleMatchInput,
} from './policy.ts';

export type FindingKind = 'unreachable' | 'shadowed' | 'ambiguous-allow' | 'unknown-action';

export interface PolicyFinding {
  readonly severity: 'error' | 'warn';
  readonly kind: FindingKind;
  readonly rules: readonly string[];
  readonly detail: string;
}

export interface PolicyAnalysis {
  readonly findings: readonly PolicyFinding[];
  readonly points: number;
  readonly errors: number;
  readonly warnings: number;
}

/** Caps keep the analysis bounded on adversarial rule sets (ADR-034). */
const POINTS_PER_RULE = 256;
const POINTS_TOTAL = 4096;
const TENANT = 'acme';
const FIXED_NOW = Date.UTC(2026, 0, 1);

const NO_AUTH = {
  issuer: 'https://analysis.invalid',
  subject: 'analysis',
  audience: 'analysis',
  expiresAt: FIXED_NOW,
  issuedAt: FIXED_NOW,
  tokenId: 'analysis',
  authTime: FIXED_NOW,
  amr: ['pwd', 'mfa'],
  claims: {},
  verifiedAt: FIXED_NOW,
} as const;

/** Concrete id for a pattern, so `acme/...` is probed at `acme/sample`. */
function concretize(pattern: string): string {
  if (pattern.endsWith('...')) return `${pattern.slice(0, -3)}sample`;
  return pattern.replace(/\*/g, 'sample').replace(/\?/g, 's');
}

function above(level: Classification): Classification {
  const rank = classificationRank(level);
  const next = KNOWN_CLASSIFICATIONS.find((c) => classificationRank(c) > rank);
  return next ?? level;
}

/** A time that satisfies the rule's own window, so a scheduled rule is not "dead". */
function nowFor(rule: PolicyRule): number {
  let now = FIXED_NOW;
  for (const c of rule.conditions ?? []) {
    if (c.kind === 'after') now = Math.max(now, Date.parse(c.iso) + 1);
    if (c.kind === 'before') now = Math.min(now, Date.parse(c.iso) - 1);
  }
  return now;
}

function pointsFor(rule: PolicyRule): RuleMatchInput[] {
  const kinds = rule.principals.kinds ?? ['agent'];
  const ids = rule.principals.ids;
  const roles = rule.principals.roles ?? [];

  const principals = kinds.flatMap((kind) =>
    (ids ?? [`${kind}:sample`]).map((id) => ({ id, kind, tenantId: TENANT, roles })),
  );

  const resourceIds = [...(rule.resources.ids ?? []), ...(rule.resources.idPatterns ?? []).map(concretize)];
  const resourceTypes: readonly ResourceType[] = rule.resources.types ?? ['document'];
  const classifications: Classification[] =
    rule.resources.maxClassification === undefined
      ? ['internal']
      : [rule.resources.maxClassification, above(rule.resources.maxClassification)];

  const resources = (resourceIds.length > 0 ? resourceIds : ['res:sample']).flatMap((id) =>
    resourceTypes.flatMap((type) =>
      classifications.map((classification) => ({ id, type, tenantId: TENANT, classification })),
    ),
  );

  const actions: readonly Action[] = rule.actions.includes('*') ? KNOWN_ACTIONS : rule.actions;

  const params: Record<string, string | number | boolean> = {};
  let networkHost: string | undefined;
  for (const c of rule.conditions ?? []) {
    if (c.kind === 'param-equals') params[c.key] = c.value;
    if (c.kind === 'network-host-in' && networkHost === undefined) networkHost = c.hosts[0];
  }

  const needsApproval =
    rule.requiresApproval === true || (rule.conditions ?? []).some((c) => c.kind === 'approval-present');
  const now = nowFor(rule);

  const out: RuleMatchInput[] = [];
  for (const principal of principals) {
    for (const resource of resources) {
      for (const action of actions) {
        out.push({
          principal,
          resource,
          action,
          now,
          ...(Object.keys(params).length > 0 ? { params } : {}),
          ...(networkHost !== undefined ? { networkHost } : {}),
          ...(needsApproval ? { approvals: [approvalFor(principal.id, action, resource.id, now)] } : {}),
        });
        if (out.length >= POINTS_PER_RULE) return out;
      }
    }
  }
  return out;
}

/** `reviewerAuth` is never read by matching; fixed values keep analysis deterministic. */
function approvalFor(principalId: string, action: Action, resourceId: string, now: number): Approval {
  return {
    id: 'analysis-approval',
    approvedBy: 'user:analysis',
    reviewerAuth: NO_AUTH,
    principalId,
    action,
    resourceId,
    expiresAt: now + 60_000,
  };
}

const pointKey = (p: RuleMatchInput): string =>
  `${p.principal.id}|${p.principal.kind}|${p.principal.roles.join(',')}|${p.resource.id}|${p.resource.type}|${p.resource.classification}|${p.action}|${p.now}|${p.networkHost ?? ''}|${JSON.stringify(p.params ?? {})}|${p.approvals?.length ?? 0}`;

export function analyzePolicy(rules: readonly PolicyRule[]): PolicyAnalysis {
  // Dedupe points across rules: the same context is the same evidence.
  const seen = new Map<string, RuleMatchInput>();
  for (const rule of rules) {
    for (const point of pointsFor(rule)) {
      if (seen.size >= POINTS_TOTAL) break;
      const key = pointKey(point);
      if (!seen.has(key)) seen.set(key, point);
    }
  }
  const points = [...seen.values()];
  // The same compiled cache the engine would build: a bare matcher call would
  // degrade every idPattern to a literal and analyse the wrong policy.
  const cache = compileRulePatterns(rules);

  const matched = new Map<string, number>(rules.map((r) => [r.id, 0]));
  const shadowed = new Map<string, number>(rules.map((r) => [r.id, 0]));
  const ambiguous = new Map<string, readonly string[]>();

  for (const point of points) {
    const hits = rules.filter((r) => matchesRule(r, point, cache));
    if (hits.length === 0) continue;

    const denies = hits.filter((r) => r.effect === 'deny');
    const allows = hits.filter((r) => r.effect === 'allow');

    for (const r of hits) matched.set(r.id, (matched.get(r.id) ?? 0) + 1);
    for (const r of allows) if (denies.length > 0) shadowed.set(r.id, (shadowed.get(r.id) ?? 0) + 1);

    for (let i = 0; i < allows.length; i++) {
      for (let j = i + 1; j < allows.length; j++) {
        const a = allows[i]!;
        const b = allows[j]!;
        const [first, second] = a.id < b.id ? [a.id, b.id] : [b.id, a.id];
        const key = `${first}|${second}`;
        if (!ambiguous.has(key)) ambiguous.set(key, [first, second]);
      }
    }
  }

  const findings: PolicyFinding[] = [];
  for (const rule of rules) {
    // A rule's own declarations generate its points, so it always matches at
    // least one — unless its conditions are contradictory or its window is
    // empty. Typos therefore show up here, not as "unreachable".
    const unknown = rule.actions.filter((a) => a !== '*' && !(KNOWN_ACTIONS as readonly string[]).includes(a));
    if (unknown.length > 0) {
      findings.push({
        severity: 'warn',
        kind: 'unknown-action',
        rules: [rule.id],
        detail: `${rule.id} names action(s) outside the known vocabulary: ${unknown.join(', ')} — no request carries these unless an integration defines them`,
      });
    }

    if ((matched.get(rule.id) ?? 0) === 0) {
      findings.push({
        severity: 'error',
        kind: 'unreachable',
        rules: [rule.id],
        detail: `${rule.id} matches none of the ${points.length} representative points — dead rule (typo'd action, unknown kind, or an empty time window)`,
      });
      continue;
    }
    if (rule.effect === 'allow' && shadowed.get(rule.id) === matched.get(rule.id)) {
      findings.push({
        severity: 'error',
        kind: 'shadowed',
        rules: [rule.id],
        detail: `${rule.id} is denied at every point it matches — a deny rule covers it completely, so it can never grant anything`,
      });
    }
  }
  for (const [key, pair] of ambiguous) {
    findings.push({
      severity: 'warn',
      kind: 'ambiguous-allow',
      rules: pair,
      detail: `${key.replace('|', ' and ')} both allow at the same point — the credited ruleId follows declaration order`,
    });
  }

  const errors = findings.filter((f) => f.severity === 'error').length;
  return { findings, points: points.length, errors, warnings: findings.length - errors };
}

export function formatFindings(analysis: PolicyAnalysis, policyId = 'policy'): string[] {
  const out = [`${policyId}: ${analysis.points} representative points, ${analysis.errors} error(s), ${analysis.warnings} warning(s)`];
  for (const f of analysis.findings) out.push(`  [${f.severity}] ${f.kind}: ${f.detail}`);
  return out;
}
