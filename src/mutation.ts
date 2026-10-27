/**
 * Mutation testing on policy (H14, ADR-035).
 *
 * A mutated policy that the golden decision set cannot tell apart from the real
 * one means one of two things: the goldens have a coverage hole, or the mutant
 * is semantically equivalent. The first is worth fixing, the second is worth
 * allowlisting with a reason — and neither is visible without generating the
 * mutants.
 *
 * Mutants are derived from the rule set, so the run is bounded and
 * deterministic. They are the mistakes a reviewer actually makes: a flipped
 * effect, a widened ceiling, a dropped approval requirement, a dropped
 * condition, a principal restriction that never got written.
 */

import { KNOWN_CLASSIFICATIONS, canonicalJson, classificationRank, type Classification } from './domain.ts';
import type { PolicyRule } from './policy.ts';
import { verifyGolden, type Golden } from './policy-testing.ts';

export type MutationKind =
  | 'drop-rule'
  | 'flip-effect'
  | 'widen-actions'
  | 'drop-ceiling'
  | 'widen-ceiling'
  | 'drop-approval'
  | 'drop-condition'
  | 'widen-principals';

export interface Mutant {
  /** Stable identity: `<ruleId>:<kind>` (conditions add an index). */
  readonly id: string;
  readonly ruleId: string;
  readonly kind: MutationKind;
  readonly description: string;
  readonly rules: readonly PolicyRule[];
}

export interface MutantResult {
  readonly mutant: Mutant;
  readonly killed: boolean;
  /** Indices of the golden expectations that disagree with this mutant. */
  readonly killedBy: readonly number[];
}

function above(level: Classification): Classification {
  const rank = classificationRank(level);
  return KNOWN_CLASSIFICATIONS.find((c) => classificationRank(c) > rank) ?? level;
}

/** One mutation applied to one rule; `undefined` when it would change nothing. */
function apply(rule: PolicyRule, kind: MutationKind, conditionIndex?: number): PolicyRule | undefined {
  switch (kind) {
    case 'flip-effect':
      return { ...rule, effect: rule.effect === 'allow' ? 'deny' : 'allow' };
    case 'widen-actions':
      return rule.actions.includes('*') ? undefined : { ...rule, actions: ['*'] };
    case 'drop-ceiling':
      return rule.maxClassification === undefined ? undefined : { ...rule, maxClassification: undefined };
    case 'widen-ceiling': {
      if (rule.maxClassification === undefined) return undefined;
      const wider = above(rule.maxClassification);
      return wider === rule.maxClassification ? undefined : { ...rule, maxClassification: wider };
    }
    case 'drop-approval':
      return rule.requiresApproval ? { ...rule, requiresApproval: undefined } : undefined;
    case 'drop-condition': {
      const conditions = rule.conditions;
      if (!conditions || conditionIndex === undefined || conditionIndex >= conditions.length) return undefined;
      const next = conditions.filter((_, i) => i !== conditionIndex);
      return { ...rule, conditions: next.length > 0 ? next : undefined };
    }
    case 'widen-principals':
      return rule.principals.kinds === undefined &&
        rule.principals.ids === undefined &&
        rule.principals.roles === undefined
        ? undefined
        : { ...rule, principals: {} };
    case 'drop-rule':
      return undefined; // handled at the rule-set level
  }
}

/** Every mutant of this rule set. A mutation that changes nothing is not emitted. */
export function mutateRules(rules: readonly PolicyRule[]): readonly Mutant[] {
  const out: Mutant[] = [];
  const kinds: readonly MutationKind[] = [
    'flip-effect',
    'widen-actions',
    'drop-ceiling',
    'widen-ceiling',
    'drop-approval',
    'drop-condition',
    'widen-principals',
  ];

  for (const rule of rules) {
    out.push({
      id: `${rule.id}:drop-rule`,
      ruleId: rule.id,
      kind: 'drop-rule',
      description: `delete rule ${rule.id}`,
      rules: rules.filter((r) => r !== rule),
    });

    for (const kind of kinds) {
      const indexes = kind === 'drop-condition' ? (rule.conditions ?? []).map((_, i) => i) : [undefined];
      for (const index of indexes) {
        const mutated = apply(rule, kind, index);
        if (mutated === undefined) continue;
        if (canonicalJson(mutated) === canonicalJson(rule)) continue;
        const suffix = index === undefined ? '' : `[${index}]`;
        out.push({
          id: `${rule.id}:${kind}${suffix}`,
          ruleId: rule.id,
          kind,
          description: `${kind.replace(/-/g, ' ')} on ${rule.id}${suffix}`,
          rules: rules.map((r) => (r === rule ? mutated : r)),
        });
      }
    }
  }
  return out;
}

/** Killed = the golden set disagrees with the mutant somewhere. */
export function evaluateMutants(mutants: readonly Mutant[], golden: Golden): readonly MutantResult[] {
  return mutants.map((mutant) => {
    const verification = verifyGolden({ ...golden, rules: mutant.rules });
    const killedBy = verification.mismatches.map((m) => m.index);
    return { mutant, killed: killedBy.length > 0, killedBy };
  });
}

export interface MutationSummary {
  readonly total: number;
  readonly killed: number;
  /** Mutants the goldens cannot kill, split by whether the allowance names them. */
  readonly survivors: readonly MutantResult[];
  readonly allowlisted: readonly MutantResult[];
  /** Survivors with no allowance entry — these fail the lane. */
  readonly unexpected: readonly MutantResult[];
}

export function summarize(results: readonly MutantResult[], allowlist: readonly { id: string }[] = []): MutationSummary {
  const allowed = new Set(allowlist.map((a) => a.id));
  const survivors = results.filter((r) => !r.killed);
  return {
    total: results.length,
    killed: results.length - survivors.length,
    survivors,
    allowlisted: survivors.filter((r) => allowed.has(r.mutant.id)),
    unexpected: survivors.filter((r) => !allowed.has(r.mutant.id)),
  };
}
