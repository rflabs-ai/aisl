/**
 * Machine-checked PDP invariants (Stage 3, ADR-042).
 *
 * The thirteen invariants in `security-tests/invariants.test.ts` are examples:
 * each names a scenario and asserts the outcome. That catches the case someone
 * thought of. This module states the same properties as predicates over a
 * *state*, so a test can run the real authorization service across an
 * enumerated state space and assert that no reachable state violates any
 * property — which is what "machine-checked" can honestly mean here: exhaustive
 * over a bounded model, not a proof.
 *
 * The checks are deliberately necessary-and-not-sufficient: the model cannot
 * see inside the policy engine, so "allowed implies a covering capability
 * exists" is provable from the state, while "the policy intended this" is not.
 */

import {
  type Action,
  type AuthorizationDecision,
  type Classification,
  type Principal,
  type Resource,
  classificationRank,
} from './domain.ts';
import type { Capability } from './capability.ts';

export interface InvariantState {
  /** Human-readable coordinates, used only in failure messages. */
  readonly label: string;
  readonly principal: Principal;
  readonly resource: Resource;
  readonly action: Action;
  /** Capabilities the *subject* held when the decision was made. */
  readonly held: readonly Capability[];
  readonly now: number;
  readonly decision: AuthorizationDecision;
}

export interface Invariant {
  readonly id: string;
  readonly description: string;
  /** Returns a human-readable violation, or null when the property holds. */
  readonly violation: (state: InvariantState) => string | null;
}

/** A capability that could authorize this exact request, ignoring the policy. */
function covers(cap: Capability, state: InvariantState): boolean {
  const { principal, resource, action, now } = state;
  return (
    cap.subject === principal.id &&
    cap.tenantId === principal.tenantId &&
    cap.resourceIds.includes(resource.id) &&
    cap.actions.includes(action) &&
    cap.expiresAt > now &&
    cap.usedAt === undefined &&
    classificationRank(cap.maxClassification) >= classificationRank(resource.classification)
  );
}

const allowed = (s: InvariantState): boolean => s.decision.decision === 'allow';

export const INVARIANTS: readonly Invariant[] = [
  {
    id: 'no-authority-without-capability',
    description: 'An allow carries a capability that covers this subject, resource, action, time and classification.',
    violation: (s) =>
      allowed(s) && !s.held.some((c) => covers(c, s))
        ? `allowed ${s.action} on ${s.resource.id} with no covering capability`
        : null,
  },
  {
    id: 'cross-tenant-never-allowed',
    description: 'A principal and a resource in different tenants can never produce an allow.',
    violation: (s) =>
      allowed(s) && s.principal.tenantId !== s.resource.tenantId
        ? `allowed cross-tenant ${s.principal.tenantId} -> ${s.resource.tenantId}`
        : null,
  },
  {
    id: 'expired-capability-never-authorizes',
    description: 'When every covering capability has expired, the answer is deny.',
    violation: (s) => {
      const covering = s.held.filter(
        (c) => c.subject === s.principal.id && c.resourceIds.includes(s.resource.id) && c.actions.includes(s.action),
      );
      const allExpired = covering.length > 0 && covering.every((c) => c.expiresAt <= s.now);
      return allowed(s) && allExpired ? `allowed with only expired capabilities (${covering.length})` : null;
    },
  },
  {
    id: 'classification-ceiling-respected',
    description: 'An allow never exceeds the ceiling of a capability that covers the request.',
    violation: (s) =>
      allowed(s) &&
      !s.held.some(
        (c) =>
          c.subject === s.principal.id &&
          c.resourceIds.includes(s.resource.id) &&
          c.actions.includes(s.action) &&
          classificationRank(c.maxClassification) >= classificationRank(s.resource.classification),
      )
        ? `allowed ${s.resource.classification} above every granted ceiling`
        : null,
  },
  {
    id: 'foreign-capability-never-authorizes',
    description: "Another subject's capability cannot be the authority for this decision.",
    violation: (s) => {
      const foreignOnly =
        s.held.length > 0 &&
        s.held.filter((c) => c.subject !== s.principal.id).length === s.held.length;
      return allowed(s) && foreignOnly ? 'allowed on the strength of another subject\'s capability' : null;
    },
  },
  {
    id: 'empty-capability-set-denies',
    description: 'With no capabilities held, every request is denied.',
    violation: (s) => (allowed(s) && s.held.length === 0 ? 'allowed with no capabilities held' : null),
  },
  {
    id: 'deny-carries-no-authority',
    description: 'A denial never returns a capability id — no authority is handed out with a no.',
    violation: (s) =>
      !allowed(s) && s.decision.capabilityId !== undefined
        ? `deny carried capabilityId ${s.decision.capabilityId}`
        : null,
  },
];

export interface Violation {
  readonly label: string;
  readonly invariant: string;
  readonly message: string;
}

/** Every property that fails for one state. */
export function checkState(state: InvariantState): readonly Violation[] {
  const out: Violation[] = [];
  for (const invariant of INVARIANTS) {
    const message = invariant.violation(state);
    if (message !== null) out.push({ label: state.label, invariant: invariant.id, message });
  }
  return out;
}

/** Run the whole space. A single violation fails the model. */
export function checkAll(states: readonly InvariantState[]): readonly Violation[] {
  return states.flatMap(checkState);
}

/** Classification helper re-exported for callers building states. */
export type { Classification };
