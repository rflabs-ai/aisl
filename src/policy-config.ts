/**
 * M11: policy bundles — policy as a verified, attributable artifact.
 *
 * A bundle is `{ id, version, rules|roles, provenance, hash }` where
 * `hash = sha256(canonicalJson({ version, rules|roles }))`. Provenance and id
 * sit OUTSIDE the hash: they describe the artifact, they are not its content.
 *
 * The boundary enforced here is the verified artifact: anything loaded through
 * `loadPolicyBundle`/`loadRoleBundle` is content-checked before use, fail
 * closed on any mismatch. Authoring is still in-repo and the review gate is
 * git — this is NOT a policy service; it makes tampering detectable at load
 * time, nothing more.
 */

import { createHash } from 'node:crypto';
import { canonicalJson, type Role } from './domain.ts';
import {
  BASELINE_ROLES,
  createPolicyEngine,
  type PolicyEngine,
  type PolicyRule,
} from './policy.ts';
import type { EventStore } from './events.ts';

export interface BundleProvenance {
  /** Where the bundle came from (e.g. 'repo:src/policy/baseline.json'). */
  readonly source: string;
  /** Reviewer principal id. The review gate itself is git, not this field. */
  readonly reviewedBy?: string;
  /** ISO timestamp of the approval. */
  readonly approvedAt?: string;
}

export interface PolicyBundle {
  /** Becomes the engine id. */
  readonly id: string;
  readonly version: number;
  readonly rules: readonly PolicyRule[];
  readonly provenance: BundleProvenance;
  /** sha256(canonicalJson({ version, rules })) — provenance and id are OUTSIDE the hash. */
  readonly hash: string;
}

export interface RoleBundle {
  readonly id: string;
  readonly version: number;
  readonly roles: readonly Role[];
  readonly provenance: BundleProvenance;
  /** sha256(canonicalJson({ version, roles })) */
  readonly hash: string;
}

export class PolicyBundleError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'PolicyBundleError';
  }
}

function sha256Json(payload: unknown): string {
  return createHash('sha256').update(canonicalJson(payload)).digest('hex');
}

export function policyBundleHash(bundle: Omit<PolicyBundle, 'hash'>): string {
  return sha256Json({ version: bundle.version, rules: bundle.rules });
}

export function roleBundleHash(bundle: Omit<RoleBundle, 'hash'>): string {
  return sha256Json({ version: bundle.version, roles: bundle.roles });
}

/**
 * Structural gate, shared by both loaders. Hash mismatch is detected after
 * this; both failures are PolicyBundleError, fail closed.
 */
function assertBundleShape(bundle: unknown, kind: string): void {
  if (typeof bundle !== 'object' || bundle === null) {
    throw new PolicyBundleError(`${kind} bundle must be an object`);
  }
  const b = bundle as Record<string, unknown>;
  if (typeof b.id !== 'string' || b.id === '') {
    throw new PolicyBundleError(`${kind} bundle: "id" must be a non-empty string`);
  }
  if (typeof b.version !== 'number' || !Number.isInteger(b.version)) {
    throw new PolicyBundleError(`${kind} bundle '${b.id}': "version" must be an integer`);
  }
  const provenance = b.provenance as BundleProvenance | undefined;
  if (typeof provenance !== 'object' || provenance === null || typeof provenance.source !== 'string' || provenance.source === '') {
    throw new PolicyBundleError(`${kind} bundle '${b.id}': "provenance.source" must be a non-empty string`);
  }
  if (typeof b.hash !== 'string') {
    throw new PolicyBundleError(`${kind} bundle '${b.id}': "hash" must be a string`);
  }
}

export function loadPolicyBundle(bundle: PolicyBundle): PolicyBundle {
  assertBundleShape(bundle, 'policy');
  if (!Array.isArray(bundle.rules)) {
    throw new PolicyBundleError(`policy bundle '${bundle.id}': "rules" must be an array`);
  }
  const computed = policyBundleHash(bundle);
  if (computed !== bundle.hash) {
    throw new PolicyBundleError(
      `policy bundle '${bundle.id}': hash mismatch — recomputed ${computed}, bundle claims ${bundle.hash}`,
    );
  }
  return bundle;
}

export function loadRoleBundle(bundle: RoleBundle): RoleBundle {
  assertBundleShape(bundle, 'role');
  if (!Array.isArray(bundle.roles)) {
    throw new PolicyBundleError(`role bundle '${bundle.id}': "roles" must be an array`);
  }
  const computed = roleBundleHash(bundle);
  if (computed !== bundle.hash) {
    throw new PolicyBundleError(
      `role bundle '${bundle.id}': hash mismatch — recomputed ${computed}, bundle claims ${bundle.hash}`,
    );
  }
  return bundle;
}

/**
 * Build an engine from a verified bundle. The bundle is refused BEFORE anything
 * else happens, so a tampered bundle never reaches rule compilation and never
 * appends an event. The load event is opt-in via `opts.eventLog`: plain-rule
 * engines (createPolicyEngine directly) never append it — the seam stays
 * optional.
 */
export function createEngineFromBundle(
  bundle: PolicyBundle,
  opts: { roleBundle?: RoleBundle; eventLog?: EventStore; tenantId?: string; actor?: string } = {},
): PolicyEngine {
  const verified = loadPolicyBundle(bundle);
  const roles = opts.roleBundle ? loadRoleBundle(opts.roleBundle).roles : BASELINE_ROLES;
  const engine = createPolicyEngine(verified.rules, verified.id, roles);
  opts.eventLog?.append({
    tenantId: opts.tenantId ?? '',
    principal: opts.actor ?? 'system',
    actor: opts.actor ?? 'system',
    actorKind: 'authorization',
    action: 'policy.load',
    result: 'success',
    metadata: {
      phase: 'policy-load',
      version: verified.version,
      hash: verified.hash,
      ruleCount: verified.rules.length,
      provenance: verified.provenance,
      bundleId: verified.id,
    },
  });
  return engine;
}
