/**
 * Policy testing primitives.
 *
 * Primitives only:
 *   - `simulate(engine, scenarios)`  - run scenarios through an engine.
 *   - `diffDecisions(before, after, scenarios)` - what changed between two engines.
 *   - `loadFixtures(dir)` - load JSON fixtures into a typed shape, with validation.
 *   - `loadGolden(file)` / `verifyGolden(g)` - the versioned decision oracle (H3).
 *
 * The harness is the test-time artifact M7 ships. The runtime path is unchanged.
 */

import { readdirSync, readFileSync } from 'node:fs';
import { join } from 'node:path';
import { createHash } from 'node:crypto';
import {
  canonicalJson,
  type Action,
  type AuthContext,
  type Classification,
  type Principal,
  type PrincipalKind,
  type Resource,
  type ResourceType,
} from './domain.ts';
import { createPolicyEngine, type Approval, type EvaluationContext, type PolicyEngine, type PolicyResult, type PolicyRule } from './policy.ts';

export interface Scenario {
  readonly principal: Principal;
  readonly resource: Resource;
  readonly action: Action;
  readonly params?: Readonly<Record<string, unknown>>;
  readonly approvals?: readonly Approval[];
  readonly now?: number;
  readonly networkHost?: string;
}

export type Decision = PolicyResult;

export interface DecisionDiff {
  readonly index: number;
  readonly scenario: Scenario;
  readonly before: PolicyResult;
  readonly after: PolicyResult;
}

export interface Expected {
  readonly effect: 'allow' | 'deny';
  readonly ruleId?: string;
  readonly reason?: string;
}

export interface Fixture {
  readonly id: string;
  readonly name: string;
  readonly rules: readonly PolicyRule[];
  readonly scenarios: readonly Scenario[];
  readonly expected: readonly Expected[];
}

const PRINCIPAL_KINDS: ReadonlySet<PrincipalKind> = new Set<PrincipalKind>([
  'user',
  'service',
  'authorization',
  'agent',
  'model',
  'tool',
]);

const RESOURCE_TYPES: ReadonlySet<ResourceType> = new Set<ResourceType>([
  'repository',
  'file',
  'document',
  'database',
  'api',
  'secret',
  'network-destination',
  'system',
  'audit-log',
]);

const KNOWN_CLASSIFICATIONS: ReadonlySet<string> = new Set<string>([
  'public',
  'internal',
  'confidential',
  'restricted',
  'pii',
  'phi',
  'privileged-legal',
  'financial',
  'trade-secret',
]);

// ponytail: actions allow strings outside the vocabulary via `string & {}`, so the
// loader rejects only names that fail the basic shape (non-empty, slash-free,
// not just whitespace). Anything else passes through. Same for classifications.
function isActionShapeOk(s: unknown): s is string {
  return typeof s === 'string' && s.length > 0 && !/\s/.test(s);
}

function isResourceTypeOk(t: unknown): t is ResourceType {
  return typeof t === 'string' && (RESOURCE_TYPES.has(t as ResourceType) || /^[a-z][a-z0-9-.]*$/.test(t));
}

function isPrincipalKindOk(k: unknown): k is PrincipalKind {
  return typeof k === 'string' && (PRINCIPAL_KINDS.has(k as PrincipalKind) || /^[a-z][a-z0-9-]*$/.test(k));
}

function isClassificationOk(c: unknown): c is Classification {
  return typeof c === 'string' && c.length > 0 && (KNOWN_CLASSIFICATIONS.has(c) || /^x-[a-z0-9-]+$/.test(c) || /^[a-z][a-z0-9-]*$/.test(c));
}

export function simulate(engine: PolicyEngine, scenarios: readonly Scenario[]): Decision[] {
  const out: Decision[] = [];
  for (const s of scenarios) {
    const ctx: EvaluationContext = {
      principal: s.principal,
      resource: s.resource,
      action: s.action,
      now: s.now ?? 0,
      ...(s.params !== undefined ? { params: s.params } : {}),
      ...(s.approvals !== undefined ? { approvals: s.approvals } : {}),
      ...(s.networkHost !== undefined ? { networkHost: s.networkHost } : {}),
    };
    out.push(engine.evaluate(ctx));
  }
  return out;
}

function decisionsEqual(a: PolicyResult, b: PolicyResult): boolean {
  return a.effect === b.effect && a.ruleId === b.ruleId && a.reason === b.reason;
}

export function diffDecisions(
  before: PolicyEngine,
  after: PolicyEngine,
  scenarios: readonly Scenario[],
): DecisionDiff[] {
  const bef = simulate(before, scenarios);
  const aft = simulate(after, scenarios);
  const out: DecisionDiff[] = [];
  for (let i = 0; i < scenarios.length; i++) {
    const b = bef[i]!;
    const a = aft[i]!;
    if (!decisionsEqual(a, b)) {
      out.push({ index: i, scenario: scenarios[i]!, before: b, after: a });
    }
  }
  return out;
}

interface RawScenario {
  readonly principal?: unknown;
  readonly resource?: unknown;
  readonly action?: unknown;
  readonly params?: unknown;
  readonly approvals?: unknown;
  readonly now?: unknown;
  readonly networkHost?: unknown;
}

interface RawFixture {
  readonly id?: unknown;
  readonly name?: unknown;
  readonly rules?: unknown;
  readonly scenarios?: unknown;
  readonly expected?: unknown;
}

function asNonEmptyString(value: unknown, file: string, field: string): string {
  if (typeof value !== 'string' || value.length === 0) {
    throw new Error(`${file}: field "${field}" must be a non-empty string`);
  }
  return value;
}

function asStringArray(value: unknown, file: string, field: string): readonly string[] {
  if (!Array.isArray(value) || !value.every((x) => typeof x === 'string')) {
    throw new Error(`${file}: field "${field}" must be an array of strings`);
  }
  return value as readonly string[];
}

function asAction(value: unknown, file: string, field: string): Action {
  if (!isActionShapeOk(value)) {
    throw new Error(`${file}: field "${field}" must be a non-empty action string`);
  }
  return value;
}

function validatePrincipal(value: unknown, file: string, index: number): Principal {
  if (typeof value !== 'object' || value === null) {
    throw new Error(`${file}: scenario[${index}].principal must be an object`);
  }
  const p = value as Record<string, unknown>;
  const id = asNonEmptyString(p.id, file, `scenarios[${index}].principal.id`);
  const kind = p.kind;
  if (!isPrincipalKindOk(kind)) {
    throw new Error(`${file}: scenario[${index}].principal.kind "${String(kind)}" outside domain.ts vocabulary`);
  }
  const tenantId = asNonEmptyString(p.tenantId, file, `scenarios[${index}].principal.tenantId`);
  const roles = Array.isArray(p.roles) && p.roles.every((r) => typeof r === 'string') ? (p.roles as readonly string[]) : [];
  const attributes: Record<string, string | number | boolean> =
    typeof p.attributes === 'object' && p.attributes !== null && !Array.isArray(p.attributes)
      ? (p.attributes as Record<string, string | number | boolean>)
      : {};
  return {
    id,
    kind,
    tenantId,
    roles,
    attributes,
    ...(p.auth !== undefined ? { auth: p.auth as AuthContext } : {}),
  };
}

function validateResource(value: unknown, file: string, index: number): Resource {
  if (typeof value !== 'object' || value === null) {
    throw new Error(`${file}: scenario[${index}].resource must be an object`);
  }
  const r = value as Record<string, unknown>;
  const id = asNonEmptyString(r.id, file, `scenarios[${index}].resource.id`);
  const type = r.type;
  if (!isResourceTypeOk(type)) {
    throw new Error(`${file}: scenario[${index}].resource.type "${String(type)}" outside domain.ts vocabulary`);
  }
  const tenantId = asNonEmptyString(r.tenantId, file, `scenarios[${index}].resource.tenantId`);
  const classification = r.classification;
  if (!isClassificationOk(classification)) {
    throw new Error(`${file}: scenario[${index}].resource.classification "${String(classification)}" outside domain.ts vocabulary`);
  }
  const attributes: Record<string, string | number | boolean> =
    typeof r.attributes === 'object' && r.attributes !== null && !Array.isArray(r.attributes)
      ? (r.attributes as Record<string, string | number | boolean>)
      : {};
  return { id, type, tenantId, classification, attributes };
}

function validateScenario(value: unknown, file: string, index: number): Scenario {
  if (typeof value !== 'object' || value === null) {
    throw new Error(`${file}: scenario[${index}] must be an object`);
  }
  const raw = value as RawScenario;
  const p = validatePrincipal(raw.principal, file, index);
  const r = validateResource(raw.resource, file, index);
  if (p.tenantId !== r.tenantId) {
    throw new Error(`${file}: scenario[${index}] is cross-tenant (principal=${p.tenantId}, resource=${r.tenantId})`);
  }
  return {
    principal: p,
    resource: r,
    action: asAction(raw.action, file, `scenarios[${index}].action`),
    ...(raw.params !== undefined && typeof raw.params === 'object' && raw.params !== null
      ? { params: raw.params as Readonly<Record<string, unknown>> }
      : {}),
    ...(Array.isArray(raw.approvals) ? { approvals: raw.approvals as readonly Approval[] } : {}),
    ...(typeof raw.now === 'number' ? { now: raw.now } : {}),
    ...(typeof raw.networkHost === 'string' ? { networkHost: raw.networkHost } : {}),
  };
}

function validateExpected(value: unknown, file: string, index: number): Expected {
  if (typeof value !== 'object' || value === null) {
    throw new Error(`${file}: expected[${index}] must be an object`);
  }
  const e = value as Record<string, unknown>;
  if (e.effect !== 'allow' && e.effect !== 'deny') {
    throw new Error(`${file}: expected[${index}].effect must be "allow" or "deny"`);
  }
  return {
    effect: e.effect,
    ...(typeof e.ruleId === 'string' ? { ruleId: e.ruleId } : {}),
    ...(typeof e.reason === 'string' ? { reason: e.reason } : {}),
  };
}

function validateRule(value: unknown, file: string, index: number): PolicyRule {
  if (typeof value !== 'object' || value === null) {
    throw new Error(`${file}: rules[${index}] must be an object`);
  }
  const r = value as Record<string, unknown>;
  const id = asNonEmptyString(r.id, file, `rules[${index}].id`);
  if (r.effect !== 'allow' && r.effect !== 'deny') {
    throw new Error(`${file}: rules[${index}].effect must be "allow" or "deny"`);
  }
  const principals = (r.principals !== undefined ? r.principals : {}) as PolicyRule['principals'];
  const actions = Array.isArray(r.actions) ? asStringArray(r.actions, file, `rules[${index}].actions`) : [];
  const resources = (r.resources !== undefined ? r.resources : {}) as PolicyRule['resources'];
  const conditions: PolicyRule['conditions'] | undefined = Array.isArray(r.conditions)
    ? (r.conditions as PolicyRule['conditions'])
    : undefined;
  return {
    id,
    effect: r.effect,
    principals,
    actions,
    resources,
    ...(typeof r.description === 'string' ? { description: r.description } : {}),
    ...(conditions !== undefined ? { conditions } : {}),
    ...(typeof r.maxClassification === 'string' ? { maxClassification: r.maxClassification as Classification } : {}),
    ...(r.requiresApproval === true ? { requiresApproval: true } : {}),
  };
}

export function loadFixtures(dir: string): Fixture[] {
  let entries: readonly string[];
  try {
    entries = readdirSync(dir);
  } catch {
    return [];
  }
  const out: Fixture[] = [];
  for (const name of entries) {
    if (!name.endsWith('.json')) continue;
    out.push(loadFixtureFile(join(dir, name)));
  }
  return out;
}

/**
 * One fixture file, validated. Shared by `loadFixtures` and `loadGolden`.
 * `allowLengthMismatch` exists for goldens being re-blessed: adding a scenario
 * before recomputing the expectations is a legitimate intermediate state, and
 * the mismatch is reported by `verifyGolden` rather than hidden.
 */
export function loadFixtureFile(file: string, allowLengthMismatch = false): Fixture {
  {
    let raw: unknown;
    // indentation kept from the loop this was extracted out of

    try {
      raw = JSON.parse(readFileSync(file, 'utf8'));
    } catch (e) {
      throw new Error(`${file}: malformed JSON (${(e as Error).message})`);
    }
    if (typeof raw !== 'object' || raw === null) {
      throw new Error(`${file}: fixture must be an object`);
    }
    const f = raw as RawFixture;
    const id = asNonEmptyString(f.id, file, 'id');
    const nameF = asNonEmptyString(f.name, file, 'name');
    if (!Array.isArray(f.rules)) {
      throw new Error(`${file}: "rules" must be an array`);
    }
    if (!Array.isArray(f.scenarios)) {
      throw new Error(`${file}: "scenarios" must be an array`);
    }
    if (!Array.isArray(f.expected)) {
      throw new Error(`${file}: "expected" must be an array`);
    }
    if (!allowLengthMismatch && f.scenarios.length !== f.expected.length) {
      throw new Error(`${file}: scenarios.length (${f.scenarios.length}) != expected.length (${f.expected.length})`);
    }
    const rules = (f.rules as readonly unknown[]).map((r, i) => validateRule(r, file, i));
    const scenarios = (f.scenarios as readonly unknown[]).map((s, i) => validateScenario(s, file, i));
    const expected = (f.expected as readonly unknown[]).map((e, i) => validateExpected(e, file, i));
    return { id, name: nameF, rules, scenarios, expected };
  }
}

/**
 * A versioned golden decision set (H3, ADR-034).
 *
 * A golden is a fixture whose `rules` are the policy under test and whose
 * `expected` is the full result — effect, ruleId, and reason. `policyHash`
 * binds it to that exact rule set, so a golden can never silently describe a
 * different policy than the one being evaluated.
 *
 * This is the oracle H14's mutation lane consumes: a mutated rule set must make
 * at least one entry here disagree, or the golden set is too weak to mean
 * anything.
 */
/**
 * A mutant the golden set provably cannot kill, with the reason. The escape
 * hatch exists so a future equivalent mutant cannot turn the lane into a gate
 * somebody deletes: adding an entry is a reviewable diff that names its
 * justification, and the default remains "strengthen the golden set".
 */
export interface MutationAllowance {
  readonly id: string;
  readonly reason: string;
}

export interface Golden extends Fixture {
  readonly version: number;
  readonly policyId: string;
  readonly policyHash: string;
  readonly mutationAllowlist?: readonly MutationAllowance[];
}

export interface GoldenMismatch {
  readonly index: number;
  readonly expected: Expected;
  readonly actual: Decision;
}

export interface GoldenVerification {
  readonly hashMatches: boolean;
  /** Scenario and expectation counts agree — a golden mid-edit does not. */
  readonly lengthMatches: boolean;
  readonly mismatches: readonly GoldenMismatch[];
}

export function goldenHash(rules: readonly PolicyRule[]): string {
  return createHash('sha256').update(canonicalJson(rules)).digest('hex');
}

export function loadGolden(file: string): Golden {
  const fixture = loadFixtureFile(file, true);
  let raw: unknown;
  try {
    raw = JSON.parse(readFileSync(file, 'utf8'));
  } catch (e) {
    throw new Error(`${file}: malformed JSON (${(e as Error).message})`);
  }
  const g = raw as Partial<Golden>;
  if (typeof g.version !== 'number' || !Number.isInteger(g.version)) {
    throw new Error(`${file}: golden "version" must be an integer`);
  }
  if (typeof g.policyId !== 'string' || g.policyId === '') {
    throw new Error(`${file}: golden "policyId" must be a non-empty string`);
  }
  if (typeof g.policyHash !== 'string' || g.policyHash === '') {
    throw new Error(`${file}: golden "policyHash" must be a non-empty string`);
  }
  if (g.mutationAllowlist !== undefined) {
    if (!Array.isArray(g.mutationAllowlist)) {
      throw new Error(`${file}: golden "mutationAllowlist" must be an array`);
    }
    for (const [i, entry] of g.mutationAllowlist.entries()) {
      if (typeof entry?.id !== 'string' || entry.id === '' || typeof entry.reason !== 'string' || entry.reason === '') {
        throw new Error(`${file}: mutationAllowlist[${i}] needs a non-empty "id" and "reason"`);
      }
    }
  }
  return {
    ...fixture,
    version: g.version,
    policyId: g.policyId,
    policyHash: g.policyHash,
    ...(g.mutationAllowlist !== undefined ? { mutationAllowlist: g.mutationAllowlist } : {}),
  };
}

/** Compare the committed expectations against what the engine actually decides. */
export function verifyGolden(g: Golden, engine?: PolicyEngine): GoldenVerification {
  const actual = simulate(engine ?? createPolicyEngine(g.rules, g.policyId), g.scenarios);
  const mismatches: GoldenMismatch[] = [];
  for (let i = 0; i < g.expected.length; i++) {
    const exp = g.expected[i]!;
    const got = actual[i];
    if (!got) continue;
    const bad =
      got.effect !== exp.effect ||
      (exp.ruleId !== undefined && got.ruleId !== exp.ruleId) ||
      (exp.reason !== undefined && got.reason !== exp.reason);
    if (bad) mismatches.push({ index: i, expected: exp, actual: got });
  }
  return {
    hashMatches: goldenHash(g.rules) === g.policyHash,
    lengthMatches: g.scenarios.length === g.expected.length,
    mismatches,
  };
}
