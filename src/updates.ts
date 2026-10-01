/**
 * H12 — Secure updates (ADR-025).
 *
 * The update channel, in one chain: signed update descriptor -> embedded H10
 * build manifest (live tree/SBOM digests recomputed, never trusted) ->
 * persisted high-water mark -> canary rollout state. Each link refuses with a
 * distinct reason and no link can be skipped:
 *
 *   1. Signature proves origin. It does NOT prove freshness — that is the
 *      high-water mark's job. A perfectly signed, perfectly stale descriptor
 *      is refused (`rollback-blocked`).
 *   2. The high-water mark never lowers, including under emergency rollback:
 *      the version you rolled back FROM stays burned, so the emergency path
 *      cannot become the replay path.
 *   3. Emergency rollback is a signed, single-use grant naming the exact
 *      from-version; replay fails `grant-mismatch`. Single-use is enforced by
 *      a monotonic rollback generation carried in the grant and the state —
 *      a used grant stays used even if its from-version becomes current
 *      again.
 *   4. Promotion needs an explicit passing health signal; a failing signal
 *      halts the rollout and the halt is sticky (only a new descriptor or a
 *      rollback grant resolves it).
 *
 * State is code-written only, atomic (temp + rename), and carries no key
 * material — the invariant test enforces that boundary.
 *
 * ponytail: the health signal is a caller-supplied boolean and canary cohort
 * selection is the deployer's — wire per-instance attested health and a
 * descriptor transparency log when a second instance or a release endpoint
 * exists (H11/Stage-3).
 */

import { sign as cryptoSign, verify as cryptoVerify } from 'node:crypto';
import { existsSync, mkdirSync, readFileSync, renameSync, writeFileSync } from 'node:fs';
import { dirname } from 'node:path';
import { canonicalJson } from './domain.ts';
import { verifyManifest, type BuildManifest } from './supply-chain.ts';

export type UpdateRefusal =
  | 'not-an-update'
  | 'bad-stages'
  | 'bad-version'
  | 'bad-signature'
  | 'no-verification-key'
  | 'manifest-rejected'
  | 'rollback-blocked'
  | 'state-malformed'
  | 'no-pending-rollout'
  | 'halted'
  | 'not-a-rollback-grant'
  | 'bad-grant-signature'
  | 'grant-mismatch';

export interface UpdateDescriptor {
  readonly type: 'asl-update';
  readonly version: 1;
  /** Monotonic release number (the M11 bundle pattern): ordering decides offline. */
  readonly releaseVersion: number;
  readonly channel: string;
  /** Ascending rollout percentages; the first entry is the canary. */
  readonly stages: readonly number[];
  /** The H10 build manifest of the release this descriptor carries. */
  readonly manifest: BuildManifest;
  /** H10 Ed25519 signature over `manifest` — verified against the live tree. */
  readonly manifestSignature: string;
  readonly issuedAt: string;
  readonly issuedBy: string;
}

export interface RollbackGrant {
  readonly type: 'asl-rollback-grant';
  readonly version: 1;
  readonly targetVersion: number;
  readonly fromVersion: number;
  /** The `rollbackGeneration` current when the grant was issued — one use per generation. */
  readonly generation: number;
  readonly reason: string;
  readonly issuedAt: string;
  readonly issuedBy: string;
}

export interface UpdateState {
  readonly type: 'asl-update-state';
  readonly version: 1;
  /** The mark that never lowers. Any descriptor at or below it is a replay. */
  readonly highWaterMark: number;
  /** Monotonic count of applied rollbacks — a grant works at most once per generation. */
  readonly rollbackGeneration: number;
  readonly current: {
    readonly releaseVersion: number;
    /** Channel of the applied release; `null` after a rollback (unknown, recorded honestly). */
    readonly channel: string | null;
    readonly appliedAt: string;
  } | null;
  readonly rollout: {
    readonly status: 'none' | 'canary' | 'promoted' | 'halted';
    readonly stageIndex: number;
    readonly stages: readonly number[];
    readonly pendingVersion: number | null;
    readonly haltReason: string | null;
  };
}

export interface UpdateVerifyResult {
  readonly valid: boolean;
  readonly reason?: UpdateRefusal;
  readonly detail?: string;
}

export interface UpdateResult {
  readonly ok: boolean;
  readonly reason?: UpdateRefusal;
  readonly detail?: string;
  readonly state?: UpdateState;
}

/** Thrown only by `loadState` on a corrupt file — callers surface it as `state-malformed`. */
class UpdateStateError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'UpdateStateError';
  }
}

function initialState(): UpdateState {
  return {
    type: 'asl-update-state',
    version: 1,
    highWaterMark: 0,
    rollbackGeneration: 0,
    current: null,
    rollout: { status: 'none', stageIndex: 0, stages: [], pendingVersion: null, haltReason: null },
  };
}

function isInteger(value: unknown): value is number {
  return typeof value === 'number' && Number.isInteger(value);
}

/** Structural gate for a descriptor — malformed input is a refusal, never a cast. */
function descriptorStructure(raw: unknown): { descriptor?: UpdateDescriptor; reason?: UpdateRefusal } {
  if (typeof raw !== 'object' || raw === null) return { reason: 'not-an-update' };
  const d = raw as Record<string, unknown>;
  if (d.type !== 'asl-update' || d.version !== 1) return { reason: 'not-an-update' };
  if (!isInteger(d.releaseVersion) || d.releaseVersion < 1) return { reason: 'bad-version' };
  const stages = d.stages;
  if (!Array.isArray(stages) || stages.length === 0) return { reason: 'bad-stages' };
  for (let i = 0; i < stages.length; i++) {
    const s = stages[i];
    if (!isInteger(s) || s < 1 || s > 100) return { reason: 'bad-stages' };
    if (i > 0 && s <= (stages[i - 1] as number)) return { reason: 'bad-stages' };
  }
  // A rollout that ends short of full coverage is not a promotion.
  if (stages[stages.length - 1] !== 100) return { reason: 'bad-stages' };
  if (typeof d.manifest !== 'object' || d.manifest === null) return { reason: 'not-an-update' };
  if (typeof d.manifestSignature !== 'string' || d.manifestSignature === '') return { reason: 'not-an-update' };
  if (typeof d.channel !== 'string' || d.channel === '') return { reason: 'not-an-update' };
  if (typeof d.issuedAt !== 'string' || typeof d.issuedBy !== 'string') return { reason: 'not-an-update' };
  return { descriptor: raw as UpdateDescriptor };
}

/** Ed25519 over the canonical descriptor. A bad key throws — fail closed. */
export function signUpdate(descriptor: UpdateDescriptor, privateKeyPem: string): string {
  const data = Buffer.from(canonicalJson(descriptor), 'utf8');
  return cryptoSign(null, data, privateKeyPem).toString('base64');
}

export function verifyDescriptor(raw: unknown, signature: string, publicKeyPem: string): UpdateVerifyResult {
  const structure = descriptorStructure(raw);
  if (structure.reason !== undefined) return { valid: false, reason: structure.reason };
  if (typeof publicKeyPem !== 'string' || publicKeyPem === '') {
    return { valid: false, reason: 'no-verification-key' };
  }
  const data = Buffer.from(canonicalJson(raw), 'utf8');
  const sig = Buffer.from(signature, 'base64');
  let signatureValid: boolean;
  try {
    signatureValid = cryptoVerify(null, data, publicKeyPem, sig);
  } catch {
    return { valid: false, reason: 'bad-signature' };
  }
  if (!signatureValid) return { valid: false, reason: 'bad-signature' };
  return { valid: true };
}

/**
 * The full chain: descriptor structure + signature, then the embedded H10
 * manifest verified against the LIVE repo (tree/SBOM digests recomputed).
 * An inner refusal surfaces as `manifest-rejected:<reason>`.
 */
export function verifyUpdate(
  raw: unknown,
  signature: string,
  opts: { publicKeyPem: string; repoRoot: string },
): UpdateVerifyResult {
  const descriptorCheck = verifyDescriptor(raw, signature, opts.publicKeyPem);
  if (!descriptorCheck.valid) return descriptorCheck;
  const structure = descriptorStructure(raw);
  if (structure.descriptor === undefined) return { valid: false, reason: structure.reason ?? 'not-an-update' };
  const descriptor = structure.descriptor;
  const manifestResult = verifyManifest(descriptor.manifest, descriptor.manifestSignature, opts.publicKeyPem, {
    repoRoot: opts.repoRoot,
  });
  if (!manifestResult.valid) {
    return { valid: false, reason: 'manifest-rejected', detail: manifestResult.reason };
  }
  return { valid: true };
}

function stateStructure(raw: unknown): UpdateState | null {
  if (typeof raw !== 'object' || raw === null) return null;
  const s = raw as Record<string, unknown>;
  if (s.type !== 'asl-update-state' || s.version !== 1) return null;
  if (!isInteger(s.highWaterMark) || s.highWaterMark < 0) return null;
  if (!isInteger(s.rollbackGeneration) || s.rollbackGeneration < 0) return null;
  const current = s.current;
  if (current !== null) {
    if (typeof current !== 'object') return null;
    const c = current as Record<string, unknown>;
    if (!isInteger(c.releaseVersion) || c.releaseVersion < 1) return null;
    if (!(typeof c.channel === 'string' || c.channel === null)) return null;
    if (typeof c.appliedAt !== 'string') return null;
  }
  const rollout = s.rollout;
  if (typeof rollout !== 'object' || rollout === null) return null;
  const r = rollout as Record<string, unknown>;
  if (!['none', 'canary', 'promoted', 'halted'].includes(String(r.status))) return null;
  if (!isInteger(r.stageIndex) || r.stageIndex < 0) return null;
  if (!Array.isArray(r.stages) || !r.stages.every((x) => isInteger(x))) return null;
  if (!(r.pendingVersion === null || isInteger(r.pendingVersion))) return null;
  if (!(r.haltReason === null || typeof r.haltReason === 'string')) return null;
  return raw as UpdateState;
}

/**
 * Load persisted update state. Missing file = initial state (first use);
 * a corrupt file throws `UpdateStateError` — a reset must never be a
 * side effect of a parse failure.
 */
export function loadState(path: string): UpdateState {
  if (!existsSync(path)) return initialState();
  let parsed: unknown;
  try {
    parsed = JSON.parse(readFileSync(path, 'utf8'));
  } catch {
    throw new UpdateStateError(`update state at ${path} is not valid JSON — refuse (fail closed)`);
  }
  const state = stateStructure(parsed);
  if (state === null) {
    throw new UpdateStateError(`update state at ${path} does not match the asl-update-state contract — refuse (fail closed)`);
  }
  return state;
}

/** Atomic write: temp file + rename, so a crash cannot truncate the high-water mark. */
function saveState(path: string, state: UpdateState): void {
  mkdirSync(dirname(path), { recursive: true });
  const tmp = `${path}.tmp`;
  writeFileSync(tmp, `${JSON.stringify(state, null, 2)}\n`);
  renameSync(tmp, path);
}

/**
 * Verify the whole chain, enforce the high-water mark, and land the rollout
 * at canary. Raises the mark on success; a replay is refused with
 * `rollback-blocked` regardless of how valid its signature is.
 */
export function applyUpdate(
  raw: unknown,
  signature: string,
  opts: { publicKeyPem: string; repoRoot: string; statePath: string },
): UpdateResult {
  const chain = verifyUpdate(raw, signature, { publicKeyPem: opts.publicKeyPem, repoRoot: opts.repoRoot });
  if (!chain.valid) return { ok: false, reason: chain.reason, detail: chain.detail };
  const structure = descriptorStructure(raw);
  if (structure.descriptor === undefined) {
    return { ok: false, reason: structure.reason ?? 'not-an-update' };
  }
  const descriptor = structure.descriptor;

  let state: UpdateState;
  try {
    state = loadState(opts.statePath);
  } catch (err) {
    return { ok: false, reason: 'state-malformed', detail: (err as Error).message };
  }

  if (descriptor.releaseVersion <= state.highWaterMark) {
    return { ok: false, reason: 'rollback-blocked', state };
  }

  const next: UpdateState = {
    ...state,
    highWaterMark: descriptor.releaseVersion,
    current: {
      releaseVersion: descriptor.releaseVersion,
      channel: descriptor.channel,
      appliedAt: new Date().toISOString(),
    },
    rollout: {
      status: 'canary',
      stageIndex: 0,
      stages: [...descriptor.stages],
      pendingVersion: descriptor.releaseVersion,
      haltReason: null,
    },
  };
  saveState(opts.statePath, next);
  return { ok: true, state: next };
}

/**
 * Advance the rollout exactly one stage per explicit passing health signal.
 * A failing signal halts and the halt is sticky: no pass clears it — only a
 * new descriptor (apply) or a rollback grant does.
 */
export function promoteUpdate(opts: { statePath: string; healthOk: boolean }): UpdateResult {
  let state: UpdateState;
  try {
    state = loadState(opts.statePath);
  } catch (err) {
    return { ok: false, reason: 'state-malformed', detail: (err as Error).message };
  }

  const rollout = state.rollout;
  if (rollout.status === 'halted') return { ok: false, reason: 'halted', state };
  if (rollout.status !== 'canary') return { ok: false, reason: 'no-pending-rollout', state };

  if (!opts.healthOk) {
    const halted: UpdateState = {
      ...state,
      rollout: { ...rollout, status: 'halted', haltReason: 'health-check-failed' },
    };
    saveState(opts.statePath, halted);
    return { ok: false, reason: 'halted', state: halted };
  }

  const last = rollout.stages.length - 1;
  const stageIndex = Math.min(rollout.stageIndex + 1, last);
  const promoted: UpdateState = {
    ...state,
    rollout: { ...rollout, stageIndex, status: stageIndex >= last ? 'promoted' : 'canary' },
  };
  saveState(opts.statePath, promoted);
  return { ok: true, state: promoted };
}

export function signRollbackGrant(grant: RollbackGrant, privateKeyPem: string): string {
  const data = Buffer.from(canonicalJson(grant), 'utf8');
  return cryptoSign(null, data, privateKeyPem).toString('base64');
}

function grantStructure(raw: unknown): { grant?: RollbackGrant; reason?: UpdateRefusal } {
  if (typeof raw !== 'object' || raw === null) return { reason: 'not-a-rollback-grant' };
  const g = raw as Record<string, unknown>;
  if (g.type !== 'asl-rollback-grant' || g.version !== 1) return { reason: 'not-a-rollback-grant' };
  if (!isInteger(g.targetVersion) || g.targetVersion < 1) return { reason: 'not-a-rollback-grant' };
  if (!isInteger(g.fromVersion) || g.fromVersion < 1) return { reason: 'not-a-rollback-grant' };
  if (!isInteger(g.generation) || g.generation < 0) return { reason: 'not-a-rollback-grant' };
  if (typeof g.reason !== 'string' || typeof g.issuedAt !== 'string' || typeof g.issuedBy !== 'string') {
    return { reason: 'not-a-rollback-grant' };
  }
  return { grant: raw as RollbackGrant };
}

/**
 * Emergency rollback: signed, single-use, backward-only, and it never lowers
 * the high-water mark. The grant must name the exact version currently
 * applied AND the current `rollbackGeneration`; success increments the
 * generation, so a used grant stays used even if its from-version becomes
 * current again through another rollback.
 */
export function rollbackUpdate(
  raw: unknown,
  signature: string,
  opts: { publicKeyPem: string; statePath: string },
): UpdateResult {
  const structure = grantStructure(raw);
  if (structure.reason !== undefined) return { ok: false, reason: structure.reason };
  if (typeof opts.publicKeyPem !== 'string' || opts.publicKeyPem === '') {
    return { ok: false, reason: 'no-verification-key' };
  }
  const data = Buffer.from(canonicalJson(raw), 'utf8');
  const sig = Buffer.from(signature, 'base64');
  let signatureValid: boolean;
  try {
    signatureValid = cryptoVerify(null, data, opts.publicKeyPem, sig);
  } catch {
    return { ok: false, reason: 'bad-grant-signature' };
  }
  if (!signatureValid) return { ok: false, reason: 'bad-grant-signature' };

  let state: UpdateState;
  try {
    state = loadState(opts.statePath);
  } catch (err) {
    return { ok: false, reason: 'state-malformed', detail: (err as Error).message };
  }
  const grant = structure.grant;
  if (grant === undefined) return { ok: false, reason: structure.reason ?? 'not-a-rollback-grant' };
  if (state.current === null) return { ok: false, reason: 'grant-mismatch', state };
  if (grant.fromVersion !== state.current.releaseVersion) return { ok: false, reason: 'grant-mismatch', state };
  if (grant.targetVersion >= grant.fromVersion) return { ok: false, reason: 'grant-mismatch', state };
  if (grant.generation !== state.rollbackGeneration) return { ok: false, reason: 'grant-mismatch', state };

  const next: UpdateState = {
    ...state,
    rollbackGeneration: state.rollbackGeneration + 1,
    current: {
      releaseVersion: grant.targetVersion,
      channel: null,
      appliedAt: new Date().toISOString(),
    },
    rollout: { status: 'none', stageIndex: 0, stages: [], pendingVersion: null, haltReason: null },
  };
  saveState(opts.statePath, next);
  return { ok: true, state: next };
}