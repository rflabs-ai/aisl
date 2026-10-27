/**
 * H14 — adversarial evaluation harness (ADR-033).
 *
 * The harness composes the pieces that already exist (the attack corpus, the
 * legitimate fixtures, the policy engine) into one run and pins their inputs
 * with digests, so drift in the corpus or in the decision semantics is a loud
 * failure instead of a silent edit.
 *
 * This module is pure: it reads directories to digest them and otherwise
 * computes. The CLI owns the world, the corpus execution, and the file writes.
 * No runtime path imports this file.
 *
 * What this is NOT: evidence of safety. The corpus is implementer-authored,
 * so a green run means the enumerated attacks still behave as specified —
 * nothing more. Unknown-unknown attacks remain the residual (ADR-033).
 */

import { createHash } from 'node:crypto';
import { readdirSync, readFileSync } from 'node:fs';
import { join } from 'node:path';
import type { PolicyResult } from './policy.ts';

export const ADVERSARIAL_REPORT_VERSION = 'ASL-ADVERSARIAL v1';

export interface Digests {
  readonly corpus: string;
  readonly fixtures: string;
  readonly decisions: string;
}

export interface Baseline {
  readonly version: string;
  readonly blessedAt: string;
  readonly digests: Digests;
}

export type LaneName = 'corpus' | 'drift' | 'differential' | 'mutation';

export interface Lane {
  readonly lane: LaneName;
  readonly passed: boolean;
  readonly detail: string;
}

export interface AdversarialReport {
  readonly version: string;
  readonly generatedAt: string;
  readonly gitHead: string | null;
  readonly digests: Digests;
  readonly lanes: readonly Lane[];
  readonly passed: boolean;
}

const sha256 = (input: string | Uint8Array): string => createHash('sha256').update(input).digest('hex');

/**
 * Digest a corpus directory. Sorted names plus a NUL separator, so a rename is
 * a change (names are part of the corpus contract) and two files cannot be
 * concatenated into the same byte stream as one differently-named file.
 */
export function digestDirectory(dir: string): string {
  const names = readdirSync(dir, { withFileTypes: true })
    .filter((e) => e.isFile())
    .map((e) => e.name)
    .sort();
  const h = createHash('sha256');
  for (const name of names) {
    h.update(`${name}\0`);
    h.update(readFileSync(join(dir, name)));
    h.update('\0');
  }
  return h.digest('hex');
}

/** One stable line per decision: effect, the rule that decided it, and why. */
export function decidedVector(decisions: readonly PolicyResult[]): readonly string[] {
  return decisions.map((d) => `${d.effect}|${d.ruleId ?? ''}|${d.reason}`);
}

export function digestDecisionVector(vector: readonly string[]): string {
  return sha256(vector.join('\n'));
}

export function buildBaseline(digests: Digests, blessedAt: string): Baseline {
  return { version: ADVERSARIAL_REPORT_VERSION, blessedAt, digests };
}

const mismatched = (current: Digests, baseline: Baseline, keys: readonly (keyof Digests)[]): string[] =>
  keys.filter((k) => current[k] !== baseline.digests[k]).map((k) => `${k} digest changed`);

export function driftLane(current: Digests, baseline: Baseline | null): Lane {
  if (baseline === null) {
    return { lane: 'drift', passed: false, detail: 'no baseline: run `npm run adversarial -- --bless` and review the diff' };
  }
  const changed = mismatched(current, baseline, ['corpus', 'fixtures']);
  return {
    lane: 'drift',
    passed: changed.length === 0,
    detail: changed.length === 0 ? `corpus + fixtures unchanged since ${baseline.blessedAt}` : changed.join(', '),
  };
}

export function differentialLane(current: Digests, baseline: Baseline | null): Lane {
  if (baseline === null) {
    return { lane: 'differential', passed: false, detail: 'no baseline: run `npm run adversarial -- --bless` and review the diff' };
  }
  const changed = mismatched(current, baseline, ['decisions']);
  return {
    lane: 'differential',
    passed: changed.length === 0,
    detail:
      changed.length === 0
        ? `decision vector unchanged since ${baseline.blessedAt}`
        : `${changed.join(', ')} — a policy change altered decisions; H3 owns whether that is correct`,
  };
}

/**
 * ADR-035: a surviving mutant means the golden set cannot tell a mutated policy
 * from the real one. Passing requires *all* mutants killed, and requires at
 * least one mutant to have been generated — a lane that runs nothing is not a
 * pass, it is a silent no-op.
 */
export function mutationLane(
  total: number,
  killed: number,
  unexpected: readonly string[],
  allowlisted = 0,
): Lane {
  if (total === 0) {
    return { lane: 'mutation', passed: false, detail: 'no mutants were generated — the policy has no rules to mutate' };
  }
  const ok = unexpected.length === 0;
  const suffix = allowlisted > 0 ? `, ${allowlisted} allowlisted equivalent(s)` : '';
  return {
    lane: 'mutation',
    passed: ok,
    detail: ok
      ? `${killed}/${total} mutants killed${suffix}`
      : `${killed}/${total} killed; survivors: ${unexpected.join(', ')}${suffix}`,
  };
}

export function corpusLane(passed: number, total: number, failed: readonly string[] = []): Lane {
  const ok = total > 0 && passed === total;
  return {
    lane: 'corpus',
    passed: ok,
    detail: ok ? `${passed}/${total} cases behaved as required` : `${passed}/${total} passed; failed: ${failed.join(', ')}`,
  };
}

export function buildReport(input: {
  readonly generatedAt: string;
  readonly gitHead: string | null;
  readonly digests: Digests;
  readonly lanes: readonly Lane[];
}): AdversarialReport {
  return {
    version: ADVERSARIAL_REPORT_VERSION,
    generatedAt: input.generatedAt,
    gitHead: input.gitHead,
    digests: input.digests,
    lanes: input.lanes,
    passed: input.lanes.length > 0 && input.lanes.every((l) => l.passed),
  };
}

