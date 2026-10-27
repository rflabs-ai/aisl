/**
 * Taint labels for the session data path (H4, ADR-036).
 *
 * A label answers three questions about a value: how sensitive is it, which
 * resources did it come from, and was any of it attacker-influenced. It is the
 * data half of the enforcement story — the PDP answers "may this principal do
 * this", a label answers "what has this session already seen, and is that still
 * true three steps later".
 *
 * The algebra is deliberately one-directional: `combine` takes the maximum
 * classification, the union of sources, and the OR of `untrusted`. There is no
 * operation that lowers a label, which is what makes it safe to fold into every
 * decision point without thinking about order.
 */

import { classificationRank, type Classification } from './domain.ts';

export interface TaintLabel {
  /** Resource ids (or tool-declared names) that influenced the value. */
  readonly sources: readonly string[];
  readonly classification: Classification;
  /** True when any contributor was attacker-influenceable (documents, tool output). */
  readonly untrusted: boolean;
}

/** Nothing seen yet: public, no sources, trusted. */
export const CLEAN_TAINT: TaintLabel = { sources: [], classification: 'public', untrusted: false };

/**
 * A value whose provenance cannot be established (an output from a resource the
 * runtime does not know). Ranked at the ceiling by `x-unknown-source`, matching
 * the existing fail-closed convention for unknown resources.
 */
export const UNKNOWN_TAINT: TaintLabel = {
  sources: [],
  classification: 'x-unknown-source',
  untrusted: true,
};

/** Cap on recorded sources: a label is evidence metadata, not a provenance database. */
const MAX_SOURCES = 16;

/**
 * Label for content that came from `resourceId`. Data is untrusted by default:
 * a document, a tool result, and a model turn are all attacker-influenceable.
 * Callers that know better (an operator-authored prompt) do not use this.
 */
export function taintFor(resourceId: string, classification: Classification, untrusted = true): TaintLabel {
  return { sources: [resourceId], classification, untrusted };
}

const sortSources = (sources: Iterable<string>): readonly string[] =>
  [...new Set(sources)].sort().slice(0, MAX_SOURCES);

/**
 * Fold labels together. Maximum classification, union of sources, OR of
 * `untrusted`. Undefined entries are ignored, so callers can pass optional
 * labels without branching.
 */
export function combine(...labels: readonly (TaintLabel | undefined)[]): TaintLabel {
  let classification: Classification = 'public';
  let untrusted = false;
  const sources: string[] = [];

  for (const label of labels) {
    if (label === undefined) continue;
    if (classificationRank(label.classification) > classificationRank(classification)) {
      classification = label.classification;
    }
    if (label.untrusted) untrusted = true;
    sources.push(...label.sources);
  }

  const merged = sortSources(sources);
  if (merged.length === 0 && classification === 'public' && !untrusted) return CLEAN_TAINT;
  return { sources: merged, classification, untrusted };
}

/** Evidence-safe projection: ids and labels only, never content. */
export function taintMetadata(label: TaintLabel): { sources: readonly string[]; classification: Classification; untrusted: boolean } {
  return { sources: label.sources, classification: label.classification, untrusted: label.untrusted };
}

/** Does this label exceed what the destination may hold? Used by the write path. */
export function exceeds(label: TaintLabel, classification: Classification): boolean {
  return classificationRank(label.classification) > classificationRank(classification);
}
