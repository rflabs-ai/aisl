/**
 * `npm run policy:diff` — loads BASELINE_POLICY plus an optional overlay file
 * and prints the changed scenarios.
 *
 * Usage:
 *   node src/policy-diff.ts                       # baseline vs baseline (prints "0 changed")
 *   node src/policy-diff.ts path/to/overlay.json  # baseline vs baseline+overlay
 *
 * Overlay file shape:
 *   { "rules": [ ...PolicyRule... ] }                      (legacy, unversioned)
 *   { "id", "version", "rules", "provenance", "hash" }     (M11 PolicyBundle —
 *    hash-verified BEFORE any engine is built; mismatch aborts the diff)
 */

import { readFileSync } from 'node:fs';
import { createPolicyEngine, BASELINE_POLICY, type PolicyRule } from './policy.ts';
import { diffDecisions } from './policy-testing.ts';
import { loadPolicyBundle, type PolicyBundle } from './policy-config.ts';

const overlayPath = process.argv[2];

function baselineScenarios() {
  const now = Date.UTC(2026, 5, 1);
  const agent = {
    id: 'agent:a', kind: 'agent' as const, tenantId: 'acme',
    roles: ['worker'], attributes: {},
  };
  const doc = (id: string, classification: string, tenantId = 'acme') => ({
    id, type: 'document' as const, tenantId, classification, attributes: {},
  });
  return [
    { principal: agent, resource: doc('repo-a', 'internal'), action: 'read', now },
    { principal: agent, resource: doc('phi-doc', 'phi'), action: 'read', now },
    { principal: agent, resource: doc('phi-doc', 'phi'), action: 'export', now },
    { principal: agent, resource: doc('repo-a', 'internal'), action: 'export', now },
    { principal: agent, resource: doc('repo-a', 'public'), action: 'read', now },
  ];
}

interface Overlay {
  readonly rules: readonly PolicyRule[];
  readonly id: string;
  readonly versionLabel: string;
}

function loadOverlay(path: string): Overlay {
  const raw = JSON.parse(readFileSync(path, 'utf8')) as { rules?: unknown; version?: unknown; id?: unknown };
  // Versioned bundle: verify the hash before any engine is built (fail closed).
  if (raw.version !== undefined) {
    const bundle = loadPolicyBundle(raw as PolicyBundle);
    return { rules: bundle.rules, id: bundle.id, versionLabel: ` (bundle v${bundle.version})` };
  }
  if (!Array.isArray(raw.rules)) throw new Error(`overlay ${path}: "rules" must be an array`);
  return { rules: raw.rules as readonly PolicyRule[], id: 'baseline+overlay', versionLabel: '' };
}

// The overlay is verified (and may abort the run) before any engine is built.
const overlay = overlayPath ? loadOverlay(overlayPath) : undefined;
if (overlay?.versionLabel) console.log(`overlay: ${overlay.id}${overlay.versionLabel}`);

const before = createPolicyEngine(BASELINE_POLICY, 'baseline');
const after = overlay
  ? createPolicyEngine([...BASELINE_POLICY, ...overlay.rules], overlay.id)
  : createPolicyEngine(BASELINE_POLICY, 'baseline');
const scenarios = baselineScenarios();
const diffs = diffDecisions(before, after, scenarios);
console.log(`${diffs.length} changed`);
for (const d of diffs) {
  console.log(`  [${d.index}] ${d.scenario.action} ${d.scenario.resource.id} (${d.scenario.resource.classification})`);
  console.log(`    before: ${d.before.effect} rule=${d.before.ruleId ?? '∅'} reason=${d.before.reason}`);
  console.log(`    after:  ${d.after.effect} rule=${d.after.ruleId ?? '∅'} reason=${d.after.reason}`);
}
