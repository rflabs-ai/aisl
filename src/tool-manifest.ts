/**
 * Tool declarations as data (H6, ADR-039 amendment, ADR-040).
 *
 * A declaration describes what a tool is for, which actions it serves, and what
 * params it accepts. Putting it in a manifest rather than inline in code makes
 * it reviewable as one diff and changeable without touching the implementation.
 *
 * The risk that comes with that is two sources of truth: a manifest that says
 * one thing and code that does another. The guard is that the binding is
 * strict — `manifestFor` refuses a tool with no entry rather than letting it
 * register undeclared, so a manifest that was forgotten is an error, not a
 * silent downgrade to "output provenance unknown".
 */

import { readFileSync } from 'node:fs';
import { validateDeclaration, ToolProtocolError, type ToolDeclaration } from './tool-protocol.ts';

export const TOOL_MANIFEST_VERSION = 1;

export interface ToolManifest {
  readonly version: number;
  readonly tools: readonly ToolDeclaration[];
}

export class ToolManifestError extends Error {
  constructor(file: string, detail: string) {
    super(`${file}: ${detail}`);
    this.name = 'ToolManifestError';
  }
}

export function parseManifest(file: string, raw: string): ToolManifest {
  let parsed: unknown;
  try {
    parsed = JSON.parse(raw);
  } catch (e) {
    throw new ToolManifestError(file, `malformed JSON (${(e as Error).message})`);
  }
  if (typeof parsed !== 'object' || parsed === null) throw new ToolManifestError(file, 'must be an object');
  const m = parsed as Partial<ToolManifest>;
  if (typeof m.version !== 'number' || !Number.isInteger(m.version)) {
    throw new ToolManifestError(file, '"version" must be an integer');
  }
  if (!Array.isArray(m.tools)) throw new ToolManifestError(file, '"tools" must be an array');

  const seen = new Set<string>();
  for (const [i, tool] of (m.tools as readonly unknown[]).entries()) {
    if (typeof tool !== 'object' || tool === null) throw new ToolManifestError(file, `tools[${i}] must be an object`);
    const t = tool as ToolDeclaration;
    if (seen.has(t.name)) throw new ToolManifestError(file, `duplicate tool '${t.name}'`);
    seen.add(t.name);
    const problems = validateDeclaration(t);
    if (problems.length > 0) throw new ToolProtocolError(String(t.name), problems);
  }
  return { version: m.version, tools: m.tools as readonly ToolDeclaration[] };
}

export function loadToolManifest(file: string): ToolManifest {
  return parseManifest(file, readFileSync(file, 'utf8'));
}

/**
 * The declaration for `name`, or a refusal. Never returns undefined: a tool
 * without a manifest entry must not register, or the manifest stops being the
 * authoritative description of the tool surface.
 */
export function manifestFor(manifest: ToolManifest, name: string): ToolDeclaration {
  const found = manifest.tools.find((t) => t.name === name);
  if (!found) throw new ToolManifestError('manifest', `no declaration for tool '${name}'`);
  return found;
}
