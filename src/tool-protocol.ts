/**
 * Agent-to-tool protocol (H6, ADR-039).
 *
 * The session and a tool agree on three things before any call happens: what
 * the tool is for (a description the model reads), which actions it serves, and
 * what params it accepts. All three are untrusted input — the description is
 * attacker-influenceable text that lands in a prompt, and params arrive from a
 * model that may be compromised.
 *
 * This module is the declaration and its validation. Enforcement (refusing a
 * call, refusing an undeclared output) lives in `AgentSession`.
 */

import { KNOWN_ACTIONS, type Action } from './domain.ts';
import { detectInjectionSignals } from './registry.ts';

export const TOOL_PROTOCOL_VERSION = 1;

export interface ToolParamSpec {
  readonly name: string;
  readonly required?: boolean;
  readonly type?: 'string' | 'number' | 'boolean';
}

export interface ToolDeclaration {
  readonly name: string;
  /** Shown to the model. Data, never instructions — validated as such below. */
  readonly description: string;
  readonly actions: readonly Action[];
  /** When present, params outside this list are refused (no smuggled keys). */
  readonly params?: readonly ToolParamSpec[];
  /** The tool's own output ceiling; the session enforces the smaller of this and its quota. */
  readonly maxOutputBytes?: number;
}

export class ToolProtocolError extends Error {
  readonly problems: readonly string[];
  constructor(name: string, problems: readonly string[]) {
    super(`tool '${name}' violates the protocol: ${problems.join('; ')}`);
    this.name = 'ToolProtocolError';
    this.problems = problems;
  }
}

/**
 * A tool description is prompt text. Instructions in it are an injection
 * vector, so the same detector that flags hostile documents flags it here —
 * and unlike a document, a schema description has no legitimate reason to
 * contain them.
 */
export function schemaInjectionSignals(declaration: ToolDeclaration): readonly string[] {
  return detectInjectionSignals(declaration.description);
}

export function validateDeclaration(declaration: ToolDeclaration): readonly string[] {
  const problems: string[] = [];
  if (declaration.name.trim() === '') problems.push('name must be non-empty');
  if (declaration.description.trim() === '') problems.push('description must be non-empty');

  const signals = schemaInjectionSignals(declaration);
  if (signals.length > 0) problems.push(`description contains injection signals: ${signals.join(', ')}`);

  if (declaration.actions.length === 0) problems.push('actions must be non-empty');
  const unknown = declaration.actions.filter((a) => !(KNOWN_ACTIONS as readonly string[]).includes(a));
  if (unknown.length > 0) problems.push(`actions outside the vocabulary: ${unknown.join(', ')}`);

  const seen = new Set<string>();
  for (const param of declaration.params ?? []) {
    if (param.name.trim() === '') problems.push('param name must be non-empty');
    if (seen.has(param.name)) problems.push(`duplicate param '${param.name}'`);
    seen.add(param.name);
  }

  return problems;
}

export function assertDeclaration(declaration: ToolDeclaration): void {
  const problems = validateDeclaration(declaration);
  if (problems.length > 0) throw new ToolProtocolError(declaration.name, problems);
}

export interface ParamValidation {
  readonly ok: boolean;
  readonly error?: string;
}

/**
 * Parameter confusion: a declared tool accepts exactly its declared keys. An
 * undeclared extra key is refused rather than ignored, because ignoring it
 * leaves the tool free to read it.
 */
export function validateParams(
  declaration: ToolDeclaration,
  params: Readonly<Record<string, unknown>> | undefined,
): ParamValidation {
  const specs = declaration.params;
  if (specs === undefined) return { ok: true };
  const given = params ?? {};
  const declared = new Set(specs.map((s) => s.name));

  const extra = Object.keys(given).filter((k) => !declared.has(k));
  if (extra.length > 0) return { ok: false, error: `undeclared params: ${extra.sort().join(', ')}` };

  for (const spec of specs) {
    const value = given[spec.name];
    if (value === undefined) {
      if (spec.required === true) return { ok: false, error: `missing required param '${spec.name}'` };
      continue;
    }
    if (spec.type !== undefined && typeof value !== spec.type) {
      return { ok: false, error: `param '${spec.name}' must be ${spec.type}` };
    }
  }
  return { ok: true };
}
