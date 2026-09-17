/**
 * Output reliability layer: the guard that sits between `model.complete()` and
 * the user. See RELIABILITY.md §2–§5 for the design this implements.
 *
 * Hard doctrine (matches the rest of the project):
 *   - The guard holds no authority. `GuardContext` exposes no issuance,
 *     authorization, secret, or grant handle. R3 enforces this structurally.
 *   - Fail-closed. If `guard()` throws, the response is withheld.
 *   - D5 leaks skip the ladder entirely. Strikethrough is not a secrecy control.
 *   - D6 (model-based critique) is telemetry only — see the stub.
 */

import { seal } from './seal.ts';
import { classificationRank, type ActionRequest, type AuthorizationDecision, type Classification } from './domain.ts';

export type ClaimFlagReason =
  | 'unverified-claim'
  | 'citation-forgery'
  | 'action-claim-mismatch'
  | 'numeric-mismatch'
  | 'leak'
  | 'critic-flag';

export interface ClaimFlag {
  readonly claim: string;
  readonly reason: ClaimFlagReason;
  readonly sourceId?: string;
}

export type GuardStatus = 'delivered' | 'flagged' | 'repaired' | 'withheld';

export interface StepRecord {
  readonly request: ActionRequest;
  readonly decision: AuthorizationDecision;
  readonly executed: boolean;
  readonly output?: unknown;
  readonly error?: string;
}

export interface GuardContext {
  readonly sessionId: string;
  readonly modelText: string;
  readonly context: ReadonlyMap<string, string>;
  readonly steps: readonly StepRecord[];
  readonly canaries: readonly string[];
  readonly classification: Classification;
}

export interface GuardedResponse {
  readonly status: GuardStatus;
  readonly text: string;
  readonly flags: readonly ClaimFlag[];
  readonly citations: readonly { readonly claim: string; readonly sourceId: string }[];
  readonly guardId: string;
  readonly originalSealed: string | null;
}

export interface ResponseGuard {
  readonly id: string;
  guard(ctx: GuardContext): GuardedResponse;
}

export type RepairFn = (text: string, flags: readonly ClaimFlag[]) => string | null;
export type RegenerateFn = (text: string, flags: readonly ClaimFlag[]) => string;

const SAFE_COMPLETION = 'I could not verify this answer.';
const ESCALATE_DEFAULT = 'This response is awaiting human review (escalation required).';
const GUARD_ID = 'grounded-guard-v1';
const NUMBER_RE = /(\b\d+(?:\.\d+)?\b)/g;
const CITATION_RE = /\[source:([^\]\s]+)\s+"([^"]*)"\]/g;
const MARKER_RE = /\[removed:\s*[a-z-]+\]/g;
const VERB_RE = /\bI\s+(deleted|wrote|created|removed|modified|added|read)\b/g;
const VERB_TO_ACTION: Readonly<Record<string, string>> = {
  deleted: 'delete', removed: 'delete', wrote: 'write', created: 'write',
  modified: 'write', added: 'write', read: 'read',
};

interface RawCitation { readonly claim: string; readonly sourceId: string; readonly index: number; readonly length: number }

function renderOutputs(steps: readonly StepRecord[]): string[] {
  const out: string[] = [];
  for (const s of steps) {
    if (!s.executed || s.output === undefined) continue;
    const rendered = typeof s.output === 'string' ? s.output : JSON.stringify(s.output);
    if (rendered !== undefined) out.push(rendered);
  }
  return out;
}

function extractCitations(text: string): readonly RawCitation[] {
  const out: RawCitation[] = [];
  for (const m of text.matchAll(CITATION_RE)) {
    if (m.index === undefined) continue;
    out.push({ claim: m[2]!, sourceId: m[1]!, index: m.index, length: m[0].length });
  }
  return out;
}

function toCitations(text: string): readonly { claim: string; sourceId: string }[] {
  return extractCitations(text).map((c) => ({ claim: c.claim, sourceId: c.sourceId }));
}

export function runDetectors(ctx: GuardContext): readonly ClaimFlag[] {
  const flags: ClaimFlag[] = [];
  for (const c of ctx.canaries) {
    if (c.length > 0 && ctx.modelText.includes(c)) flags.push({ claim: c, reason: 'leak' });
  }
  if (flags.length > 0) return flags;

  const citations = extractCitations(ctx.modelText);
  for (const c of citations) {
    const body = ctx.context.get(c.sourceId);
    if (body === undefined || c.claim.length === 0 || !body.includes(c.claim)) {
      flags.push({ claim: c.claim, reason: 'citation-forgery', sourceId: c.sourceId });
    }
  }
  const stepOutputs = renderOutputs(ctx.steps);
  for (const m of ctx.modelText.matchAll(NUMBER_RE)) {
    if (m.index === undefined) continue;
    const idx = m.index, n = m[0]!;
    const insideCitation = citations.some((s) => idx >= s.index && idx <= s.index + s.length);
    if (insideCitation) continue;
    if (stepOutputs.some((o) => o.includes(n))) continue;
    flags.push({ claim: n, reason: 'unverified-claim' });
  }
  for (const m of ctx.modelText.matchAll(VERB_RE)) {
    if (m.index === undefined) continue;
    const verb = m[1]!.toLowerCase();
    const action = VERB_TO_ACTION[verb];
    if (action === undefined) continue;
    if (!ctx.steps.some((s) => s.executed && s.request.action === action)) {
      flags.push({ claim: `I ${verb}`, reason: 'action-claim-mismatch' });
    }
  }
  if (stepOutputs.length > 0) {
    for (const m of ctx.modelText.matchAll(NUMBER_RE)) {
      const n = m[0]!;
      if (!stepOutputs.some((b) => b.includes(n))) flags.push({ claim: n, reason: 'numeric-mismatch' });
    }
  }
  return flags;
}

export function repairSpanStrip(text: string, flags: readonly ClaimFlag[]): string | null {
  let out = text;
  for (const f of flags) {
    if (!f.claim) continue;
    out = out.split(f.claim).join(`[removed: ${f.reason}]`);
  }
  const withoutMarkers = out.replace(MARKER_RE, '').trim();
  return withoutMarkers.length === 0 ? null : out;
}

export function runLadder(
  initialText: string,
  flags: readonly ClaimFlag[],
  repairFn: RepairFn,
  regenerateFn: RegenerateFn | null,
  options: { readonly escalateText: string; readonly classification: Classification; readonly ctx: GuardContext },
): GuardedResponse {
  if (flags.length === 0) return { status: 'delivered', text: initialText, flags: [], citations: toCitations(initialText), guardId: GUARD_ID, originalSealed: null };
  const repairable = flags.filter((f) => f.reason !== 'leak');
  const sealed = (txt: string) => JSON.stringify(seal(txt, options.classification));
  const okIfClean = (text: string): GuardedResponse | null =>
    runDetectors({ ...options.ctx, modelText: text, canaries: [] }).length === 0
      ? { status: 'repaired', text, flags: [], citations: toCitations(text), guardId: GUARD_ID, originalSealed: sealed(initialText) }
      : null;
  const repaired = repairFn(initialText, repairable);
  if (repaired !== null) { const r = okIfClean(repaired); if (r !== null) return r; }
  if (regenerateFn !== null) { const r = okIfClean(regenerateFn(initialText, repairable)); if (r !== null) return r; }
  const text = classificationRank(options.classification) >= classificationRank('confidential')
    ? (options.escalateText ?? ESCALATE_DEFAULT)
    : SAFE_COMPLETION;
  return { status: 'withheld', text, flags, citations: [], guardId: GUARD_ID, originalSealed: sealed(initialText) };
}

export function assertGuardContextIsReadOnly(ctx: GuardContext): void {
  const offenders = Object.keys(ctx).filter((k) => /issue|authoriz|secret|grant/i.test(k));
  if (offenders.length > 0) {
    throw new Error(`GuardContext exposes authority-shaped keys: ${offenders.join(',')}`);
  }
}

export class GroundedResponseGuard implements ResponseGuard {
  readonly id = GUARD_ID;
  guard(ctx: GuardContext): GuardedResponse {
    try {
      const flags = runDetectors(ctx);
      if (flags.some((f) => f.reason === 'leak')) {
        return { status: 'withheld', text: SAFE_COMPLETION, flags, citations: [], guardId: this.id, originalSealed: JSON.stringify(seal(ctx.modelText, ctx.classification)) };
      }
      return runLadder(ctx.modelText, flags.filter((f) => f.reason !== 'leak'), repairSpanStrip, null, { escalateText: ESCALATE_DEFAULT, classification: ctx.classification, ctx });
    } catch {
      return { status: 'withheld', text: SAFE_COMPLETION, flags: [], citations: [], guardId: this.id, originalSealed: null };
    }
  }
}

// ponytail: D6 model-based critique is a stub. Real critic is a future hook;
// upgrade path: a second model pass with critic prompt or n-sample agreement. Telemetry only.
export const D6_STUB = true;
