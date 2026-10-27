/**
 * Content-level egress DLP (H7, ADR-037).
 *
 * The PDP decides *where* bytes may go. This decides *what* may go: a payload
 * carrying a value above the destination's ceiling, or a canary value planted
 * to prove exfiltration, is refused before it leaves the process.
 *
 * Two design rules:
 *   1. A refusal never echoes the value it caught. The reason names a class
 *      ("canary:phi"), never the token — otherwise the error message is the
 *      exfiltration channel.
 *   2. Encodings are checked, not trusted. A token is matched raw, base64
 *      (standard and url-safe), hex, and url-encoded, and the payload is
 *      decoded once before matching — the cheap evasions are the common ones.
 *
 * What this is not: semantic DLP. It cannot know that a paraphrase or a
 * steganographic channel carries the data (ADR-037 residual), and it does not
 * replace the classification check, which stays authoritative.
 */

import { classificationRank, type Classification } from './domain.ts';
import type { TaintLabel } from './taint.ts';

/** A planted value whose appearance in egress proves a leak. */
export interface Canary {
  /** Unique token, e.g. `CANARY-phi-7f3a2b`. */
  readonly token: string;
  readonly classification: Classification;
}

export type DlpFindingKind = 'above-ceiling' | 'canary' | 'volume';

export interface DlpFinding {
  readonly kind: DlpFindingKind;
  readonly classification: Classification;
  /** Fixed label describing the match — never the matched value. */
  readonly detail: string;
}

export interface DlpVerdict {
  readonly allow: boolean;
  /** Machine-readable reason; a fixed label, never content. */
  readonly reason: string;
  readonly findings: readonly DlpFinding[];
  readonly bytes: number;
}

export interface EgressInspection {
  readonly payload: string;
  readonly label: TaintLabel;
  /** Highest classification this destination may receive. */
  readonly ceiling: Classification;
  readonly canaries?: readonly Canary[];
  /** Payload size cap for this egress; above it the egress is refused. */
  readonly maxBytes?: number;
}

const bytesOf = (s: string): number => Buffer.byteLength(s, 'utf8');

/** Every cheap encoding of a token that an exfiltration attempt might use. */
export function tokenEncodings(token: string): readonly string[] {
  const buf = Buffer.from(token, 'utf8');
  const b64 = buf.toString('base64');
  const b64url = b64.replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
  return [token, b64, b64url, buf.toString('hex'), encodeURIComponent(token)];
}

const BASE64_RE = /^[A-Za-z0-9+/=\s]{16,}$/;
const HEX_RE = /^(?:[0-9a-fA-F]{2})+$/;

/**
 * One decode pass over the payload. A fully-encoded body is the most obvious
 * bypass, so it is checked explicitly rather than left to the caller.
 */
function decodeOnce(payload: string): readonly string[] {
  const trimmed = payload.trim();
  const out: string[] = [];
  if (BASE64_RE.test(trimmed)) {
    try {
      out.push(Buffer.from(trimmed, 'base64').toString('utf8'));
    } catch {
      /* not decodable — nothing to add */
    }
  }
  if (HEX_RE.test(trimmed)) {
    try {
      out.push(Buffer.from(trimmed, 'hex').toString('utf8'));
    } catch {
      /* not decodable — nothing to add */
    }
  }
  return out;
}

/** Canaries present in this text, raw or encoded, including a single decode pass. */
export function scanForCanaries(payload: string, canaries: readonly Canary[]): readonly DlpFinding[] {
  if (canaries.length === 0) return [];
  const candidates = [payload, ...decodeOnce(payload)];
  const findings: DlpFinding[] = [];

  for (const canary of canaries) {
    if (canary.token.length < 4) continue; // too short to be evidence of anything
    const encodings = tokenEncodings(canary.token);
    const hit = candidates.some((candidate) => encodings.some((needle) => candidate.includes(needle)));
    if (hit) {
      findings.push({
        kind: 'canary',
        classification: canary.classification,
        detail: `canary:${canary.classification}`,
      });
    }
  }
  return findings;
}

/**
 * Decide whether this payload may leave. Order matters: the classification
 * check is authoritative, so it runs first and cannot be argued with by a
 * clean canary scan.
 */
export function inspectEgress(input: EgressInspection): DlpVerdict {
  const bytes = bytesOf(input.payload);
  const findings: DlpFinding[] = [];

  if (classificationRank(input.label.classification) > classificationRank(input.ceiling)) {
    findings.push({
      kind: 'above-ceiling',
      classification: input.label.classification,
      detail: `payload:${input.label.classification}`,
    });
  }

  findings.push(...scanForCanaries(input.payload, input.canaries ?? []));

  if (input.maxBytes !== undefined && bytes > input.maxBytes) {
    findings.push({
      kind: 'volume',
      classification: input.label.classification,
      detail: `volume:${bytes}>${input.maxBytes}`,
    });
  }

  const first = findings[0];
  return {
    allow: first === undefined,
    reason: first === undefined ? 'egress-allow' : first.detail,
    findings,
    bytes,
  };
}
