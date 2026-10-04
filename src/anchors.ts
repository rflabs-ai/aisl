/**
 * H11 (ADR-031): tamper-evident evidence — external anchor sinks, multi-source
 * reconciliation, and operator-held checkpoints.
 *
 * M3 anchored each head hash to a local file inside the runtime's trust domain.
 * This module adds the pieces that make the anchor durable *outside* it:
 *
 * - `AnchorSink`: a publication port. The M3 file stays as-is (events.ts owns
 *   `anchorPath`); `FileAnchorSink` is a second file witness (e.g. a mounted
 *   WORM path), and `HttpAnchorSink` publishes heads to an operator-configured
 *   witness over the built-in fetch. Publication is non-blocking: a dead
 *   witness degrades detection granularity, never availability, and never
 *   silently (counters + `lastError`, draivable with `flush()`).
 * - `verifyAnchoredEvidence`: reconciles a bundle against any number of anchor
 *   sources — binding, head coverage, truncation (a source ahead of the
 *   bundle), and forks (two sources disagreeing at one seq).
 * - `createCheckpoint` / `verifyCheckpoint`: an Ed25519-signed
 *   `asl-anchor-checkpoint` the operator holds off-host. This is the offline
 *   external witness: a rewritten or truncated chain fails against it even
 *   when the attacker holds the signing key.
 *
 * Trust boundary: the witness receives `{ seq, headHash, eventCount, sentAt }`
 * only — no event content, no tenant data, no signing key. The optional bearer
 * token lives in config and is never logged or echoed into status/errors.
 */

import { appendFileSync, existsSync, mkdirSync } from 'node:fs';
import { dirname } from 'node:path';
import { createHash, sign as cryptoSign, verify as cryptoVerify, type KeyObject } from 'node:crypto';
import { canonicalJson } from './domain.ts';
import {
  eventPublicKey,
  eventSigningKeyPair,
  verifyBundle,
  type AuditExport,
  type SecurityEvent,
  type VerificationResult,
} from './events.ts';

const SHA256_HEX = /^[0-9a-f]{64}$/;

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}

// ---------------------------------------------------------------------------
// Anchor sinks
// ---------------------------------------------------------------------------

/** One published anchor: the chain head at a point in time. */
export interface AnchorPoint {
  readonly seq: number;
  readonly headHash: string;
  /** Number of events in the chain when this point was published (seq + 1). */
  readonly eventCount: number;
  /** Event timestamp of the anchored head (ms epoch). */
  readonly at: number;
}

export interface AnchorSinkStatus {
  readonly name: string;
  readonly published: number;
  readonly failed: number;
  readonly dropped: number;
  readonly pending: number;
  readonly lastPublishedSeq?: number;
  readonly lastError?: string;
}

/**
 * Publication port. `publish` must never throw into the evidence append: a
 * misbehaving sink is the sink's bug, not a reason to lose an event.
 */
export interface AnchorSink {
  readonly name: string;
  publish(point: AnchorPoint): void;
  flush(): Promise<void>;
  status(): AnchorSinkStatus;
}

/** A second anchor file (e.g. a WORM mount). Same `<seq>:<hash>\n` format as M3. */
export class FileAnchorSink implements AnchorSink {
  readonly name: string;
  private readonly path: string;
  private published = 0;
  private lastSeq?: number;

  constructor(path: string, name = 'file') {
    this.path = path;
    this.name = name;
  }

  publish(point: AnchorPoint): void {
    const dir = dirname(this.path);
    if (dir && dir !== '.' && !existsSync(dir)) mkdirSync(dir, { recursive: true });
    appendFileSync(this.path, `${point.seq}:${point.headHash}\n`, 'utf8');
    this.published += 1;
    this.lastSeq = point.seq;
  }

  async flush(): Promise<void> {}

  status(): AnchorSinkStatus {
    return {
      name: this.name,
      published: this.published,
      failed: 0,
      dropped: 0,
      pending: 0,
      ...(this.lastSeq !== undefined ? { lastPublishedSeq: this.lastSeq } : {}),
    };
  }
}

export interface HttpAnchorSinkOptions {
  readonly url: string;
  /** Optional witness bearer token (env-sourced; never logged). */
  readonly token?: string;
  readonly name?: string;
  /** Bounded pending queue; overflow drops the OLDEST point (the newest head still proves truncation). */
  readonly queueLimit?: number;
  readonly fetchFn?: typeof globalThis.fetch;
}

/**
 * Publishes each head to an operator-configured HTTP witness. The queue is
 * drained on publish (fire-and-forget) and on `flush()`. A failed publish
 * keeps the point at the head of the queue for the next attempt and records a
 * fixed-label error — no URL, no token, no response body.
 */
export class HttpAnchorSink implements AnchorSink {
  readonly name: string;
  private readonly url: string;
  private readonly token?: string;
  private readonly fetchFn: typeof globalThis.fetch;
  private readonly queueLimit: number;
  private readonly queue: AnchorPoint[] = [];
  private inflight?: Promise<void>;
  private publishedCount = 0;
  private failedCount = 0;
  private droppedCount = 0;
  private lastSeq?: number;
  private lastError?: string;

  constructor(options: HttpAnchorSinkOptions) {
    if (!options.url) throw new Error('HttpAnchorSink requires a witness url');
    const limit = options.queueLimit ?? 256;
    if (!Number.isSafeInteger(limit) || limit < 1) throw new Error('HttpAnchorSink queueLimit must be a positive integer');
    this.url = options.url;
    if (options.token !== undefined) this.token = options.token;
    this.fetchFn = options.fetchFn ?? globalThis.fetch.bind(globalThis);
    this.queueLimit = limit;
    this.name = options.name ?? 'http-witness';
  }

  publish(point: AnchorPoint): void {
    if (this.queue.length >= this.queueLimit) {
      this.queue.shift();
      this.droppedCount += 1;
    }
    this.queue.push(point);
    // Fire-and-forget: the append path must never await the network.
    void this.flush();
  }

  flush(): Promise<void> {
    if (!this.inflight) {
      this.inflight = this.drain().finally(() => {
        this.inflight = undefined;
      });
    }
    return this.inflight;
  }

  private async drain(): Promise<void> {
    while (this.queue.length > 0) {
      const point = this.queue[0]!;
      const headers: Record<string, string> = { 'content-type': 'application/json' };
      if (this.token !== undefined) headers.authorization = `Bearer ${this.token}`;
      let response: Response;
      try {
        response = await this.fetchFn(this.url, {
          method: 'POST',
          headers,
          body: JSON.stringify({
            version: 1,
            kind: 'asl-anchor-head',
            seq: point.seq,
            headHash: point.headHash,
            eventCount: point.eventCount,
            sentAt: point.at,
          }),
        });
      } catch {
        this.failedCount += 1;
        this.lastError = 'witness request failed (network)';
        return;
      }
      if (!response.ok) {
        this.failedCount += 1;
        this.lastError = `witness refused the anchor (HTTP ${response.status})`;
        return;
      }
      this.queue.shift();
      this.publishedCount += 1;
      this.lastSeq = point.seq;
      this.lastError = undefined;
    }
  }

  status(): AnchorSinkStatus {
    return {
      name: this.name,
      published: this.publishedCount,
      failed: this.failedCount,
      dropped: this.droppedCount,
      pending: this.queue.length,
      ...(this.lastSeq !== undefined ? { lastPublishedSeq: this.lastSeq } : {}),
      ...(this.lastError !== undefined ? { lastError: this.lastError } : {}),
    };
  }
}

// ---------------------------------------------------------------------------
// Witness head protocol (verification side)
// ---------------------------------------------------------------------------

export class WitnessProtocolError extends Error {}

export interface WitnessHead {
  readonly seq: number;
  readonly headHash: string;
  readonly receivedAt?: number;
}

/**
 * ponytail: no paging — one witness response must carry every head, capped to
 * bound memory against a hostile witness. Upgrade: `?fromSeq=` paging when a
 * real chain outgrows the cap.
 */
export const MAX_WITNESS_HEADS = 100_000;

function witnessError(message: string): WitnessProtocolError {
  return new WitnessProtocolError(message);
}

/** Fetch the witness's recorded heads. A malformed response is refused whole — no partial trust. */
export async function fetchWitnessHeads(
  url: string,
  options: { token?: string; fetchFn?: typeof globalThis.fetch } = {},
): Promise<WitnessHead[]> {
  const headers: Record<string, string> = { accept: 'application/json' };
  if (options.token !== undefined) headers.authorization = `Bearer ${options.token}`;
  let response: Response;
  try {
    response = await (options.fetchFn ?? globalThis.fetch.bind(globalThis))(url, { method: 'GET', headers });
  } catch {
    throw witnessError('witness request failed (network)');
  }
  if (!response.ok) throw witnessError(`witness refused the request (HTTP ${response.status})`);
  let body: unknown;
  try {
    body = await response.json();
  } catch {
    throw witnessError('witness response is not valid JSON');
  }
  if (!isRecord(body)) throw witnessError('witness response is not an object');
  const heads = body.heads;
  if (!Array.isArray(heads)) throw witnessError('witness response has no heads array');
  if (heads.length > MAX_WITNESS_HEADS) throw witnessError('witness response carries too many heads (paging is not implemented)');
  const out: WitnessHead[] = [];
  for (const raw of heads) {
    if (!isRecord(raw)) throw witnessError('witness head is not an object');
    const { seq, headHash, receivedAt } = raw;
    if (typeof seq !== 'number' || !Number.isSafeInteger(seq) || seq < 0) {
      throw witnessError('witness head seq is not a non-negative integer');
    }
    if (typeof headHash !== 'string' || !SHA256_HEX.test(headHash)) {
      throw witnessError('witness head is not a sha256 hex digest');
    }
    if (receivedAt !== undefined && (typeof receivedAt !== 'number' || !Number.isSafeInteger(receivedAt) || receivedAt < 0)) {
      throw witnessError('witness head receivedAt is not a non-negative integer');
    }
    out.push(receivedAt === undefined ? { seq, headHash } : { seq, headHash, receivedAt });
  }
  return out;
}

/** Convert witness heads into M3 anchor-line content so one verifier covers both sources. */
export function witnessHeadsToAnchorContent(heads: readonly WitnessHead[]): string {
  return heads.map((h) => `${h.seq}:${h.headHash}`).join('\n') + (heads.length > 0 ? '\n' : '');
}

// ---------------------------------------------------------------------------
// Anchor parsing + reconciliation
// ---------------------------------------------------------------------------

export interface ParsedAnchorLine {
  readonly seq: number;
  readonly headHash: string;
  /** 1-based line number in the source content. */
  readonly line: number;
}

export interface AnchorParse {
  readonly lines: readonly ParsedAnchorLine[];
  readonly errors: readonly string[];
}

/** Parse M3 anchor content. Malformed lines are reported with their line number; they are never skipped silently. */
export function parseAnchorLines(content: string): AnchorParse {
  const lines: ParsedAnchorLine[] = [];
  const errors: string[] = [];
  const seen = new Set<number>();
  content.split(/\r?\n/).forEach((text, i) => {
    const lineNo = i + 1;
    const trimmed = text.trim();
    if (trimmed === '') return;
    const match = /^(\d+):([0-9a-f]{64})$/.exec(trimmed);
    if (!match) {
      errors.push(`line ${lineNo}: not in <seq>:<sha256-hex> format`);
      return;
    }
    const seq = Number(match[1]);
    if (!Number.isSafeInteger(seq) || seq < 0) {
      errors.push(`line ${lineNo}: seq is not a non-negative integer`);
      return;
    }
    if (seen.has(seq)) {
      errors.push(`line ${lineNo}: duplicate seq ${seq}`);
      return;
    }
    seen.add(seq);
    lines.push({ seq, headHash: match[2]!, line: lineNo });
  });
  return { lines, errors };
}

export interface AnchorSource {
  readonly name: string;
  readonly content: string;
}

export interface AnchorSourceReport {
  readonly name: string;
  readonly lines: number;
  readonly headSeq?: number;
  readonly headHash?: string;
  readonly matchesBundleHead: boolean;
  readonly aheadOfBundle: boolean;
  readonly errors: readonly string[];
}

export interface AnchorFork {
  readonly seq: number;
  readonly hashes: readonly { readonly source: string; readonly headHash: string }[];
}

export interface AnchoredVerification {
  readonly valid: boolean;
  /** True when no external source was presented: the bundle verifies, but is not corroborated. */
  readonly unanchored: boolean;
  readonly bundle: VerificationResult;
  readonly sources: readonly AnchorSourceReport[];
  readonly fork?: AnchorFork;
  readonly checkpoint?: CheckpointVerification;
  readonly errors: readonly string[];
}

function extractEvents(input: string | AuditExport | readonly SecurityEvent[]): { events: SecurityEvent[]; errors: string[] } {
  try {
    if (typeof input === 'string') {
      const parsed: unknown = JSON.parse(input);
      if (!isRecord(parsed) || !Array.isArray(parsed.events)) return { events: [], errors: ['bundle JSON has no events array'] };
      return { events: parsed.events as SecurityEvent[], errors: [] };
    }
    if (Array.isArray(input)) return { events: [...input], errors: [] };
    // Same narrowing pattern as verifyBundle: the union member is selected
    // here; the hash/signature checks downstream are the actual trust gate.
    const exported = input as AuditExport;
    return { events: [...exported.events], errors: [] };
  } catch {
    return { events: [], errors: ['bundle is not valid JSON'] };
  }
}

/**
 * Reconcile a bundle against zero or more anchor sources.
 *
 * Fail-closed rules: a malformed source, a gap/reorder within a source, a
 * line that disagrees with the event at its seq, a source ahead of the bundle
 * head (tail truncation), cross-source divergence at one seq (fork), or a
 * bundle head no source covers (unanchored tail) each invalidate the result.
 * With no sources the result is `unanchored: true` — never silently anchored.
 */
export function verifyAnchoredEvidence(
  bundle: string | AuditExport | readonly SecurityEvent[],
  options: { publicKey?: KeyObject; sources?: readonly AnchorSource[]; checkpoint?: EvidenceCheckpoint } = {},
): AnchoredVerification {
  const bundleResult = verifyBundle(bundle, options.publicKey !== undefined ? { publicKey: options.publicKey } : {});
  const { events, errors: extractErrors } = extractEvents(bundle);
  const errors: string[] = [...extractErrors];
  const head = events.at(-1);
  const bySeq = new Map<number, { source: string; headHash: string }[]>();
  const reports: AnchorSourceReport[] = [];
  const sources = options.sources ?? [];

  const eventHashBySeq = new Map<number, string>();
  for (const e of events) eventHashBySeq.set(e.seq, e.eventHash);

  for (const source of sources) {
    const parsed = parseAnchorLines(source.content);
    const sourceErrors: string[] = [...parsed.errors];

    for (let i = 1; i < parsed.lines.length; i++) {
      const prev = parsed.lines[i - 1]!;
      const cur = parsed.lines[i]!;
      if (cur.seq !== prev.seq + 1) {
        sourceErrors.push(`seq order: line ${cur.line} has seq ${cur.seq} after ${prev.seq} (gap or reorder)`);
      }
    }

    for (const line of parsed.lines) {
      const boundHash = eventHashBySeq.get(line.seq);
      if (boundHash !== undefined && boundHash !== line.headHash) {
        sourceErrors.push(`seq ${line.seq}: anchor hash does not match the event at that seq`);
      }
      if (head !== undefined && line.seq > head.seq) {
        sourceErrors.push(`seq ${line.seq}: anchor is ahead of the bundle head (${head.seq})`);
      }
    }

    const last = parsed.lines.at(-1);
    const aheadOfBundle = head !== undefined && last !== undefined && last.seq > head.seq;
    const matchesBundleHead =
      head !== undefined && parsed.lines.some((l) => l.seq === head.seq && l.headHash === head.eventHash);

    reports.push({
      name: source.name,
      lines: parsed.lines.length,
      ...(last !== undefined ? { headSeq: last.seq, headHash: last.headHash } : {}),
      matchesBundleHead,
      aheadOfBundle,
      errors: sourceErrors,
    });

    for (const line of parsed.lines) {
      const entries = bySeq.get(line.seq);
      const entry = { source: source.name, headHash: line.headHash };
      if (entries) entries.push(entry);
      else bySeq.set(line.seq, [entry]);
    }
  }

  let fork: AnchorFork | undefined;
  for (const [seq, entries] of bySeq) {
    if (new Set(entries.map((e) => e.headHash)).size > 1) {
      fork = { seq, hashes: entries };
      errors.push(`anchor fork at seq ${seq}: ${entries.map((e) => e.source).join(', ')} disagree`);
    }
  }

  const unanchored = sources.length === 0;
  if (!unanchored) {
    if (head === undefined) {
      errors.push('the bundle has no events to anchor');
    } else if (!reports.some((r) => r.matchesBundleHead)) {
      errors.push(`the bundle head (seq ${head.seq}) is not anchored by any source: the tail is unanchored`);
    }
    if (reports.some((r) => r.aheadOfBundle)) {
      errors.push('an anchor source is ahead of the bundle head: tail truncation suspected');
    }
  }
  for (const report of reports) {
    for (const error of report.errors) errors.push(`${report.name}: ${error}`);
  }

  let checkpoint: CheckpointVerification | undefined;
  if (options.checkpoint !== undefined) {
    checkpoint = verifyCheckpoint(
      options.checkpoint,
      events,
      options.publicKey !== undefined ? { publicKey: options.publicKey } : {},
    );
    if (!checkpoint.valid) errors.push(...checkpoint.errors.map((e) => `checkpoint: ${e}`));
  }

  const valid = bundleResult.valid && errors.length === 0;
  return {
    valid,
    unanchored,
    bundle: bundleResult,
    sources: reports,
    ...(fork !== undefined ? { fork } : {}),
    ...(checkpoint !== undefined ? { checkpoint } : {}),
    errors,
  };
}

// ---------------------------------------------------------------------------
// Operator-held checkpoints
// ---------------------------------------------------------------------------

/**
 * A signed statement by the operator: "at seq N the chain head was H".
 * Held off-host, this is H11's "append-only store the runtime cannot rewrite".
 */
export interface EvidenceCheckpoint {
  readonly type: 'asl-anchor-checkpoint';
  readonly version: 1;
  readonly seq: number;
  readonly headHash: string;
  readonly eventCount: number;
  readonly createdAt: number;
  readonly previousCheckpointDigest: string | null;
  readonly signature: string;
}

function checkpointBody(checkpoint: EvidenceCheckpoint): Record<string, unknown> {
  return {
    type: checkpoint.type,
    version: checkpoint.version,
    seq: checkpoint.seq,
    headHash: checkpoint.headHash,
    eventCount: checkpoint.eventCount,
    createdAt: checkpoint.createdAt,
    previousCheckpointDigest: checkpoint.previousCheckpointDigest,
  };
}

export function checkpointDigest(checkpoint: EvidenceCheckpoint): string {
  return createHash('sha256').update(canonicalJson(checkpointBody(checkpoint))).digest('hex');
}

/**
 * Sign the chain head with the existing event-signing key (no new key, no new
 * authority). The chain must be the full dense chain from seq 0: a checkpoint
 * of a slice would be an unfalsifiable claim about a window.
 */
export function createCheckpoint(
  events: readonly SecurityEvent[],
  options: { previous?: EvidenceCheckpoint; now?: number } = {},
): EvidenceCheckpoint {
  if (events.length === 0) throw new Error('cannot create an evidence checkpoint for an empty chain');
  if (events[0]!.seq !== 0 || events.some((e, i) => e.seq !== i)) {
    throw new Error('cannot create an evidence checkpoint without the full chain from seq 0');
  }
  const last = events.at(-1)!;
  const body = {
    type: 'asl-anchor-checkpoint' as const,
    version: 1 as const,
    seq: last.seq,
    headHash: last.eventHash,
    eventCount: events.length,
    createdAt: options.now ?? Date.now(),
    previousCheckpointDigest: options.previous !== undefined ? checkpointDigest(options.previous) : null,
  };
  const signature = cryptoSign(null, Buffer.from(canonicalJson(body), 'utf8'), eventSigningKeyPair().privateKey).toString('base64');
  return { ...body, signature };
}

export interface CheckpointVerification {
  readonly valid: boolean;
  readonly errors: readonly string[];
}

/**
 * Verify a checkpoint against a full chain. Refuses: structural garbage, a bad
 * signature, a chain that is not the full dense chain, a chain shorter than
 * the checkpoint (truncation), a chain whose event at the checkpointed seq
 * hashes differently (rewrite), a broken checkpoint chain (previous digest
 * mismatch), and a same-seq fork against the previous checkpoint.
 */
export function verifyCheckpoint(
  checkpoint: EvidenceCheckpoint,
  events: readonly SecurityEvent[],
  options: { publicKey?: KeyObject; previous?: EvidenceCheckpoint } = {},
): CheckpointVerification {
  const errors: string[] = [];

  if (!isRecord(checkpoint) || checkpoint.type !== 'asl-anchor-checkpoint') {
    return { valid: false, errors: ['checkpoint type is not asl-anchor-checkpoint'] };
  }
  if (checkpoint.version !== 1) errors.push(`unsupported checkpoint version ${String(checkpoint.version)}`);
  if (!Number.isSafeInteger(checkpoint.seq) || checkpoint.seq < 0) errors.push('checkpoint seq is not a non-negative integer');
  if (typeof checkpoint.headHash !== 'string' || !SHA256_HEX.test(checkpoint.headHash)) errors.push('checkpoint headHash is not a sha256 hex digest');
  if (!Number.isSafeInteger(checkpoint.eventCount) || checkpoint.eventCount <= 0) errors.push('checkpoint eventCount is not a positive integer');
  if (typeof checkpoint.createdAt !== 'number' || !Number.isFinite(checkpoint.createdAt)) errors.push('checkpoint createdAt is not a finite number');
  if (checkpoint.previousCheckpointDigest !== null && (typeof checkpoint.previousCheckpointDigest !== 'string' || !SHA256_HEX.test(checkpoint.previousCheckpointDigest))) {
    errors.push('checkpoint previousCheckpointDigest is neither null nor a sha256 hex digest');
  }
  if (typeof checkpoint.signature !== 'string' || checkpoint.signature === '') errors.push('checkpoint has no signature');
  if (errors.length > 0) return { valid: false, errors };

  let signatureValid = false;
  try {
    signatureValid = cryptoVerify(
      null,
      Buffer.from(canonicalJson(checkpointBody(checkpoint)), 'utf8'),
      options.publicKey ?? eventPublicKey(),
      Buffer.from(checkpoint.signature, 'base64'),
    );
  } catch {
    signatureValid = false;
  }
  if (!signatureValid) return { valid: false, errors: ['checkpoint signature does not verify'] };

  if (events.length === 0 || events[0]!.seq !== 0 || events.some((e, i) => e.seq !== i)) {
    return { valid: false, errors: ['checkpoint verification requires the full chain from seq 0'] };
  }
  const head = events.at(-1)!;
  if (checkpoint.seq > head.seq) {
    return { valid: false, errors: [`checkpoint seq ${checkpoint.seq} is beyond the chain head ${head.seq}: tail truncation`] };
  }
  const bound = events[checkpoint.seq]!;
  if (bound.eventHash !== checkpoint.headHash) {
    return { valid: false, errors: [`checkpoint headHash does not match the event at seq ${checkpoint.seq}: the chain was rewritten`] };
  }
  if (checkpoint.eventCount !== checkpoint.seq + 1) {
    errors.push(`checkpoint eventCount ${checkpoint.eventCount} does not equal seq+1 (${checkpoint.seq + 1})`);
  }

  if (options.previous !== undefined) {
    const previous = options.previous;
    if (checkpoint.previousCheckpointDigest !== checkpointDigest(previous)) {
      errors.push('checkpoint does not chain to the previous checkpoint (digest mismatch)');
    }
    if (checkpoint.seq < previous.seq) errors.push('checkpoint seq is before the previous checkpoint');
    if (checkpoint.seq === previous.seq && checkpoint.headHash !== previous.headHash) {
      errors.push(`checkpoint fork: same seq ${checkpoint.seq} as the previous checkpoint with a different head hash`);
    }
    if (checkpoint.seq > previous.seq) {
      const previousBound = events[previous.seq];
      if (!previousBound || previousBound.eventHash !== previous.headHash) {
        errors.push('the previous checkpoint no longer matches the chain: fork or rewrite detected');
      }
    }
  }

  return { valid: errors.length === 0, errors };
}