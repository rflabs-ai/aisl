/**
 * H11 — Tamper-evident evidence (ADR-031).
 *
 * External anchor sinks (file + HTTP witness), multi-source anchor
 * reconciliation (binding, truncation, fork), operator-held signed
 * checkpoints, durable federation anchor history, and recorded legal holds.
 *
 * Written before `src/anchors.ts` / `src/retention.ts` exist: the red run is
 * the proof the contract drives the implementation.
 */

import { test, describe } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, readFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { DatabaseSync } from 'node:sqlite';
import { generateKeyPairSync } from 'node:crypto';
import {
  EventLog,
  GENESIS_HASH,
  bundleFromEvents,
  eventHash,
  eventPublicKey,
  signEventBody,
  verifyBundle,
  type SecurityEvent,
} from '../src/events.ts';
import {
  FileAnchorSink,
  HttpAnchorSink,
  WitnessProtocolError,
  checkpointDigest,
  createCheckpoint,
  fetchWitnessHeads,
  parseAnchorLines,
  verifyAnchoredEvidence,
  verifyCheckpoint,
  witnessHeadsToAnchorContent,
  type AnchorPoint,
  type AnchorSink,
  type AnchorSinkStatus,
  type EvidenceCheckpoint,
} from '../src/anchors.ts';
import { RetentionLedger } from '../src/retention.ts';
import { AnchorRegistry } from '../src/rest-anchors.ts';
import { authorizationRoot } from '../src/pdp.ts';
import { buildWorld } from '../src/scenario.ts';

function tmpDir(name: string): string {
  return mkdtempSync(join(tmpdir(), `asl-h11-${name}-`));
}

function appendEvent(log: EventLog, note = '') {
  return log.append({
    tenantId: 'acme',
    principal: 'agent:one',
    actor: 'agent:one',
    actorKind: 'agent',
    action: 'read',
    result: 'success',
    ...(note ? { metadata: { note } } : {}),
  });
}

function anchorContent(events: readonly SecurityEvent[]): string {
  return events.map((e) => `${e.seq}:${e.eventHash}`).join('\n') + '\n';
}

/** Rebuild a chain as an attacker holding the signing key would: relink, rehash, re-sign. */
function rebuildChain(
  events: readonly SecurityEvent[],
  mutate?: { at: number; change: (e: SecurityEvent) => SecurityEvent },
): SecurityEvent[] {
  const out: SecurityEvent[] = [];
  events.forEach((e, i) => {
    const base = mutate && mutate.at === i ? mutate.change(e) : e;
    const partial: Omit<SecurityEvent, 'eventHash' | 'signature'> = {
      seq: out.length,
      timestamp: base.timestamp,
      tenantId: base.tenantId,
      principal: base.principal,
      actor: base.actor,
      actorKind: base.actorKind,
      action: base.action,
      resourceId: base.resourceId,
      decision: base.decision,
      denyReason: base.denyReason,
      policyId: base.policyId,
      capabilityId: base.capabilityId,
      result: base.result,
      metadata: base.metadata,
      previousEventHash: out.at(-1)?.eventHash ?? GENESIS_HASH,
    };
    out.push({ ...partial, eventHash: eventHash(partial), signature: signEventBody(partial) });
  });
  return out;
}

class RecordingSink implements AnchorSink {
  readonly name: string;
  readonly points: AnchorPoint[] = [];
  private readonly throwOnPublish: boolean;

  constructor(name: string, options: { throwOnPublish?: boolean } = {}) {
    this.name = name;
    this.throwOnPublish = options.throwOnPublish ?? false;
  }

  publish(point: AnchorPoint): void {
    if (this.throwOnPublish) throw new Error('sink exploded');
    this.points.push(point);
  }

  async flush(): Promise<void> {}

  status(): AnchorSinkStatus {
    return { name: this.name, published: this.points.length, failed: 0, dropped: 0, pending: 0 };
  }
}

describe('H11: anchor sinks', () => {
  test('self-contained (memory) worlds never inherit the environment witness sink', async () => {
    const originalUrl = process.env.EVENT_ANCHOR_WITNESS_URL;
    const originalFetch = globalThis.fetch;
    let calls = 0;
    process.env.EVENT_ANCHOR_WITNESS_URL = 'https://witness.invalid/heads';
    globalThis.fetch = (async () => {
      calls += 1;
      return new Response('ok', { status: 200 });
    }) as typeof globalThis.fetch;
    try {
      const world = buildWorld({ memory: true });
      await new Promise((resolve) => setTimeout(resolve, 5));
      world.eventLog.close();
    } finally {
      globalThis.fetch = originalFetch;
      if (originalUrl === undefined) delete process.env.EVENT_ANCHOR_WITNESS_URL;
      else process.env.EVENT_ANCHOR_WITNESS_URL = originalUrl;
    }
    assert.equal(calls, 0, 'a demo world must not publish fixture heads to the configured witness');
  });

  test('FileAnchorSink writes the M3 line format and counts publishes', () => {
    const dir = tmpDir('file-sink');
    try {
      const path = join(dir, 'evidence.anchor');
      const sink = new FileAnchorSink(path);
      sink.publish({ seq: 0, headHash: 'a'.repeat(64), eventCount: 1, at: 1 });
      sink.publish({ seq: 1, headHash: 'b'.repeat(64), eventCount: 2, at: 2 });
      assert.equal(readFileSync(path, 'utf8'), `0:${'a'.repeat(64)}\n1:${'b'.repeat(64)}\n`);
      const status = sink.status();
      assert.equal(status.published, 2);
      assert.equal(status.lastPublishedSeq, 1);
      assert.equal(status.pending, 0);
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });

  test('EventLog fans every append out to every configured sink', () => {
    const sinkA = new RecordingSink('a');
    const sinkB = new RecordingSink('b');
    const log = new EventLog(undefined, { sinks: [sinkA, sinkB] });
    const events = [appendEvent(log), appendEvent(log), appendEvent(log)];
    for (const sink of [sinkA, sinkB]) {
      assert.equal(sink.points.length, 3);
      sink.points.forEach((point, i) => {
        assert.equal(point.seq, i);
        assert.equal(point.eventCount, i + 1);
        assert.equal(point.headHash, events[i]!.eventHash);
        assert.equal(point.at, events[i]!.timestamp);
      });
    }
  });

  test('a throwing sink cannot break the append or starve the other sinks', () => {
    const bad = new RecordingSink('bad', { throwOnPublish: true });
    const good = new RecordingSink('good');
    const log = new EventLog(undefined, { sinks: [bad, good] });
    const event = appendEvent(log);
    assert.ok(event.eventHash);
    assert.equal(good.points.length, 1);
    assert.equal(good.points[0]!.headHash, event.eventHash);
  });

  test('HttpAnchorSink posts the documented payload and drains on flush', async () => {
    const calls: { url: string; init: { method?: string; headers?: Record<string, string>; body?: string } }[] = [];
    const fetchFn: typeof globalThis.fetch = async (url, init) => {
      calls.push({ url: String(url), init: (init ?? {}) as { method?: string; headers?: Record<string, string>; body?: string } });
      return new Response('{"ok":true}', { status: 200 });
    };
    const sink = new HttpAnchorSink({ url: 'https://witness.example.com/heads', fetchFn });
    sink.publish({ seq: 4, headHash: 'c'.repeat(64), eventCount: 5, at: 1700 });
    await sink.flush();
    assert.equal(calls.length, 1);
    assert.equal(calls[0]!.url, 'https://witness.example.com/heads');
    assert.equal(calls[0]!.init.method, 'POST');
    assert.equal(calls[0]!.init.headers?.['content-type'], 'application/json');
    assert.deepEqual(JSON.parse(calls[0]!.init.body!), {
      version: 1,
      kind: 'asl-anchor-head',
      seq: 4,
      headHash: 'c'.repeat(64),
      eventCount: 5,
      sentAt: 1700,
    });
    const status = sink.status();
    assert.equal(status.published, 1);
    assert.equal(status.pending, 0);
    assert.equal(status.lastPublishedSeq, 4);
  });

  test('the witness token is sent as a header and never appears in status or errors', async () => {
    const token = 'witness-token-CANARY-1234';
    const headers: Record<string, string>[] = [];
    const fetchFn: typeof globalThis.fetch = async (_url, init) => {
      headers.push((init?.headers ?? {}) as Record<string, string>);
      return new Response('nope', { status: 503 });
    };
    const sink = new HttpAnchorSink({ url: 'https://witness.example.com/heads', token, fetchFn });
    sink.publish({ seq: 0, headHash: 'd'.repeat(64), eventCount: 1, at: 1 });
    await sink.flush();
    assert.equal(headers[0]?.authorization, `Bearer ${token}`);
    assert.ok(!JSON.stringify(sink.status()).includes(token), 'status must not carry the token');
    assert.match(sink.status().lastError ?? '', /HTTP 503/);
    assert.ok(!(sink.status().lastError ?? '').includes(token));
  });

  test('a failing witness is loud but non-blocking: append succeeds, the point retries on the next publish', async () => {
    let fail = true;
    const fetchFn: typeof globalThis.fetch = async () => {
      if (fail) throw new TypeError('connect ECONNREFUSED');
      return new Response('ok', { status: 200 });
    };
    const sink = new HttpAnchorSink({ url: 'https://witness.example.com/heads', fetchFn });
    const log = new EventLog(undefined, { sinks: [sink] });
    const event = appendEvent(log); // must not throw even though the witness is down
    await sink.flush().catch(() => {});
    const down = sink.status();
    assert.equal(down.failed, 1);
    assert.equal(down.pending, 1);
    assert.ok(down.lastError);
    assert.ok(event.eventHash);

    fail = false;
    await sink.flush();
    const recovered = sink.status();
    assert.equal(recovered.published, 1);
    assert.equal(recovered.pending, 0);
    assert.equal(recovered.lastPublishedSeq, 0);
  });

  test('the bounded queue drops the oldest pending point and counts it', async () => {
    const fetchFn: typeof globalThis.fetch = async () => {
      throw new TypeError('offline');
    };
    const sink = new HttpAnchorSink({ url: 'https://witness.example.com/heads', fetchFn, queueLimit: 2 });
    for (let seq = 0; seq < 4; seq++) sink.publish({ seq, headHash: String(seq).repeat(64), eventCount: seq + 1, at: seq });
    await sink.flush().catch(() => {});
    const status = sink.status();
    assert.equal(status.pending, 2);
    assert.equal(status.dropped, 2);
  });

  test('flushAnchors() drains configured sinks through the store surface', async () => {
    let published = 0;
    const fetchFn: typeof globalThis.fetch = async () => {
      published += 1;
      return new Response('ok', { status: 200 });
    };
    const sink = new HttpAnchorSink({ url: 'https://witness.example.com/heads', fetchFn });
    const log = new EventLog(undefined, { sinks: [sink] });
    appendEvent(log);
    appendEvent(log);
    await log.flushAnchors();
    assert.equal(published, 2);
    assert.equal(sink.status().pending, 0);
  });
});

describe('H11: witness head protocol', () => {
  test('fetchWitnessHeads validates the response and returns the heads', async () => {
    const seen: { url: string; method?: string; authorization?: string }[] = [];
    const fetchFn: typeof globalThis.fetch = async (url, init) => {
      seen.push({
        url: String(url),
        method: init?.method,
        ...((init?.headers as Record<string, string> | undefined)?.authorization
          ? { authorization: (init?.headers as Record<string, string>).authorization }
          : {}),
      });
      return new Response(
        JSON.stringify({ version: 1, heads: [{ seq: 0, headHash: 'a'.repeat(64), receivedAt: 11 }] }),
        { status: 200 },
      );
    };
    const heads = await fetchWitnessHeads('https://witness.example.com/heads', { fetchFn, token: 'tok' });
    assert.deepEqual(heads, [{ seq: 0, headHash: 'a'.repeat(64), receivedAt: 11 }]);
    assert.equal(seen[0]!.method, 'GET');
    assert.equal(seen[0]!.authorization, 'Bearer tok');
  });

  test('a malformed witness response is refused and its body is never echoed', async () => {
    const canary = 'WITNESS-BODY-CANARY-42';
    const fetchFn: typeof globalThis.fetch = async () =>
      new Response(JSON.stringify({ version: 1, heads: [{ seq: -1, headHash: canary }] }), { status: 200 });
    await assert.rejects(
      fetchWitnessHeads('https://witness.example.com/heads', { fetchFn }),
      (error: unknown) => {
        assert.ok(error instanceof WitnessProtocolError);
        assert.ok(!error.message.includes(canary), 'the refusal must not echo the response body');
        return true;
      },
    );
  });

  test('a non-2xx witness response is refused', async () => {
    const fetchFn: typeof globalThis.fetch = async () => new Response('down', { status: 502 });
    await assert.rejects(
      fetchWitnessHeads('https://witness.example.com/heads', { fetchFn }),
      (error: unknown) => error instanceof WitnessProtocolError,
    );
  });

  test('witness heads convert to the M3 anchor line format', () => {
    const content = witnessHeadsToAnchorContent([
      { seq: 0, headHash: 'a'.repeat(64), receivedAt: 1 },
      { seq: 1, headHash: 'b'.repeat(64), receivedAt: 2 },
    ]);
    assert.equal(content, `0:${'a'.repeat(64)}\n1:${'b'.repeat(64)}\n`);
    const parsed = parseAnchorLines(content);
    assert.equal(parsed.errors.length, 0);
    assert.equal(parsed.lines.length, 2);
  });
});

describe('H11: anchor parsing and reconciliation', () => {
  test('parseAnchorLines parses M3 content and tolerates the trailing newline', () => {
    const parsed = parseAnchorLines(`0:${'a'.repeat(64)}\n1:${'b'.repeat(64)}\n`);
    assert.equal(parsed.errors.length, 0);
    assert.deepEqual(parsed.lines.map((l) => l.seq), [0, 1]);
    assert.equal(parsed.lines[1]!.line, 2);
  });

  test('parseAnchorLines reports a malformed line with its number', () => {
    const parsed = parseAnchorLines(`0:${'a'.repeat(64)}\nnot-a-line\n`);
    assert.equal(parsed.lines.length, 1);
    assert.equal(parsed.errors.length, 1);
    assert.match(parsed.errors[0]!, /line 2/);
  });

  test('verifyAnchoredEvidence binds the bundle head to an anchor source', () => {
    const log = new EventLog();
    const events = [appendEvent(log), appendEvent(log), appendEvent(log)];
    const result = verifyAnchoredEvidence(bundleFromEvents(events), {
      sources: [{ name: 'local', content: anchorContent(events) }],
      publicKey: eventPublicKey(),
    });
    assert.equal(result.valid, true, result.errors.join('; '));
    assert.equal(result.unanchored, false);
    assert.equal(result.sources[0]!.matchesBundleHead, true);
    assert.equal(result.sources[0]!.aheadOfBundle, false);
    assert.equal(result.sources[0]!.errors.length, 0);
  });

  test('a bundle with no source is reported unanchored, never silently anchored', () => {
    const log = new EventLog();
    const events = [appendEvent(log), appendEvent(log)];
    const result = verifyAnchoredEvidence(bundleFromEvents(events), { publicKey: eventPublicKey() });
    assert.equal(result.bundle.valid, true);
    assert.equal(result.unanchored, true);
    assert.equal(result.valid, true);
  });

  test('a source line that disagrees with the event at its seq fails the binding', () => {
    const log = new EventLog();
    const events = [appendEvent(log), appendEvent(log), appendEvent(log)];
    const lines = anchorContent(events).split('\n');
    lines[1] = `1:${'f'.repeat(64)}`; // still well-formed, wrong hash
    const result = verifyAnchoredEvidence(bundleFromEvents(events), {
      sources: [{ name: 'local', content: lines.join('\n') }],
      publicKey: eventPublicKey(),
    });
    assert.equal(result.valid, false);
    assert.match(result.sources[0]!.errors.join('; '), /seq 1/);
  });

  test('a source ahead of the bundle head reports tail truncation', () => {
    const log = new EventLog();
    const full = Array.from({ length: 8 }, () => appendEvent(log));
    const sliced = full.slice(0, 5);
    const result = verifyAnchoredEvidence(bundleFromEvents(sliced), {
      sources: [{ name: 'local', content: anchorContent(full) }],
      publicKey: eventPublicKey(),
    });
    assert.equal(result.valid, false);
    assert.equal(result.sources[0]!.aheadOfBundle, true);
    assert.match(result.errors.join('; '), /truncat/i);
  });

  test('a source with a deleted middle line reports a gap', () => {
    const log = new EventLog();
    const events = Array.from({ length: 5 }, () => appendEvent(log));
    const lines = events.map((e) => `${e.seq}:${e.eventHash}`);
    lines.splice(2, 1); // selective deletion: seq 2 vanishes
    const result = verifyAnchoredEvidence(bundleFromEvents(events), {
      sources: [{ name: 'local', content: lines.join('\n') + '\n' }],
      publicKey: eventPublicKey(),
    });
    assert.equal(result.valid, false);
    assert.match(result.sources[0]!.errors.join('; '), /gap|order/i);
  });

  test('two sources disagreeing at the same seq report a fork', () => {
    const log = new EventLog();
    const events = Array.from({ length: 4 }, () => appendEvent(log));
    const a = anchorContent(events).split('\n');
    const b = anchorContent(events).split('\n');
    b[2] = `2:${'e'.repeat(64)}`;
    const result = verifyAnchoredEvidence(bundleFromEvents(events), {
      sources: [
        { name: 'local', content: a.join('\n') },
        { name: 'witness', content: b.join('\n') },
      ],
      publicKey: eventPublicKey(),
    });
    assert.equal(result.valid, false);
    assert.equal(result.fork?.seq, 2);
    assert.deepEqual(result.fork?.hashes.map((h) => h.source).sort(), ['local', 'witness']);
  });

  test('a source that lags the bundle head leaves the tail unanchored and fails closed', () => {
    const log = new EventLog();
    const events = Array.from({ length: 6 }, () => appendEvent(log));
    const result = verifyAnchoredEvidence(bundleFromEvents(events), {
      sources: [{ name: 'witness', content: anchorContent(events.slice(0, 4)) }],
      publicKey: eventPublicKey(),
    });
    assert.equal(result.valid, false);
    assert.equal(result.sources[0]!.matchesBundleHead, false);
    assert.match(result.errors.join('; '), /unanchored/i);
  });

  test('timestamp regressions are reported as anomalies without flipping validity', () => {
    const log = new EventLog();
    const events = [100, 200, 150].map((timestamp) =>
      log.append({
        tenantId: 'acme',
        principal: 'agent:one',
        actor: 'agent:one',
        actorKind: 'agent',
        action: 'read',
        result: 'success',
        timestamp,
      }),
    );
    const result = verifyAnchoredEvidence(bundleFromEvents(events), {
      sources: [{ name: 'local', content: anchorContent(events) }],
      publicKey: eventPublicKey(),
    });
    assert.equal(result.bundle.valid, true, result.bundle.errors.join('; '));
    assert.equal(result.valid, true);
    assert.equal(result.bundle.timestampAnomalies.length, 1);
    assert.equal(result.bundle.timestampAnomalies[0]!.seq, 2);
    assert.equal(result.bundle.timestampAnomalies[0]!.previousSeq, 1);
  });
});

describe('H11: operator-held checkpoints', () => {
  test('createCheckpoint binds the chain head and verifies offline', () => {
    const log = new EventLog();
    const events = Array.from({ length: 5 }, () => appendEvent(log));
    const checkpoint = createCheckpoint(events, { now: 1234 });
    assert.equal(checkpoint.type, 'asl-anchor-checkpoint');
    assert.equal(checkpoint.seq, 4);
    assert.equal(checkpoint.headHash, events[4]!.eventHash);
    assert.equal(checkpoint.eventCount, 5);
    assert.equal(checkpoint.createdAt, 1234);
    assert.equal(checkpoint.previousCheckpointDigest, null);

    const verified = verifyCheckpoint(checkpoint, events, { publicKey: eventPublicKey() });
    assert.equal(verified.valid, true, verified.errors.join('; '));
    assert.match(checkpointDigest(checkpoint), /^[0-9a-f]{64}$/);
  });

  test('an empty chain cannot be checkpointed', () => {
    assert.throws(() => createCheckpoint([]), /empty/i);
  });

  test('a truncated chain is refused against the checkpoint', () => {
    const log = new EventLog();
    const events = Array.from({ length: 5 }, () => appendEvent(log));
    const checkpoint = createCheckpoint(events);
    const truncated = rebuildChain(events.slice(0, 3));
    const result = verifyCheckpoint(checkpoint, truncated, { publicKey: eventPublicKey() });
    assert.equal(result.valid, false);
    assert.match(result.errors.join('; '), /truncat/i);
  });

  test('a rewritten chain that is internally valid is still caught by the checkpoint', () => {
    const log = new EventLog();
    const events = Array.from({ length: 5 }, () => appendEvent(log));
    const checkpoint = createCheckpoint(events);
    // Host attacker WITH the signing key: rebuild the chain with an edited event.
    const rewritten = rebuildChain(events, {
      at: 1,
      change: (e) => ({ ...e, action: 'delete', metadata: { note: 'rewritten' } }),
    });
    // The rewritten chain verifies against itself — signatures are valid.
    const selfCheck = verifyBundle(bundleFromEvents(rewritten), { publicKey: eventPublicKey() });
    assert.equal(selfCheck.valid, true, 'rewritten chains are internally valid; that is the threat');
    // The checkpoint still catches it at the bound seq.
    const result = verifyCheckpoint(checkpoint, rewritten, { publicKey: eventPublicKey() });
    assert.equal(result.valid, false);
    assert.match(result.errors.join('; '), /seq 4|rewrit|does not match/i);
  });

  test('a tampered checkpoint or the wrong key is refused', () => {
    const log = new EventLog();
    const events = Array.from({ length: 3 }, () => appendEvent(log));
    const checkpoint = createCheckpoint(events);
    const tampered: EvidenceCheckpoint = { ...checkpoint, headHash: 'f'.repeat(64) };
    assert.equal(verifyCheckpoint(tampered, events, { publicKey: eventPublicKey() }).valid, false);

    const other = generateKeyPairSync('ed25519');
    const wrongKey = verifyCheckpoint(checkpoint, events, { publicKey: other.publicKey });
    assert.equal(wrongKey.valid, false);
    assert.match(wrongKey.errors.join('; '), /signature/i);
  });

  test('checkpoint chaining refuses a broken link and a same-seq fork', () => {
    const log = new EventLog();
    const events = Array.from({ length: 3 }, () => appendEvent(log));
    const first = createCheckpoint(events.slice(0, 2), { now: 1000 });
    const second = createCheckpoint(events, { previous: first, now: 2000 });
    assert.equal(verifyCheckpoint(second, events, { publicKey: eventPublicKey(), previous: first }).valid, true);

    // A correctly signed checkpoint that chains to a different predecessor.
    const other = createCheckpoint(events.slice(0, 2), { now: 9999 });
    const broken = createCheckpoint(events, { previous: other, now: 3000 });
    const brokenResult = verifyCheckpoint(broken, events, { publicKey: eventPublicKey(), previous: first });
    assert.equal(brokenResult.valid, false);
    assert.match(brokenResult.errors.join('; '), /chain|digest mismatch/i);

    // Same seq as the previous checkpoint but a different head: a signed fork.
    const forkedChain = rebuildChain(events, { at: 0, change: (e) => ({ ...e, metadata: { note: 'fork' } }) });
    const forked = createCheckpoint(forkedChain.slice(0, 2), { previous: first, now: 4000 });
    const forkResult = verifyCheckpoint(forked, forkedChain, { publicKey: eventPublicKey(), previous: first });
    assert.equal(forkResult.valid, false);
    assert.match(forkResult.errors.join('; '), /fork|same seq/i);
  });
});

describe('H11: federation anchor history is durable', () => {
  test('a restarted AnchorRegistry still knows the accepted head and flags a mismatch', () => {
    const log = new EventLog();
    const root = authorizationRoot('acme');
    const first = new AnchorRegistry(log);
    const headA = 'a'.repeat(64);
    const headB = 'b'.repeat(64);
    first.record(root, { tenant: 'acme', headHash: headA, eventCount: 1, anchoredAt: 1 });

    // Restart: a fresh registry over the same durable event log.
    const restarted = new AnchorRegistry(log);
    const honest = restarted.record(root, {
      tenant: 'acme',
      headHash: headB,
      eventCount: 2,
      previousHeadHash: headA,
      anchoredAt: 2,
    });
    assert.equal(honest.tamper, false, 'the accepted head survived the restart');
    const rolledBack = restarted.record(root, {
      tenant: 'acme',
      headHash: 'c'.repeat(64),
      eventCount: 3,
      previousHeadHash: 'd'.repeat(64),
      anchoredAt: 3,
    });
    assert.equal(rolledBack.tamper, true, 'a rolled-back client head is still flagged after restart');
  });
});

describe('H11: retention and legal holds', () => {
  test('a hold is recorded as signed evidence and covers the range', () => {
    const log = new EventLog();
    const ledger = new RetentionLedger(log);
    const root = authorizationRoot('acme');
    const hold = ledger.hold(root, { tenantId: 'acme', fromSeq: 2, toSeq: 4, reason: 'litigation hold 2026-10' });
    assert.equal(hold.tenantId, 'acme');
    assert.equal(ledger.isHeld('acme', 2), true);
    assert.equal(ledger.isHeld('acme', 4), true);
    assert.equal(ledger.isHeld('acme', 5), false);
    assert.equal(ledger.isHeld('globex', 3), false);

    const event = log.all().find((e) => e.seq === hold.eventSeq)!;
    assert.equal(event.action, 'evidence.hold');
    assert.ok(event.signature, 'the hold is signed evidence');
    assert.equal(event.metadata?.reason, 'litigation hold 2026-10');
    assert.equal(log.verify({ publicKey: eventPublicKey() }).valid, true);
  });

  test('release lifts only the named hold and is itself recorded', () => {
    const log = new EventLog();
    const ledger = new RetentionLedger(log);
    const root = authorizationRoot('acme');
    const holdA = ledger.hold(root, { tenantId: 'acme', fromSeq: 0, toSeq: 9, reason: 'hold A' });
    const holdB = ledger.hold(root, { tenantId: 'acme', fromSeq: 5, toSeq: 9, reason: 'hold B' });
    const released = ledger.release(root, { holdSeq: holdA.eventSeq, reason: 'matter closed' });
    assert.equal(released.eventSeq, holdA.eventSeq);
    assert.equal(ledger.isHeld('acme', 3), false, 'hold A is lifted');
    assert.equal(ledger.isHeld('acme', 6), true, 'hold B still covers the range');
    assert.ok(log.all().some((e) => e.action === 'evidence.release'));
    assert.throws(() => ledger.release(root, { holdSeq: holdA.eventSeq, reason: 'again' }), /not active|released/i);
    assert.throws(() => ledger.release(root, { holdSeq: 9999, reason: 'ghost' }), /unknown/i);
  });

  test('holds survive a rebuild from the event log', () => {
    const log = new EventLog();
    const root = authorizationRoot('acme');
    const ledger = new RetentionLedger(log);
    const hold = ledger.hold(root, { tenantId: 'acme', fromSeq: 1, toSeq: 3, reason: 'preserve' });

    const rebuilt = new RetentionLedger(log);
    assert.equal(rebuilt.isHeld('acme', 2), true);
    assert.equal(rebuilt.status().active, 1);
    assert.equal(rebuilt.activeHolds('acme')[0]!.eventSeq, hold.eventSeq);
  });

  test('a cross-tenant hold is refused and records nothing', () => {
    const log = new EventLog();
    const ledger = new RetentionLedger(log);
    const before = log.all().length;
    assert.throws(() => ledger.hold(authorizationRoot('acme'), { tenantId: 'globex', reason: 'nope' }), /tenant/i);
    assert.equal(log.all().length, before, 'a refused hold must not write evidence');
  });

  test('structural retention: no update/delete surface exists and a storage DELETE aborts', () => {
    const log = new EventLog();
    const proto = Object.getPrototypeOf(log) as Record<string, unknown>;
    for (const name of ['update', 'delete', 'remove', 'prune', 'purge']) {
      assert.equal(typeof proto[name], 'undefined', `${name}() must not exist`);
    }

    const dir = tmpDir('retention');
    try {
      const path = join(dir, 'evidence.db');
      const stored = new EventLog(path);
      const ledger = new RetentionLedger(stored);
      const hold = ledger.hold(authorizationRoot('acme'), { tenantId: 'acme', fromSeq: 0, toSeq: 0, reason: 'hold' });
      const db = new DatabaseSync(path);
      assert.throws(() => db.exec('DELETE FROM security_events WHERE seq = 0'), /append-only/);
      db.close();
      stored.close();

      const reopened = new EventLog(path);
      assert.equal(new RetentionLedger(reopened).isHeld('acme', 0), true);
      assert.ok(reopened.all().some((e) => e.seq === hold.eventSeq && e.action === 'evidence.hold'));
      reopened.close();
      rmSync(path, { force: true });
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });
});