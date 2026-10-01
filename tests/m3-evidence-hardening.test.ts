/**
 * M3 — Evidence hardening.
 *
 * Per-event Ed25519 signatures, head-hash anchor file, offline verifier, and
 * append-only enforcement. Each test fails without its control.
 */

import { test, describe } from 'node:test';
import assert from 'node:assert/strict';
import { rmSync } from 'node:fs';
import { DatabaseSync } from 'node:sqlite';
import { createHash, generateKeyPairSync } from 'node:crypto';
import { EventLog, verifyBundle, eventPublicKey } from '../src/events.ts';

function tmp(name: string): string {
  return `${process.env.TEMP ?? '.'}\\ai-security-layer-m3-${name}-${Date.now()}-${Math.random().toString(36).slice(2)}.db`;
}

function appendEvent(log: EventLog, suffix = '') {
  return log.append({
    tenantId: 't',
    principal: 'p',
    actor: 'p',
    actorKind: 'agent',
    action: 'read',
    result: 'success',
    ...(suffix ? { metadata: { note: suffix } } : {}),
  });
}

describe('M3: per-event Ed25519 signatures', () => {
  test('every appended event carries a signature', () => {
    const log = new EventLog();
    const a = appendEvent(log);
    const b = appendEvent(log);
    assert.ok(a.signature, 'first event must have a signature');
    assert.ok(b.signature, 'second event must have a signature');
    assert.notEqual(a.signature, b.signature, 'signatures must differ across events');
  });

  test('tampering with an event field breaks the signature on verification', () => {
    const log = new EventLog();
    appendEvent(log);
    appendEvent(log, 'second');
    appendEvent(log, 'third');
    assert.equal(log.verify({ publicKey: eventPublicKey() }).valid, true);

    const mutable = log.all()[0] as { action: string };
    mutable.action = 'delete';

    const result = log.verify({ publicKey: eventPublicKey() });
    assert.equal(result.valid, false);
    assert.match(result.detail ?? '', /signature|hash/);
  });

  test('metadata with an explicit undefined value survives a persist/reload round trip', () => {
    const path = tmp('undefined-metadata');
    const log = new EventLog(path);
    log.append({
      tenantId: 't',
      principal: 'p',
      actor: 'p',
      actorKind: 'agent',
      action: 'secret.use',
      result: 'denied',
      metadata: { phase: 'secret-broker', label: 'model provider key', encrypted: true, value: undefined },
    });
    log.close();

    // The stored JSON drops `value`; the hash must be recomputable from it
    // (H13 live-Postgres finding: hashing the raw object broke chain reload).
    const reopened = new EventLog(path);
    assert.equal(reopened.verify({ publicKey: eventPublicKey() }).valid, true);
    reopened.close();
    rmSync(path, { force: true });
  });

  test('a signature produced by the wrong key is rejected by verify', () => {
    const path = tmp('wrong-key');
    const log = new EventLog(path);
    appendEvent(log);
    log.close();

    const db = new DatabaseSync(path);
    const row = db.prepare('SELECT event FROM security_events WHERE seq = 0').get() as { event: string };
    const parsed = JSON.parse(row.event) as { signature: string };
    parsed.signature = Buffer.alloc(64, 7).toString('base64');
    db.close();
    void parsed;

    const reopened = new EventLog(path);
    const fake = generateOtherKeyPair();
    const result = reopened.verify({ publicKey: fake.publicKey });
    assert.equal(result.valid, false);
    assert.match(result.detail ?? '', /signature|missing/);
    fake.cleanup();
    reopened.close();
    rmSync(path, { force: true });
  });

  test('EventLog has no update() or delete() methods (structural test)', () => {
    const log = new EventLog();
    const proto = Object.getPrototypeOf(log);
    assert.equal(typeof (proto as Record<string, unknown>).update, 'undefined', 'update() must not exist');
    assert.equal(typeof (proto as Record<string, unknown>).delete, 'undefined', 'delete() must not exist');
    assert.equal(typeof (proto as Record<string, unknown>).remove, 'undefined', 'remove() must not exist');
    assert.equal(typeof proto.append, 'function', 'append() must exist');
    assert.equal(typeof proto.verify, 'function', 'verify() must exist');
    assert.equal(typeof proto.bundle, 'function', 'bundle() must exist');
    assert.equal(typeof proto.anchor, 'function', 'anchor() must exist');
    assert.equal(typeof proto.close, 'function', 'close() must exist');
  });
});

describe('M3: head-hash anchor file', () => {
  test('each append writes one line to the anchor file', () => {
    const path = tmp('anchor');
    const anchorPath = path.replace('.db', '.anchor');
    const log = new EventLog(path, { anchorPath });
    appendEvent(log);
    appendEvent(log);
    appendEvent(log);
    log.close();

    const content = log.anchor();
    const lines = content.trim().split('\n');
    assert.equal(lines.length, 3);
    assert.match(lines[2]!, /^\d+:[0-9a-f]{64}$/);
    assert.ok(content.includes(':'));
    rmSync(path, { force: true });
    rmSync(anchorPath, { force: true });
  });

  test('anchor() returns empty string when no anchorPath was configured', () => {
    const log = new EventLog();
    appendEvent(log);
    assert.equal(log.anchor(), '');
  });
});

describe('M3: tail truncation detection', () => {
  test('a bundle missing the last event is detected by verifyBundle', () => {
    const log = new EventLog();
    appendEvent(log);
    appendEvent(log, 'two');
    appendEvent(log, 'three');
    appendEvent(log, 'four');
    const all = log.bundle();
    const parsed = JSON.parse(all) as { events: unknown[]; head: string };
    const truncated = JSON.stringify({ ...parsed, events: parsed.events.slice(0, -1) });
    const result = verifyBundle(truncated, { publicKey: eventPublicKey() });
    assert.equal(result.valid, false);
    assert.equal(result.eventCount, 3);
    assert.match(result.errors.join('|'), /previousEventHash|hash|signature|truncation/i);
  });

  test('a bundle whose head event has been removed still produces a valid chain for the truncated prefix', () => {
    const log = new EventLog();
    appendEvent(log);
    appendEvent(log, 'two');
    appendEvent(log, 'three');
    const all = log.bundle();
    const parsed = JSON.parse(all) as { events: Array<{ seq: number; eventHash: string }>; head: string };
    const truncatedEvents = parsed.events.slice(0, -1);
    const truncated = JSON.stringify({ ...parsed, head: truncatedEvents.at(-1)!.eventHash, events: truncatedEvents });
    const result = verifyBundle(truncated, { publicKey: eventPublicKey() });
    assert.equal(result.valid, true, `truncated bundle must still verify by itself; got: ${result.errors.join(' | ')}`);
    assert.equal(result.eventCount, 2);
  });
});

describe('M3: anchor reconciliation', () => {
  test('a bundle + matching anchor verifies; tampering the anchor is detected', () => {
    const path = tmp('reconcile');
    const anchorPath = path.replace('.db', '.anchor');
    const log = new EventLog(path, { anchorPath });
    appendEvent(log);
    appendEvent(log, 'two');
    appendEvent(log, 'three');
    const bundle = log.bundle();
    const anchor = log.anchor();
    log.close();

    const ok = verifyBundle(bundle, { anchorContent: anchor, publicKey: eventPublicKey() });
    assert.equal(ok.valid, true);
    assert.equal(ok.anchorMatch, true);

    const tamperedAnchor = anchor.split('\n').slice(0, -2).concat('9999:deadbeef\n').join('\n');
    const bad = verifyBundle(bundle, { anchorContent: tamperedAnchor, publicKey: eventPublicKey() });
    assert.equal(bad.anchorMatch, false);
    assert.equal(bad.valid, false);

    rmSync(path, { force: true });
    rmSync(anchorPath, { force: true });
  });
});

describe('M3: offline verifier (no database access)', () => {
  test('an exported bundle verifies offline against the public key', () => {
    const log = new EventLog();
    appendEvent(log);
    appendEvent(log, 'two');
    appendEvent(log, 'three');
    const bundle = log.bundle();

    const result = verifyBundle(bundle, { publicKey: eventPublicKey() });
    assert.equal(result.valid, true);
    assert.equal(result.eventCount, 3);
    assert.equal(result.signatureValid, true);
  });

  test('a tampered bundle fails offline verification without touching the database', () => {
    const log = new EventLog();
    appendEvent(log);
    appendEvent(log, 'two');
    const bundle = log.bundle();
    const parsed = JSON.parse(bundle) as { events: Array<{ action: string }> };
    parsed.events[0]!.action = 'delete';
    const tampered = JSON.stringify(parsed);

    const result = verifyBundle(tampered, { publicKey: eventPublicKey() });
    assert.equal(result.valid, false);
    assert.match(result.errors.join('|'), /hash|signature|previousEventHash/i);
  });

  test('a bundle with a forged signature is rejected', () => {
    const log = new EventLog();
    appendEvent(log);
    appendEvent(log, 'two');
    const bundle = log.bundle();
    const parsed = JSON.parse(bundle) as { events: Array<{ signature?: string }> };
    parsed.events[0]!.signature = Buffer.alloc(64, 9).toString('base64');
    const tampered = JSON.stringify(parsed);

    const result = verifyBundle(tampered, { publicKey: eventPublicKey() });
    assert.equal(result.valid, false);
    assert.equal(result.signatureValid, false);
  });
});

describe('M3: signature forgery resistance', () => {
  test('a forged event injected into the in-memory log breaks verify()', () => {
    const log = new EventLog();
    const good = appendEvent(log);
    appendEvent(log, 'second');
    assert.equal(log.verify({ publicKey: eventPublicKey() }).valid, true);

    const internal = (log as unknown as { events: Array<Record<string, unknown>> }).events;
    const forged = {
      ...good,
      action: 'delete',
      eventHash: createHash('sha256').update(`forged-${good.seq}`).digest('hex'),
      signature: Buffer.alloc(64, 1).toString('base64'),
    };
    internal.push(forged);

    const result = log.verify({ publicKey: eventPublicKey() });
    assert.equal(result.valid, false);
  });
});

function generateOtherKeyPair(): { publicKey: ReturnType<typeof eventPublicKey>; cleanup: () => void } {
  const kp = generateKeyPairSync('ed25519');
  return { publicKey: kp.publicKey, cleanup: () => {} };
}
