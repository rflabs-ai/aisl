/**
 * H9 — secure artifact handling (ADR-041).
 *
 * Admission is where the decision happens: the bytes are sniffed, compared to
 * what the name claims, checked for executability, and run through the H7
 * egress mediator. A quarantined artifact is kept as evidence, never served.
 */

import { test, describe } from 'node:test';
import assert from 'node:assert/strict';
import { ArtifactStore, kindFromName, sniff } from '../src/artifacts.ts';
import { combine, taintFor } from '../src/taint.ts';

const text = (s: string) => new Uint8Array(Buffer.from(s, 'utf8'));
const ELF = new Uint8Array([0x7f, 0x45, 0x4c, 0x46, 0x02, 0x01, 0x01, 0x00]);
const PNG = new Uint8Array([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a, 0x00]);

const PUBLIC = combine(taintFor('artifact:src', 'public'));

describe('H9: content is sniffed, never trusted from the name', () => {
  test('magic bytes win over the extension', () => {
    assert.equal(sniff(ELF), 'elf');
    assert.equal(sniff(PNG), 'png');
    assert.equal(sniff(text('{"a":1}')), 'json');
    assert.equal(sniff(text('hello')), 'text');
    assert.equal(kindFromName('report.pdf'), 'pdf');
    assert.equal(kindFromName('noextension'), 'text');
  });

  test('an executable named .txt is quarantined and kept', () => {
    const store = new ArtifactStore();
    const a = store.admit({ id: 'a1', tenantId: 'acme', name: 'notes.txt', bytes: ELF, label: PUBLIC, ceiling: 'restricted' });
    assert.equal(a.status, 'quarantined');
    assert.equal(a.sniffedKind, 'elf');
    assert.match(a.reason ?? '', /executable content/);
    assert.deepEqual(store.released('acme'), []);
    assert.ok(store.get('acme', 'a1'), 'quarantined bytes are evidence, not deleted');
  });

  test('a content/extension mismatch is quarantined', () => {
    const store = new ArtifactStore();
    const a = store.admit({ id: 'a2', tenantId: 'acme', name: 'image.png', bytes: text('plain prose'), label: PUBLIC, ceiling: 'restricted' });
    assert.equal(a.status, 'quarantined');
    assert.match(a.reason ?? '', /named 'png', is 'text'/);
  });

  test('an honest artifact is released with a digest and provenance', () => {
    const store = new ArtifactStore();
    const label = combine(taintFor('doc:acme-merger', 'confidential'));
    const a = store.admit({ id: 'a3', tenantId: 'acme', name: 'summary.md', bytes: text('# summary'), label, ceiling: 'confidential' });
    assert.equal(a.status, 'released');
    assert.match(a.digest, /^[0-9a-f]{64}$/);
    assert.equal(a.classification, 'confidential');
    assert.deepEqual(a.provenance.sources, ['doc:acme-merger']);
  });
});

describe('H9: an artifact is an egress channel too', () => {
  const canary = { token: 'CANARY-phi-77aa11', classification: 'phi' as const };

  test('a canary inside an artifact quarantines it', () => {
    const store = new ArtifactStore();
    const a = store.admit({
      id: 'c1',
      tenantId: 'acme',
      name: 'notes.txt',
      bytes: text(`patient rows ${canary.token}`),
      label: PUBLIC,
      ceiling: 'restricted',
      canaries: [canary],
    });
    assert.equal(a.status, 'quarantined');
    assert.match(a.reason ?? '', /dlp: canary:phi/);
    assert.ok(!JSON.stringify(a).includes(canary.token), 'the record never echoes the value');
  });

  test('an artifact above the store ceiling is quarantined', () => {
    const store = new ArtifactStore();
    const a = store.admit({
      id: 'c2',
      tenantId: 'acme',
      name: 'rows.csv',
      bytes: text('patient_id\n0001'),
      label: combine(taintFor('db:acme-phi-synthetic', 'phi')),
      ceiling: 'internal',
    });
    assert.equal(a.status, 'quarantined');
    assert.match(a.reason ?? '', /dlp: payload:phi/);
  });
});

describe('H9: artifacts are tenant-bound', () => {
  test('a foreign tenant id reads as missing', () => {
    const store = new ArtifactStore();
    store.admit({ id: 'x1', tenantId: 'acme', name: 'a.txt', bytes: text('acme only'), label: PUBLIC, ceiling: 'restricted' });
    assert.ok(store.get('acme', 'x1'));
    assert.equal(store.get('globex', 'x1'), undefined);
    assert.deepEqual(store.list('globex'), []);
  });

  test('the same id in two tenants does not collide', () => {
    const store = new ArtifactStore();
    store.admit({ id: 'same', tenantId: 'acme', name: 'a.txt', bytes: text('acme'), label: PUBLIC, ceiling: 'restricted' });
    store.admit({ id: 'same', tenantId: 'globex', name: 'a.txt', bytes: text('globex'), label: PUBLIC, ceiling: 'restricted' });
    assert.notEqual(store.get('acme', 'same')!.digest, store.get('globex', 'same')!.digest);
  });
});
