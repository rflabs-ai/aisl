/**
 * Advanced provenance (ADR-043).
 *
 * Lineage is only worth having if it is complete, acyclic, and tenant-bound.
 * Each of those is a refusal here rather than a convention.
 */

import { test, describe } from 'node:test';
import assert from 'node:assert/strict';
import { ProvenanceGraph, ProvenanceError } from '../src/provenance.ts';
import { ArtifactStore } from '../src/artifacts.ts';
import { taintFor } from '../src/taint.ts';

const g = () => new ProvenanceGraph();

describe('provenance: lineage is the transitive closure, in a stable order', () => {
  test('a two-step chain reports nearest first', () => {
    const graph = g();
    graph.record({ id: 'doc', tenantId: 'acme', kind: 'resource', parents: [], classification: 'confidential' });
    graph.record({ id: 'chunk', tenantId: 'acme', kind: 'chunk', parents: ['doc'], classification: 'confidential' });
    graph.record({ id: 'summary', tenantId: 'acme', kind: 'artifact', parents: ['chunk'], classification: 'confidential' });

    assert.deepEqual(graph.lineage('acme', 'summary').map((n) => n.id), ['chunk', 'doc']);
    assert.equal(graph.depth('acme', 'summary'), 2);
  });

  test('a diamond reports each ancestor once', () => {
    const graph = g();
    graph.record({ id: 'a', tenantId: 'acme', kind: 'resource', parents: [], classification: 'internal' });
    graph.record({ id: 'b', tenantId: 'acme', kind: 'chunk', parents: ['a'], classification: 'internal' });
    graph.record({ id: 'c', tenantId: 'acme', kind: 'chunk', parents: ['a'], classification: 'internal' });
    graph.record({ id: 'd', tenantId: 'acme', kind: 'artifact', parents: ['b', 'c'], classification: 'internal' });

    assert.deepEqual(graph.lineage('acme', 'd').map((n) => n.id), ['b', 'c', 'a']);
  });

  test('recording is idempotent', () => {
    const graph = g();
    const node = { id: 'x', tenantId: 'acme', kind: 'resource' as const, parents: [], classification: 'public' as const };
    graph.record(node);
    graph.record(node);
    assert.equal(graph.lineage('acme', 'x').length, 0);
  });
});

describe('provenance: the graph refuses to be a lie', () => {
  test('an unknown parent is refused', () => {
    const graph = g();
    assert.throws(
      () => graph.record({ id: 'b', tenantId: 'acme', kind: 'chunk', parents: ['missing'], classification: 'public' }),
      /unknown parent 'missing'/,
    );
  });

  test('a cycle is refused', () => {
    const graph = g();
    graph.record({ id: 'a', tenantId: 'acme', kind: 'resource', parents: [], classification: 'public' });
    graph.record({ id: 'b', tenantId: 'acme', kind: 'chunk', parents: ['a'], classification: 'public' });
    assert.throws(
      () => graph.record({ id: 'a', tenantId: 'acme', kind: 'resource', parents: ['b'], classification: 'public' }),
      /cycle/,
    );
  });

  test('a node cannot be its own parent', () => {
    const graph = g();
    assert.throws(
      () => graph.record({ id: 'a', tenantId: 'acme', kind: 'resource', parents: ['a'], classification: 'public' }),
      /its own parent/,
    );
  });

  test('a parent in another tenant is unusable (it reads as unknown)', () => {
    const graph = g();
    graph.record({ id: 'a', tenantId: 'globex', kind: 'resource', parents: [], classification: 'public' });
    assert.throws(
      () => graph.record({ id: 'b', tenantId: 'acme', kind: 'chunk', parents: ['a'], classification: 'public' }),
      ProvenanceError,
    );
  });
});

describe('provenance: artifacts record lineage at admission', () => {
  test('an admitted artifact carries its sources', () => {
    const graph = g();
    const store = new ArtifactStore(graph);
    graph.record({ id: 'doc:acme-merger', tenantId: 'acme', kind: 'resource', parents: [], classification: 'confidential' });

    store.admit({
      id: 'art-1',
      tenantId: 'acme',
      name: 'summary.md',
      bytes: new Uint8Array(Buffer.from('# summary', 'utf8')),
      label: taintFor('doc:acme-merger', 'confidential'),
      ceiling: 'confidential',
      derivedFrom: ['doc:acme-merger'],
    });

    assert.deepEqual(graph.lineage('acme', 'art-1').map((n) => n.id), ['doc:acme-merger']);
    assert.equal(store.lineageOf('acme', 'art-1').length, 1);
  });

  test('a quarantined artifact still records lineage — evidence needs it', () => {
    const graph = g();
    const store = new ArtifactStore(graph);
    graph.record({ id: 'doc:x', tenantId: 'acme', kind: 'resource', parents: [], classification: 'internal' });

    const a = store.admit({
      id: 'art-2',
      tenantId: 'acme',
      name: 'notes.txt',
      bytes: new Uint8Array([0x7f, 0x45, 0x4c, 0x46, 0x02, 0x01, 0x01, 0x00]),
      label: taintFor('doc:x', 'internal'),
      ceiling: 'internal',
      derivedFrom: ['doc:x'],
    });

    assert.equal(a.status, 'quarantined');
    assert.deepEqual(graph.lineage('acme', 'art-2').map((n) => n.id), ['doc:x']);
  });
});
