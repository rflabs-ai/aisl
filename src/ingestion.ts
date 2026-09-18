/**
 * Stage-0 document ingestion (ADR-020).
 *
 * Chunking is deterministic (fixed size with boundary awareness, no model in
 * the loop); chunk ids are `doc/<documentId>/chunk/<n>`; every chunk is a
 * registry resource labeled with the source document's id as `derivedFrom`;
 * labels flow through the M11 machinery — `propagateClassification` for the
 * derived label, `raiseClassification` for re-ingest — so a chunk label can
 * only RAISE. Ingestion is an event: one `document.ingest` per chunk, content
 * sealed with `sealFor` (one key per tenant + classification), never
 * plaintext. Nothing here holds or mints authority (invariant 3): the
 * constructor surface is registry + event log + an actor attribution.
 */

import { createHash } from 'node:crypto';
import { type Classification, type PrincipalKind, type Resource } from './domain.ts';
import { propagateClassification } from './registry.ts';
import { type ResourceRegistry } from './registry.ts';
import { type EventStore } from './events.ts';
import { sealFor } from './seal.ts';

export interface ChunkOptions {
  /** Target chunk size in characters. Default 2000. */
  readonly chunkSize?: number;
}

const DEFAULT_CHUNK_SIZE = 2000;

/**
 * Deterministic chunker: fixed-size windows that prefer the last paragraph
 * break ("\\n\\n"), then any line break, then a space, inside the window; a
 * hard cut only when no boundary fits (a single token longer than the window).
 * Pure function — same input, same chunks, byte-for-byte.
 */
export function chunkContent(content: string, chunkSize: number = DEFAULT_CHUNK_SIZE): string[] {
  if (!Number.isInteger(chunkSize) || chunkSize < 1) throw new Error('chunkSize must be a positive integer');
  const chunks: string[] = [];
  let rest = content;
  while (rest.length > chunkSize) {
    const window = rest.slice(0, chunkSize);
    const boundary = Math.max(
      window.lastIndexOf('\n\n') + 1,
      window.lastIndexOf('\n') + 1,
      window.lastIndexOf(' ') + 1,
    );
    const cut = boundary > 0 ? boundary : chunkSize;
    chunks.push(rest.slice(0, cut));
    rest = rest.slice(cut);
  }
  chunks.push(rest);
  return chunks;
}

export interface IngestResult {
  readonly chunks: readonly Resource[];
  /** Chunk id -> content, for the embedder's content map (never placed in events). */
  readonly content: ReadonlyMap<string, string>;
}

export interface DocumentIngesterDeps {
  readonly registry: ResourceRegistry;
  readonly eventLog: EventStore;
  /** Attribution only — the actor id/kind recorded on document.ingest events. */
  readonly actorId: string;
  readonly actorKind: PrincipalKind;
}

export class DocumentIngester {
  private readonly deps: DocumentIngesterDeps;

  constructor(deps: DocumentIngesterDeps) {
    this.deps = deps;
  }

  /**
   * Chunk + label + register + audit one document. Re-ingesting the same
   * document reuses the same chunk ids and can only raise their labels.
   * `derivedFrom` carries additional label sources (M11 propagation) — the
   * document itself is always the first source.
   */
  ingest(input: {
    readonly document: Resource;
    readonly content: string;
    readonly chunkSize?: number;
    readonly derivedFrom?: readonly Resource[];
  }): IngestResult {
    const chunkSize = input.chunkSize ?? DEFAULT_CHUNK_SIZE;
    const sources = [input.document, ...(input.derivedFrom ?? [])];
    const classification = propagateClassification(
      input.document.classification,
      sources.map((r) => r.classification),
    );

    const parts = chunkContent(input.content, chunkSize);
    const chunks: Resource[] = [];
    const content = new Map<string, string>();

    for (let i = 0; i < parts.length; i++) {
      const id = `doc/${input.document.id}/chunk/${i}`;
      const existing = this.deps.registry.get(id);
      if (existing) {
        this.deps.registry.raiseClassification(id, classification);
      } else {
        this.deps.registry.add({
          id,
          type: 'document',
          tenantId: input.document.tenantId,
          classification,
          attributes: { derivedFrom: input.document.id, chunk: `${i}/${parts.length}` },
        });
      }
      const chunkContent = parts[i]!;
      content.set(id, chunkContent);
      chunks.push(this.deps.registry.require(id));

      this.deps.eventLog.append({
        tenantId: input.document.tenantId,
        principal: this.deps.actorId,
        actor: this.deps.actorId,
        actorKind: this.deps.actorKind,
        action: 'document.ingest',
        resourceId: id,
        decision: 'allow',
        result: 'success',
        metadata: {
          phase: 'ingestion',
          documentId: input.document.id,
          chunkIndex: i,
          chunkCount: parts.length,
          chars: chunkContent.length,
          contentDigest: createHash('sha256').update(chunkContent).digest('hex'),
          derivedClassification: classification,
          sealed: sealFor(input.document.tenantId, chunkContent, classification),
        },
      });
    }

    return { chunks, content };
  }
}
