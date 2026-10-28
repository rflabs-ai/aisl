/**
 * Content-level lineage (Stage 3 row: advanced provenance, ADR-043).
 *
 * The taint label (H4) says *how sensitive* a value is and which resources
 * influenced it, flattened into a set. That is enough to decide what may happen
 * next, and not enough to answer "where did this artifact come from" six steps
 * later. This is the graph behind the label: every derived node names its
 * parents, and lineage is the transitive closure.
 *
 * Deliberately strict, because a partial lineage graph is a lie:
 *   - a parent must already be recorded (no forward references, no dangling);
 *   - a parent must be in the same tenant (cross-tenant lineage would leak
 *     existence, which is the H8 failure mode);
 *   - a cycle is refused (a node cannot be its own ancestor);
 *   - depth is capped, because an unbounded chain is a bug, not a feature.
 */

import type { Classification } from './domain.ts';

export class ProvenanceError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'ProvenanceError';
  }
}

export type ProvenanceKind = 'resource' | 'chunk' | 'artifact' | 'derived';

export interface ProvenanceNode {
  readonly id: string;
  readonly tenantId: string;
  readonly kind: ProvenanceKind;
  /** Nodes this one was derived from. Empty for a root. */
  readonly parents: readonly string[];
  readonly classification: Classification;
}

const MAX_DEPTH = 32;

const canonicalParents = (parents: readonly string[]): string => [...parents].sort().join('\u0000');

export class ProvenanceGraph {
  private readonly nodes = new Map<string, ProvenanceNode>();

  record(node: ProvenanceNode): ProvenanceNode {
    const key = this.key(node.tenantId, node.id);
    if (node.parents.includes(node.id)) throw new ProvenanceError(`'${node.id}' cannot be its own parent`);

    for (const parentId of node.parents) {
      const parent = this.nodes.get(this.key(node.tenantId, parentId));
      if (parent === undefined) {
        throw new ProvenanceError(`unknown parent '${parentId}' for '${node.id}' (same tenant, recorded first)`);
      }
      // A cycle would make lineage infinite; the parent chain reaching the new
      // node means this edge closes a loop.
      if (this.reaches(node.tenantId, parentId, node.id)) {
        throw new ProvenanceError(`cycle: '${node.id}' is already an ancestor of '${parentId}'`);
      }
    }

    const existing = this.nodes.get(key);
    if (existing !== undefined) {
      // Idempotent only for the same shape: silently accepting a re-record with
      // different parents would let one node acquire two histories.
      if (canonicalParents(existing.parents) !== canonicalParents(node.parents)) {
        throw new ProvenanceError(`'${node.id}' is already recorded with different parents`);
      }
      return existing;
    }

    this.nodes.set(key, node);
    return node;
  }

  get(tenantId: string, id: string): ProvenanceNode | undefined {
    return this.nodes.get(this.key(tenantId, id));
  }

  /**
   * Every ancestor of `id`, nearest first, then by id. Deterministic so it can
   * be recorded in evidence and diffed.
   */
  lineage(tenantId: string, id: string): readonly ProvenanceNode[] {
    const start = this.nodes.get(this.key(tenantId, id));
    if (start === undefined) throw new ProvenanceError(`unknown node '${id}'`);

    const seen = new Set<string>([id]);
    const out: ProvenanceNode[] = [];
    let frontier: readonly ProvenanceNode[] = [start];

    for (let depth = 0; frontier.length > 0; depth++) {
      if (depth > MAX_DEPTH) throw new ProvenanceError(`lineage for '${id}' exceeds ${MAX_DEPTH} levels`);
      const next: ProvenanceNode[] = [];
      for (const node of [...frontier].sort((a, b) => a.id.localeCompare(b.id))) {
        for (const parentId of node.parents) {
          if (seen.has(parentId)) continue;
          const parent = this.nodes.get(this.key(tenantId, parentId));
          if (parent === undefined) throw new ProvenanceError(`dangling parent '${parentId}'`);
          seen.add(parentId);
          out.push(parent);
          next.push(parent);
        }
      }
      frontier = next;
    }
    return out;
  }

  /** Longest path to a root; cheap because the graph is a DAG by construction. */
  depth(tenantId: string, id: string): number {
    const node = this.nodes.get(this.key(tenantId, id));
    if (node === undefined) throw new ProvenanceError(`unknown node '${id}'`);
    if (node.parents.length === 0) return 0;
    return 1 + Math.max(...node.parents.map((p) => this.depth(tenantId, p)));
  }

  private reaches(tenantId: string, fromId: string, targetId: string): boolean {
    const stack = [fromId];
    const seen = new Set<string>();
    while (stack.length > 0) {
      const current = stack.pop()!;
      if (current === targetId) return true;
      if (seen.has(current)) continue;
      seen.add(current);
      const node = this.nodes.get(this.key(tenantId, current));
      if (node !== undefined) stack.push(...node.parents);
    }
    return false;
  }

  private key(tenantId: string, id: string): string {
    return `${tenantId}\u0000${id}`;
  }
}
