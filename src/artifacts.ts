/**
 * Artifact handling (H9, ADR-041).
 *
 * An artifact is bytes an agent produced or received: a file it wrote, an
 * upload, a model output saved to disk. All of it is untrusted until verified,
 * and the verification that matters is cheap and structural: what the bytes
 * actually are, against what the name claims they are.
 *
 * Three refusals, all at admission:
 *   - executable bytes are quarantined whatever the extension says;
 *   - a content/extension (or content/declared-type) mismatch is quarantined;
 *   - an artifact whose content trips the H7 egress mediator (above its label's
 *     ceiling, or carrying a canary) is quarantined.
 *
 * A quarantined artifact is kept, not deleted: the bytes are evidence.
 */

import { createHash } from 'node:crypto';
import { classificationRank, type Classification } from './domain.ts';
import { inspectEgress, type Canary } from './dlp.ts';
import type { TaintLabel } from './taint.ts';
import type { ProvenanceGraph, ProvenanceNode } from './provenance.ts';

export type ArtifactKind = 'text' | 'json' | 'png' | 'pdf' | 'zip' | 'elf' | 'pe' | 'unknown';

const EXECUTABLE: ReadonlySet<ArtifactKind> = new Set<ArtifactKind>(['elf', 'pe']);

/** Magic-byte sniff. Extension-independent by construction. */
export function sniff(bytes: Uint8Array): ArtifactKind {
  const at = (i: number): number => bytes[i] ?? -1;
  if (at(0) === 0x89 && at(1) === 0x50 && at(2) === 0x4e && at(3) === 0x47) return 'png';
  if (at(0) === 0x25 && at(1) === 0x50 && at(2) === 0x44 && at(3) === 0x46) return 'pdf';
  if (at(0) === 0x50 && at(1) === 0x4b && at(2) === 0x03 && at(3) === 0x04) return 'zip';
  if (at(0) === 0x7f && at(1) === 0x45 && at(2) === 0x4c && at(3) === 0x46) return 'elf';
  if (at(0) === 0x4d && at(1) === 0x5a) return 'pe';
  const head = Buffer.from(bytes.subarray(0, 64)).toString('utf8').trimStart();
  if (head.startsWith('{') || head.startsWith('[')) {
    try {
      JSON.parse(Buffer.from(bytes).toString('utf8'));
      return 'json';
    } catch {
      return 'text';
    }
  }
  return 'text';
}

/** What the name says, so a mismatch can be detected. */
export function kindFromName(name: string): ArtifactKind {
  const ext = name.toLowerCase().slice(name.lastIndexOf('.') + 1);
  if (ext === 'json') return 'json';
  if (ext === 'png') return 'png';
  if (ext === 'pdf') return 'pdf';
  if (ext === 'zip') return 'zip';
  if (ext === 'txt' || ext === 'md' || ext === 'csv' || ext === 'log') return 'text';
  if (['exe', 'dll', 'so', 'elf', 'bin'].includes(ext)) return 'pe';
  // No extension or an unknown one: nothing is claimed, so nothing mismatches.
  return name.includes('.') ? 'unknown' : 'text';
}

export type ArtifactStatus = 'released' | 'quarantined';

export interface Artifact {
  readonly id: string;
  readonly tenantId: string;
  readonly name: string;
  readonly digest: string;
  readonly size: number;
  readonly declaredKind: ArtifactKind;
  readonly sniffedKind: ArtifactKind;
  readonly classification: Classification;
  readonly provenance: TaintLabel;
  readonly status: ArtifactStatus;
  readonly reason?: string;
}

export interface ArtifactAdmission {
  readonly id: string;
  readonly tenantId: string;
  readonly name: string;
  readonly bytes: Uint8Array;
  readonly label: TaintLabel;
  /** Highest classification this artifact store holds for the tenant. */
  readonly ceiling: Classification;
  readonly canaries?: readonly Canary[];
  /** ADR-043: ids this artifact was derived from, already recorded in the graph. */
  readonly derivedFrom?: readonly string[];
}

export class ArtifactStore {
  private readonly artifacts = new Map<string, Artifact>();
  private readonly provenance: ProvenanceGraph | undefined;

  /** Lineage is optional so the store stays usable on its own (ADR-043). */
  constructor(provenance?: ProvenanceGraph) {
    this.provenance = provenance;
  }

  /** Admit or quarantine. Never throws: a hostile artifact is data, not an error. */
  admit(input: ArtifactAdmission): Artifact {
    const sniffed = sniff(input.bytes);
    const declared = kindFromName(input.name);
    const digest = createHash('sha256').update(input.bytes).digest('hex');

    const reasons: string[] = [];
    if (EXECUTABLE.has(sniffed)) reasons.push(`executable content (${sniffed})`);
    if (declared !== 'unknown' && declared !== sniffed) {
      reasons.push(`content/extension mismatch: named '${declared}', is '${sniffed}'`);
    }

    // H7's mediator, reused: an artifact is egress to disk.
    const dlp = inspectEgress({
      payload: Buffer.from(input.bytes).toString('utf8'),
      label: input.label,
      ceiling: input.ceiling,
      ...(input.canaries !== undefined ? { canaries: input.canaries } : {}),
    });
    if (!dlp.allow) reasons.push(`dlp: ${dlp.reason}`);

    const artifact: Artifact = {
      id: input.id,
      tenantId: input.tenantId,
      name: input.name,
      digest,
      size: input.bytes.length,
      declaredKind: declared,
      sniffedKind: sniffed,
      classification: input.label.classification,
      provenance: input.label,
      status: reasons.length > 0 ? 'quarantined' : 'released',
      ...(reasons.length > 0 ? { reason: reasons.join('; ') } : {}),
    };
    this.artifacts.set(this.key(input.tenantId, input.id), artifact);
    // Recorded even when quarantined: evidence needs the lineage of what arrived.
    this.provenance?.record({
      id: input.id,
      tenantId: input.tenantId,
      kind: 'artifact',
      parents: input.derivedFrom ?? [],
      classification: input.label.classification,
    });
    return artifact;
  }

  /** Tenant-bound read: a foreign id is indistinguishable from a missing one. */
  get(tenantId: string, id: string): Artifact | undefined {
    const artifact = this.artifacts.get(this.key(tenantId, id));
    return artifact?.tenantId === tenantId ? artifact : undefined;
  }

  /** Every ancestor of this artifact, nearest first (ADR-043). */
  lineageOf(tenantId: string, id: string): readonly ProvenanceNode[] {
    return this.provenance?.lineage(tenantId, id) ?? [];
  }

  list(tenantId: string): readonly Artifact[] {
    return [...this.artifacts.values()].filter((a) => a.tenantId === tenantId);
  }

  /** Only released artifacts may be handed out; quarantined ones stay as evidence. */
  released(tenantId: string): readonly Artifact[] {
    return this.list(tenantId).filter((a) => a.status === 'released');
  }

  private key(tenantId: string, id: string): string {
    return `${tenantId}\u0000${id}`;
  }
}

/** Classification ceiling helper for callers that only hold a label. */
export const exceedsCeiling = (label: TaintLabel, ceiling: Classification): boolean =>
  classificationRank(label.classification) > classificationRank(ceiling);
