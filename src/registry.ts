/**
 * Resource registry and data ingestion.
 *
 * `IngestedData` is the in-memory representation of untrusted content: a
 * document, a web page, a repo file, an email, a tool result. It is DATA. It is
 * never consulted during authorization, and no function in this codebase turns
 * it into authority (see capability.ts — the only capability constructor).
 */

import { type Classification, type Resource, type ResourceType, classificationRank } from './domain.ts';

export class ResourceRegistry {
  private readonly resources = new Map<string, Resource>();

  add(resource: Resource): Resource {
    this.resources.set(resource.id, resource);
    return resource;
  }

  get(id: string): Resource | undefined {
    return this.resources.get(id);
  }

  require(id: string): Resource {
    const r = this.resources.get(id);
    if (!r) throw new UnknownResourceError(id);
    return r;
  }

  list(tenantId?: string): readonly Resource[] {
    const all = [...this.resources.values()];
    return tenantId ? all.filter((r) => r.tenantId === tenantId) : all;
  }

  /**
   * Raise-only classification update (M11 propagation). A derived label can
   * only ever increase sensitivity; unknown ids are never created — a write to
   * a resource the registry does not know cannot mint one.
   */
  raiseClassification(id: string, classification: Classification): Resource | undefined {
    const current = this.resources.get(id);
    if (!current) return undefined;
    if (classificationRank(classification) <= classificationRank(current.classification)) return current;
    const raised = { ...current, classification };
    this.resources.set(id, raised);
    return raised;
  }
}

export class UnknownResourceError extends Error {
  constructor(id: string) {
    super(`unknown resource: ${id}`);
    this.name = 'UnknownResourceError';
  }
}

export interface ResourceSpec {
  readonly id: string;
  readonly type: ResourceType;
  readonly tenantId: string;
  readonly classification: Classification;
  readonly attributes?: Readonly<Record<string, string | number | boolean>>;
}

export function defineResource(spec: ResourceSpec): Resource {
  return {
    id: spec.id,
    type: spec.type,
    tenantId: spec.tenantId,
    classification: spec.classification,
    attributes: spec.attributes ?? {},
  };
}

/**
 * Max label by classificationRank of current + sources. Unknown labels rank 100
 * and win. Propagation only raises; it never downgrades, and a derived label
 * feeds ceilings, never grants.
 */
export function propagateClassification(current: Classification, sources: readonly Classification[]): Classification {
  let best = current;
  for (const s of sources) {
    if (classificationRank(s) > classificationRank(best)) best = s;
  }
  return best;
}

export interface IngestedData {
  readonly resourceId: string;
  readonly source: string;
  readonly content: string;
  /** Data carries no authority. Kept explicit so it cannot be silently upgraded. */
  readonly authority: 'none';
  /** Present only when derivedFrom sources are given: the max label of this artifact and its sources. */
  readonly derivedClassification?: Classification;
}

export function ingestDocument(
  resource: Resource,
  content: string,
  source = resource.id,
  derivedFrom?: readonly Resource[],
): IngestedData {
  return {
    resourceId: resource.id,
    source,
    content,
    authority: 'none',
    ...(derivedFrom
      ? { derivedClassification: propagateClassification(resource.classification, derivedFrom.map((r) => r.classification)) }
      : {}),
  };
}

/**
 * Instruction-shaped content detector.
 *
 * NOT A SECURITY CONTROL. This exists for evidence and telemetry only: it
 * flags suspicious content so an investigator can see that an injection was
 * attempted. Authorization never reads its output. See DECISIONS.md ADR-011.
 */
const INJECTION_PATTERNS: readonly RegExp[] = [
  /ignore\s+(all\s+)?(previous|prior|above)\s+instructions/i,
  /disregard\s+(all\s+)?(previous|prior)\s+/i,
  /you\s+are\s+now\s+/i,
  /exfiltrat/i,
  /send\s+.{0,40}to\s+(https?:\/\/|[\w.-]+\.(com|net|io|ru))/i,
  /reveal\s+(the\s+)?(api\s+key|secret|token|password)/i,
  /grant\s+(yourself|me)\s+/i,
  /\bBEGIN\s+SYSTEM\b/i,
];

export function detectInjectionSignals(content: string): readonly string[] {
  return INJECTION_PATTERNS.filter((p) => p.test(content)).map((p) => p.source);
}
