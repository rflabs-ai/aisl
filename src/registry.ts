/**
 * Resource registry and data ingestion.
 *
 * `IngestedData` is the in-memory representation of untrusted content: a
 * document, a web page, a repo file, an email, a tool result. It is DATA. It is
 * never consulted during authorization, and no function in this codebase turns
 * it into authority (see capability.ts — the only capability constructor).
 */

import { type Classification, type Resource, type ResourceType } from './domain.ts';

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

export interface IngestedData {
  readonly resourceId: string;
  readonly source: string;
  readonly content: string;
  /** Data carries no authority. Kept explicit so it cannot be silently upgraded. */
  readonly authority: 'none';
}

export function ingestDocument(
  resource: Resource,
  content: string,
  source = resource.id,
): IngestedData {
  return { resourceId: resource.id, source, content, authority: 'none' };
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
