/**
 * Structured telemetry: observability, never a control.
 *
 * Doctrine: the PDP never reads telemetry and no authorization or enforcement
 * path depends on it — a broken or absent sink degrades visibility, never the
 * run. Emission failures are swallowed and counted, never thrown into the
 * caller. Attributes carry ids, counts, and durations only: no task text, no
 * model text, no canaries, no secrets — the same discipline as the event log.
 */

export interface TelemetryPort {
  emit(name: string, attrs: Readonly<Record<string, unknown>>): void;
}

export class JsonlTelemetry implements TelemetryPort {
  #dropped = 0;
  private readonly out: (line: string) => void;

  /** out defaults to writing one JSON object per line to stdout. */
  constructor(out: (line: string) => void = (l) => process.stdout.write(l + '\n')) {
    this.out = out;
  }

  /** Public count of emission failures swallowed so the run never breaks. */
  get dropped(): number {
    return this.#dropped;
  }

  emit(name: string, attrs: Readonly<Record<string, unknown>>): void {
    try {
      this.out(JSON.stringify({ ts: Date.now(), name, ...attrs }));
    } catch {
      this.#dropped++;
    }
  }
}

/** Counts deny reasons from a session's step records. Pure function over inputs. */
export function denyReasonCounts(
  decisions: readonly { readonly decision: string; readonly denyReason?: string }[],
): Record<string, number> {
  const counts: Record<string, number> = {};
  for (const d of decisions) {
    if (d.decision === 'deny' && d.denyReason !== undefined) {
      counts[d.denyReason] = (counts[d.denyReason] ?? 0) + 1;
    }
  }
  return counts;
}
