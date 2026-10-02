/**
 * H15 (ADR-027): fail-closed availability primitives.
 *
 * `HealthState` observes what the decision path actually experiences (store
 * append, engine evaluation, clock read) and emits one loud signal per
 * transition - down and recovery - instead of one per denied decision.
 * `ClockGuard` makes the clock a checked dependency: a throw or non-finite
 * reading is always a fault; stall and backward-jump detection are enabled
 * only when a monotonic reference is injected, because deterministic test
 * clocks freeze and travel backward by design. Health details are short fixed
 * labels: the health surface never carries error messages, let alone secrets.
 */

export type HealthDependency = 'store' | 'engine' | 'clock';
export type DependencyStatus = 'ok' | 'unavailable';

export interface HealthSnapshot {
  readonly store: DependencyStatus;
  readonly engine: DependencyStatus;
  readonly clock: DependencyStatus;
}

export type HealthTransition = (dep: HealthDependency, status: DependencyStatus, detail?: string) => void;

function warnOnTransition(dep: HealthDependency, status: DependencyStatus, detail?: string): void {
  process.emitWarning?.(`health: ${dep} ${status}${detail !== undefined ? ` (${detail})` : ''}`);
}

/** Observed per-dependency health. Emits exactly once per change. */
export class HealthState {
  private readonly status: Record<HealthDependency, DependencyStatus> = {
    store: 'ok',
    engine: 'ok',
    clock: 'ok',
  };
  private readonly onTransition: HealthTransition;

  constructor(onTransition: HealthTransition = warnOnTransition) {
    this.onTransition = onTransition;
  }

  mark(dep: HealthDependency, status: DependencyStatus, detail?: string): void {
    if (this.status[dep] === status) return;
    this.status[dep] = status;
    this.onTransition(dep, status, detail);
  }

  snapshot(): HealthSnapshot {
    return { store: this.status.store, engine: this.status.engine, clock: this.status.clock };
  }
}

export type ClockRead = { readonly ok: true; readonly at: number } | { readonly ok: false; readonly detail: string };

export interface ClockGuardOptions {
  /** Monotonic ms source. Supplying it enables trend detection (stall, backward jump). */
  readonly monotonic?: () => number;
  /** A frozen wall clock is stalled once the monotonic reference advances this far. Default 5000 ms. */
  readonly stallAfterMs?: number;
}

/**
 * Lenient by default: a throw or non-finite reading is a fault. Trend
 * detection (backward jump, stalled wall clock) requires a monotonic
 * reference so deterministic test clocks keep working.
 */
export class ClockGuard {
  private readonly wall: () => number;
  private readonly monotonic?: () => number;
  private readonly stallAfterMs: number;
  private lastWall?: number;
  private lastMonotonic?: number;

  constructor(wall: () => number, options: ClockGuardOptions = {}) {
    this.wall = wall;
    this.monotonic = options.monotonic;
    this.stallAfterMs = options.stallAfterMs ?? 5_000;
  }

  read(): ClockRead {
    let at: number;
    try {
      at = this.wall();
    } catch {
      return { ok: false, detail: 'clock read threw' };
    }
    if (!Number.isFinite(at)) return { ok: false, detail: 'clock read returned a non-finite value' };

    if (!this.monotonic) {
      this.lastWall = at;
      return { ok: true, at };
    }

    let mono: number;
    try {
      mono = this.monotonic();
    } catch {
      return { ok: false, detail: 'clock monotonic reference threw' };
    }
    if (!Number.isFinite(mono)) return { ok: false, detail: 'clock monotonic reference is non-finite' };

    if (this.lastWall !== undefined && at < this.lastWall) {
      return { ok: false, detail: 'clock moved backward' };
    }
    if (
      this.lastWall !== undefined &&
      this.lastMonotonic !== undefined &&
      at === this.lastWall &&
      mono - this.lastMonotonic >= this.stallAfterMs
    ) {
      return { ok: false, detail: 'clock stalled' };
    }
    // Only an advancing wall clock resets the stall window.
    if (this.lastWall === undefined || at > this.lastWall) {
      this.lastWall = at;
      this.lastMonotonic = mono;
    }
    return { ok: true, at };
  }
}
