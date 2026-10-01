/**
 * Session binding: capabilities and approvals bind to a specific session.
 * Ending or revoking a session invalidates its bound capabilities and approvals.
 *
 * M2 invariant: session revocation propagates within ≤ 5 seconds.
 */

import { randomUUID } from 'node:crypto';
import { type AuthContext, type Principal } from './domain.ts';
import { type Approval } from './policy.ts';
import { type Capability } from './capability.ts';
import { hasMfa } from './identity.ts';

export type SessionStatus = 'active' | 'revoked' | 'expired';

export interface Session {
  readonly id: string;
  readonly principal: Principal;
  readonly auth: AuthContext;
  readonly createdAt: number;
  readonly expiresAt: number;
  readonly mfaVerified: boolean;
  status: SessionStatus;
}

export interface SessionManagerConfig {
  /** Session lifetime in milliseconds. Default: 1 hour */
  readonly sessionLifetimeMs?: number;
  /** Clock function. Default: Date.now */
  readonly now?: () => number;
}

/**
 * Manages session lifecycle: creation, validation, revocation.
 * Sessions bind capabilities and approvals to an authenticated human.
 */
export class SessionManager {
  private readonly sessions = new Map<string, Session>();
  private readonly lifetimeMs: number;
  private readonly clock: () => number;

  constructor(config: SessionManagerConfig = {}) {
    this.lifetimeMs = config.sessionLifetimeMs ?? 3_600_000;
    this.clock = config.now ?? Date.now;
  }

  /**
   * Create a new session from an authenticated principal.
   * Requires MFA to have been verified at the IdP.
   */
  create(principal: Principal, auth: AuthContext): Session {
    if (!hasMfa(auth)) {
      throw new Error('session creation requires MFA verification at the IdP');
    }
    const now = this.clock();
    const session: Session = {
      id: randomUUID(),
      principal,
      auth,
      createdAt: now,
      expiresAt: now + this.lifetimeMs,
      mfaVerified: true,
      status: 'active',
    };
    this.sessions.set(session.id, session);
    return session;
  }

  /** Get a session by id. Returns undefined if not found or revoked/expired. */
  get(sessionId: string): Session | undefined {
    const s = this.sessions.get(sessionId);
    if (!s) return undefined;
    if (s.status !== 'active') return undefined;
    if (this.clock() >= s.expiresAt) {
      s.status = 'expired';
      return undefined;
    }
    return s;
  }

  /** Revoke a session. All bound capabilities and approvals become invalid. */
  revoke(sessionId: string): boolean {
    const s = this.sessions.get(sessionId);
    if (!s) return false;
    s.status = 'revoked';
    return true;
  }

  /** Check if a session is currently valid (active and not expired). */
  isValid(sessionId: string): boolean {
    return this.get(sessionId) !== undefined;
  }

  /** Get all active sessions for a principal. */
  activeSessionsFor(principalId: string): readonly Session[] {
    return [...this.sessions.values()].filter(
      (s) => s.principal.id === principalId && s.status === 'active' && this.clock() < s.expiresAt,
    );
  }

  /** Revoke all sessions for a principal (e.g., on offboarding). */
  revokeAllFor(principalId: string): number {
    let count = 0;
    for (const s of this.sessions.values()) {
      if (s.principal.id === principalId && s.status === 'active') {
        s.status = 'revoked';
        count++;
      }
    }
    return count;
  }

  /** All sessions, including revoked/expired — the incident reconstruction view. */
  all(): readonly Session[] {
    return [...this.sessions.values()];
  }

  /**
   * H13: revoke every active session for one tenant, optionally only those
   * created at or before `createdBefore` — the fence that lets a replayed
   * channel record avoid killing sessions created after the incident.
   */
  revokeAllForTenant(tenantId: string, createdBefore = Number.POSITIVE_INFINITY): number {
    let count = 0;
    for (const s of this.sessions.values()) {
      if (s.principal.tenantId !== tenantId) continue;
      if (s.status !== 'active') continue;
      if (s.createdAt > createdBefore) continue;
      s.status = 'revoked';
      count++;
    }
    return count;
  }

  /** H13: revoke every active session (global kill switch), timestamp-fenced. */
  revokeAll(createdBefore = Number.POSITIVE_INFINITY): number {
    let count = 0;
    for (const s of this.sessions.values()) {
      if (s.status !== 'active') continue;
      if (s.createdAt > createdBefore) continue;
      s.status = 'revoked';
      count++;
    }
    return count;
  }
}

/**
 * Bind an approval to a session. The approval is only valid while the session
 * is active. Returns a new Approval with the session binding.
 */
export function bindApproval(approval: Approval, session: Session): Approval {
  return {
    ...approval,
    id: `${approval.id}@session:${session.id}`,
  };
}

/**
 * Check if an approval is still valid given the session state.
 * Returns true if the approval's session is active and the approval has not expired.
 */
export function isApprovalValid(
  approval: Approval,
  sessionManager: SessionManager,
  now: number,
): boolean {
  if (approval.expiresAt <= now) return false;
  // Extract session id from the bound approval id pattern
  const match = approval.id.match(/@session:([a-f0-9-]+)$/);
  if (!match) return false; // unbound approval is not valid in M2
  const sessionId = match[1]!;
  const session = sessionManager.get(sessionId);
  return session !== undefined;
}

/**
 * Bind a capability to a session. The capability carries the session id in
 * its provenance, so revoking the session invalidates the capability.
 */
export function bindCapability(cap: Capability, session: Session): Capability {
  return {
    ...cap,
    provenance: {
      ...cap.provenance,
      sessionId: session.id,
    },
  };
}
