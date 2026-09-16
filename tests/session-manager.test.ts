/**
 * Session manager: lifecycle, binding, revocation.
 *
 * M2 invariant: session revocation propagates within ≤ 5 seconds.
 */

import { test, describe } from 'node:test';
import assert from 'node:assert/strict';
import { SessionManager, bindApproval, bindCapability, isApprovalValid } from '../src/session-manager.ts';
import { mockAuth, testWorld } from '../src/testing.ts';
import { type Approval } from '../src/policy.ts';
import { issueCapability } from '../src/capability.ts';

describe('session lifecycle', () => {
  test('creating a session requires MFA in the auth context', () => {
    const mgr = new SessionManager();
    const auth = mockAuth({ subject: 'user:sess-test', amr: ['pwd', 'mfa'] });
    const principal = { id: 'user:sess-test', kind: 'user' as const, tenantId: 'acme', roles: [], attributes: {}, auth };
    const session = mgr.create(principal, auth);
    assert.ok(session.id);
    assert.equal(session.mfaVerified, true);
    assert.equal(session.status, 'active');
  });

  test('creating a session without MFA throws', () => {
    const mgr = new SessionManager();
    const auth = mockAuth({ subject: 'user:no-mfa', amr: ['pwd'] }); // no MFA
    const principal = { id: 'user:no-mfa', kind: 'user' as const, tenantId: 'acme', roles: [], attributes: {}, auth };
    assert.throws(() => mgr.create(principal, auth), /MFA verification/);
  });

  test('a session expires after the configured lifetime', () => {
    let t = 1000;
    const mgr = new SessionManager({ sessionLifetimeMs: 60_000, now: () => t });
    const auth = mockAuth({ subject: 'user:expire-test', amr: ['pwd', 'mfa'] });
    const principal = { id: 'user:expire-test', kind: 'user' as const, tenantId: 'acme', roles: [], attributes: {}, auth };
    const session = mgr.create(principal, auth);
    assert.ok(mgr.isValid(session.id));

    t += 60_001; // past expiry
    assert.equal(mgr.isValid(session.id), false);
    assert.equal(mgr.get(session.id), undefined);
  });

  test('revoking a session invalidates it immediately', () => {
    const mgr = new SessionManager();
    const auth = mockAuth({ subject: 'user:revoke-test', amr: ['pwd', 'mfa'] });
    const principal = { id: 'user:revoke-test', kind: 'user' as const, tenantId: 'acme', roles: [], attributes: {}, auth };
    const session = mgr.create(principal, auth);
    assert.ok(mgr.isValid(session.id));

    const revoked = mgr.revoke(session.id);
    assert.equal(revoked, true);
    assert.equal(mgr.isValid(session.id), false);
    assert.equal(mgr.get(session.id), undefined);
  });

  test('revoking a nonexistent session returns false', () => {
    const mgr = new SessionManager();
    assert.equal(mgr.revoke('nonexistent-id'), false);
  });

  test('activeSessionsFor returns only active sessions for a principal', () => {
    const mgr = new SessionManager();
    const auth1 = mockAuth({ subject: 'user:multi', amr: ['pwd', 'mfa'] });
    const auth2 = mockAuth({ subject: 'user:multi', amr: ['pwd', 'mfa'] });
    const principal = { id: 'user:multi', kind: 'user' as const, tenantId: 'acme', roles: [], attributes: {}, auth: auth1 };
    mgr.create(principal, auth1);
    mgr.create(principal, auth2);
    assert.equal(mgr.activeSessionsFor('user:multi').length, 2);

    const sessions = mgr.activeSessionsFor('user:multi');
    mgr.revoke(sessions[0]!.id);
    assert.equal(mgr.activeSessionsFor('user:multi').length, 1);
  });

  test('revokeAllFor revokes all sessions for a principal', () => {
    const mgr = new SessionManager();
    const auth = mockAuth({ subject: 'user:bulk-revoke', amr: ['pwd', 'mfa'] });
    const principal = { id: 'user:bulk-revoke', kind: 'user' as const, tenantId: 'acme', roles: [], attributes: {}, auth };
    mgr.create(principal, auth);
    mgr.create(principal, auth);
    mgr.create(principal, auth);
    assert.equal(mgr.revokeAllFor('user:bulk-revoke'), 3);
    assert.equal(mgr.activeSessionsFor('user:bulk-revoke').length, 0);
  });
});

describe('approval binding', () => {
  test('bindApproval embeds the session id in the approval id', () => {
    const mgr = new SessionManager();
    const auth = mockAuth({ subject: 'user:bind', amr: ['pwd', 'mfa'] });
    const principal = { id: 'user:bind', kind: 'user' as const, tenantId: 'acme', roles: [], attributes: {}, auth };
    const session = mgr.create(principal, auth);

    const approval: Approval = {
      id: 'ap-1',
      approvedBy: 'user:bind',
      reviewerAuth: auth,
      principalId: 'agent:x',
      action: 'read',
      resourceId: 'doc:test',
      expiresAt: Date.now() + 60_000,
    };
    const bound = bindApproval(approval, session);
    assert.ok(bound.id.includes(`@session:${session.id}`));
  });

  test('isApprovalValid returns false for unbound approvals', () => {
    const mgr = new SessionManager();
    const auth = mockAuth({ subject: 'user:unbound', amr: ['pwd', 'mfa'] });
    const approval: Approval = {
      id: 'ap-unbound',
      approvedBy: 'user:unbound',
      reviewerAuth: auth,
      principalId: 'agent:x',
      action: 'read',
      resourceId: 'doc:test',
      expiresAt: Date.now() + 60_000,
    };
    assert.equal(isApprovalValid(approval, mgr, Date.now()), false);
  });

  test('isApprovalValid returns false when session is revoked', () => {
    const mgr = new SessionManager();
    const auth = mockAuth({ subject: 'user:revoke-approval', amr: ['pwd', 'mfa'] });
    const principal = { id: 'user:revoke-approval', kind: 'user' as const, tenantId: 'acme', roles: [], attributes: {}, auth };
    const session = mgr.create(principal, auth);

    const approval: Approval = {
      id: 'ap-revoke',
      approvedBy: 'user:revoke-approval',
      reviewerAuth: auth,
      principalId: 'agent:x',
      action: 'read',
      resourceId: 'doc:test',
      expiresAt: Date.now() + 60_000,
    };
    const bound = bindApproval(approval, session);
    assert.equal(isApprovalValid(bound, mgr, Date.now()), true);

    mgr.revoke(session.id);
    assert.equal(isApprovalValid(bound, mgr, Date.now()), false);
  });
});

describe('capability binding', () => {
  test('bindCapability adds sessionId to provenance', () => {
    const world = testWorld();
    const auth = mockAuth({ subject: 'user:cap-bind', amr: ['pwd', 'mfa'] });
    const principal = { id: 'user:cap-bind', kind: 'user' as const, tenantId: 'acme', roles: [], attributes: {}, auth };
    const mgr = new SessionManager();
    const session = mgr.create(principal, auth);

    const cap = world.authorization.issue(world.root, {
      subject: world.agent.id,
      tenantId: 'acme',
      resourceIds: [world.resources.repoA!],
      actions: ['read'],
      maxClassification: 'internal',
      expiresAt: world.clock.now() + 60_000,
      provenance: { source: 'session-bootstrap' },
    });
    const bound = bindCapability(cap, session);
    assert.equal(bound.provenance.sessionId, session.id);
  });
});
