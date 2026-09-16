# M4 — Authorization Lifecycle

Begin M4. Read PROJECT_CONTEXT.md, ARCHITECTURE.md, SECURITY_CLAIMS.md (Claims 1, 5, 6), DECISIONS.md (ADR-002), ROADMAP.md (M4), CURRENT_STATE.md, and AGENT-SESSION.md.

Goal: complete the authorization lifecycle — agents request capabilities, humans approve them, and grants can be revoked. Today capabilities are issued by code; there is no request-then-grant flow, and no way to revoke a capability that is already issued.

## 1. Capability request flow

An agent cannot mint its own authority (invariant 2). But it needs to ask for capabilities it doesn't have. Implement a `CapabilityRequest` type:

```typescript
interface CapabilityRequest {
  readonly id: string;
  readonly sessionId: string;
  readonly principalId: string;
  readonly tenantId: string;
  readonly requestedResources: readonly string[];
  readonly requestedActions: readonly Action[];
  readonly maxClassification: Classification;
  readonly justification: string;
  readonly createdAt: number;
  readonly status: 'pending' | 'approved' | 'denied' | 'expired';
  readonly reviewedBy?: string;
  readonly reviewedAt?: number;
  readonly capabilityId?: string; // set on approval
}
```

The request is stored and routed through the PDP. Only a user principal can approve. The approval produces a narrow, single-use capability scoped to exactly what was requested (or less — the reviewer can narrow scope).

## 2. Approval workflow

Extend the existing `Approval` type (`src/policy.ts`) with:
- `reviewerAuth`: the auth context of the reviewer (M2 already added this)
- `sessionId`: binding to the session that created the approval
- `capabilityRequestId`: link to the originating request

An approval that is not bound to a session (invariant: `isApprovalValid` returns false for unbound approvals — this test already exists) is invalid. An approval whose session has been revoked is invalid (this test also exists). The new work is wiring the request → approval → capability minting chain.

## 3. Capability revocation

The ROADMAP says "revoke a capability and have it take effect everywhere" with target propagation ≤ 5s (H13). Implement:

- A `RevokedCapability` record: `{ capabilityId: string, revokedAt: number, reason: string }`
- `AuthorizationService.revoke(capabilityId, reason)` — adds to a revocation set
- `AuthorizationService.isRevoked(capabilityId)` — checked inside `verifyCapability()`, before signature verification (a revoked cap is denied even if structurally valid)
- The revocation set is checked on every `authorize()` call, so propagation is immediate (in-process). In a multi-node deployment, revocations would need broadcast — document this as a known limitation.

## 4. Tests (must fail without the control)

- **Request → approval → capability minted:** agent requests, human approves, capability exists and works
- **Request denied:** agent requests, human denies, no capability minted
- **Request expired:** request times out, status becomes 'expired', no capability minted
- **Revoked capability is denied:** issue a capability, use it successfully, revoke it, use it again → denied
- **Revocation propagation is immediate:** within the same process, revocation takes effect on the next `authorize()` call
- **Scope narrowing:** reviewer approves for fewer resources than requested → capability reflects the narrower scope
- **Session revocation invalidates bound approvals:** revoke a session, the approvals bound to it become invalid (test may already exist — verify and extend)
- **Agent cannot approve its own request:** a principal of kind 'agent' cannot be the reviewer

### Structural invariant test

Add a test that enumerates the keys on a `CapabilityRequest` and asserts none carry authority (same pattern as invariant 4 for `ExecutionContext`). A capability request is intent, not authority.

## 5. Update SECURITY_CLAIMS.md

- Claim 5 (expired/consumed capabilities): add revocation as a third denial path
- Claim 6 (attenuation): note that revocation is checked before attenuation
- Add a new claim: "Revoked capabilities are denied immediately"

## 6. Update CURRENT_STATE.md

Move "Capability revocation" off the known-vulnerabilities list once tests prove it works. Add any new gaps introduced.

## Constraints

- Do not change PDP semantics, capability verification signature logic, or policy evaluation.
- Zero new runtime dependencies.
- Every new control needs a test that fails without it.
- The revocation set is in-process (same process as the PDP). Document that multi-node revocation requires broadcast (future work).
- Capability requests are evidence — they go in the event log.

## Acceptance

`npm test` green; 100% of the existing attack corpus still passes; revocation tests pass; request-approval-minting chain works end-to-end; `npm run demo` and `npm run benchmark` still produce evidence. Report what you skipped and why.
