# AuthorizationService is 1,036 lines and the most-churned file in src

Status: open
Source: code-health snapshot 2026-11-13, score model v2.
Repo: `ai-security-layer`.

## Evidence

`src/pdp.ts` is 1,036 lines and 39 functions, with 19 commits in 12 months,
the highest churn in `src/`. Max CCN 18, max cognitive 39, two functions with
more than five parameters. Per-file score 6.22, so badness times churn puts it
just behind `cli.ts`.

One class holds issuance, role issuance, revocation, incident freeze state,
authorization, evidence reveal, and audit query. Those are six responsibilities
behind one constructor, and every one of them is a security-relevant path.

## Action

Extract, without changing a branch condition:

- `src/pdp/issue.ts` - `issue`, `issueForRole`, attenuation checks
- `src/pdp/revocation.ts` - `revoke`, `isRevoked`, `revokeAll`, broadcast sync
- `src/pdp/freeze.ts` - `freeze`, `unfreeze`, `applyIncidentRecord`
- `src/pdp/authorize.ts` - `authorize`, `queryAudit`, `revealEvidence`

`AuthorizationService` keeps the constructor and delegates. This is a move and
a delegate, not a redesign; the decision logic must not change in the same
commit.

## Acceptance

- All 13 invariants, the H8 probe matrix, and the authorization-lifecycle
  suite are green.
- A review of the diff shows no changed condition, ordering, or default.
- No new public export on the world surface; `AuthorizationService` remains the
  only entry point callers use.
- A `src/pdp/*` file over 400 lines is a review flag.
