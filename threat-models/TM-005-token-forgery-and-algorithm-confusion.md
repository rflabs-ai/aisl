# TM-005 — Algorithm confusion and token forgery (M2)

## Scope

JWT/OIDC token verification at `IdentityProvider.verifyToken`
(`src/identity.ts:109`). Covers signature forgery, algorithm downgrade (notably
`alg: none` and HS256-with-public-key confusion), key confusion across
algorithms, and tampered claim fields.

## Adversary

Anyone able to present a JWT to the IdP boundary: a stolen-and-replayed token,
a token forged by a hostile IdP, a token whose header was modified after
signing, or an attacker who tricks the verifier into accepting a
symmetrically-signed token by reusing the RSA public key as an HMAC secret.

## Entry points

1. The Authorization header on any inbound principal-bearing request.
2. `IdentityProvider.verifyToken(jwt)` — the single chokepoint.
3. `IdentityProvider.authenticatedPrincipal()` — only path from a verified
   `AuthContext` to a `Principal`.

## Attack paths

| Path | Expected outcome |
| --- | --- |
| Forged signature | `verifyToken` returns `undefined`; principal is `unauthenticated-principal` |
| `alg: none` token | rejected — `jose` is configured with `algorithms: ['RS256', 'ES256']` |
| HS256 token signed with the RSA public key | rejected — algorithm not on the allowlist |
| Tampered payload (claims edited after signing) | rejected — signature does not match the canonical body |
| Expired token (`exp` in the past) | rejected — `clockTolerance` does not extend life |
| Wrong audience (`aud`) | rejected — `audience` claim enforced |
| Wrong issuer (`iss`) | rejected — `issuer` claim enforced |
| Revoked token id (`jti`) | rejected — `revokeToken()` + `isTokenRevoked()` |
| Token replay inside the expiry window | NOT detected — IdP's revocation is the control (see Known limitations) |

## Controls

- `jose.jwtVerify` with `algorithms: ['RS256', 'ES256']` whitelist
  (`src/identity.ts`); the algorithm allowlist is the defence against
  alg-confusion attacks.
- `issuer` and `audience` claim checks at verification time.
- `clockTolerance` is bounded so a backwards clock cannot extend token life
  materially (Claim 14, ADR-016).
- `IdentityProvider.revokeToken` + `isTokenRevoked` short-circuit before
  signature verification on subsequent attempts.
- `IdentityProvider.authenticatedPrincipal` is the only producer of an
  authenticated `Principal`; the field exists on `Principal.auth`, not on
  client-supplied request fields (the defect bar in SECURITY_PRINCIPLES.md).

## Assumptions

- The IdP's signing keys are kept secret and rotated on a published schedule.
- The JWKS endpoint is reachable from the runtime.
- The IdP correctly populates `exp`, `iss`, `aud`, and (where required) `amr`.

## Failure modes

- A leaked IdP private key permits token forgery indistinguishable from a
  legitimate token. KMS/HSM custody of the IdP signing key is HARD-stage
  (ADR-013 migration path).
- A malicious or compromised IdP can mint tokens that verify successfully.
  The runtime cannot distinguish stolen-but-valid from legitimate.
- Replay within the expiry window is not detected by the runtime; the IdP's
  revocation channel and short token lifetimes are the control.
- A JWKS endpoint that returns attacker-controlled keys is not currently
  pinned to a single source of truth — the first fetched JWKS is trusted
  until the next refresh.

## Test methodology

- `tests/invariants.test.ts` invariant 14 (token forgery suite, M2): tampered
  signature, expired token, wrong audience, wrong algorithm.
- `tests/invariants.test.ts` IdP-revocation case.
- `tests/invariants.test.ts` IdP-health and circuit-breaker case.

## Residual risk

- IdP compromise — a token signed by a leaked IdP key verifies correctly.
  Closing this requires HSM/TPM-backed IdP key custody and signed-key
  bundles (HARD stage).
- Replay within the expiry window — the IdP's token lifetime and revocation
  channel are the control.
- JWKS source pinning — the runtime trusts whatever the JWKS endpoint serves.
  Adding a pinned key set (out-of-band distribution + first-fetch policy) is
  HARD-stage.
