# TM-005 — Algorithm confusion and token forgery (M2)

## Scope

JWT/OIDC token verification at `IdentityProvider.verifyToken`
(`src/identity.ts:292`). Covers signature forgery, algorithm downgrade (notably
`alg: none` and HS256-with-public-key confusion), key confusion across
algorithms, tampered claim fields, long-lived or unrevocable credentials, and
clock-skew-extended lifetimes.

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
| Revoked token id (`jti`) | rejected — `revokeToken()` + `isTokenRevoked()`; H2 propagates `revoke-token` records across nodes (ADR-028) |
| Token with no `exp`/`iat`/`jti`/`sub` | rejected — H2 admission contract; the same fail-closed result as a bad signature |
| Long-lived token (`exp - iat` > the ceiling) | rejected — H2 lifetime ceiling (default 1 h, configured cap 24 h) |
| Future-issued token (clock skew) | rejected beyond the bounded tolerance (default 30 s, hard cap 60 s) |
| Expired token inside the bounded tolerance | accepted for at most the tolerance — already-expired tokens are not a separate credential class |
| Token replay inside the expiry window | NOT detected — the token's short lifetime and `jti` revocation are the control (H2, Claim 37) |

## Controls

- `jose.jwtVerify` with `algorithms: ['RS256', 'ES256']` whitelist
  (`src/identity.ts`); the algorithm allowlist is the defence against
  alg-confusion attacks.
- `issuer` and `audience` claim checks at verification time.
- H2 (ADR-028) admission contract: `sub`/`exp`/`iat`/`jti` required; the
  declared lifetime within the ceiling; a bounded clock tolerance actually
  wired into jose (`clockTolerance`) so a backwards or skewed clock cannot
  extend token life beyond the tolerance.
- `IdentityProvider.revokeToken` + `isTokenRevoked` reject revoked `jti`s;
  `attachRevocationFeed` consumes H13 `revoke-token` channel records so a
  revocation crosses nodes within the poll interval.
- `IdentityProvider.authenticatedPrincipal` is the only producer of an
  authenticated `Principal`; the field exists on `Principal.auth`, not on
  client-supplied request fields (the defect bar in SECURITY_PRINCIPLES.md).

## Assumptions

- The IdP's signing keys are kept secret and rotated on a published schedule.
- The JWKS endpoint is reachable from the runtime.
- The IdP correctly populates `sub`, `iss`, `aud`, `exp`, `iat`, `jti`, and
  (where required) `amr`, and issues short-lived tokens (RFC 9068 requires the
  first six for JWT access tokens); NTP with authentication keeps clocks aligned.

## Failure modes

- A leaked IdP private key permits token forgery indistinguishable from a
  legitimate token. KMS/HSM custody of the IdP signing key is HARD-stage
  (ADR-013 migration path).
- A malicious or compromised IdP can mint tokens that verify successfully.
  The runtime cannot distinguish stolen-but-valid from legitimate.
- Replay within the (now bounded) expiry window is not detected by the
  runtime; the short H2 lifetime ceiling and `jti` revocation are the control.
  Propagation is poll-bounded, so a channel outage widens the window.
- A JWKS endpoint that returns attacker-controlled keys is not currently
  pinned to a single source of truth — the first fetched JWKS is trusted
  until the next refresh.

## Test methodology

- `tests/invariants.test.ts` invariant 14 (token forgery suite, M2): tampered
  signature, expired token, wrong audience, wrong algorithm.
- `tests/invariants.test.ts` IdP-revocation case.
- `tests/invariants.test.ts` IdP-health and circuit-breaker case.
- `tests/h2-short-lived-credentials.test.ts` (H2): admission contract plus a
  deterministic 2 000-case expiry fuzz, the clock-tolerance regression,
  workload derivation bounds, cross-node `revoke-token` propagation, and
  credential-in-log scanning.

## Residual risk

- IdP compromise — a token signed by a leaked IdP key verifies correctly.
  Closing this requires HSM/TPM-backed IdP key custody and signed-key
  bundles (HARD stage).
- Replay within the expiry window — bounded by the H2 lifetime ceiling
  (default 1 h) and revocable by `jti` (H13 channel, poll-bounded); the
  residual is the window itself plus propagation delay.
- JWKS source pinning — the runtime trusts whatever the JWKS endpoint serves.
  Adding a pinned key set (out-of-band distribution + first-fetch policy) is
  HARD-stage.
