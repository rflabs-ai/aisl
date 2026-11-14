# Revocation feed is wired only in tests

Status: open
Source: mining S3-D0107, shard-3.md.
Repo: C:\Users\kcpat\projects\ai-security-layer.

## Evidence

`IdentityService.attachRevocationFeed` exists at `src/identity.ts:230` and is
exercised by `tests/h2-short-lived-credentials.test.ts`, but no production
assembly calls it. A grep of `src/` finds the symbol only in `identity.ts`
itself. The H13 revocation channel therefore never reaches a running server,
so cross-node token revocation looks complete while nothing attaches the feed.

Candidate text: "attachRevocationFeed/identity: appear only in tests. Let me
check production wiring."

## Action

Wire the H13 revocation channel into the production assembly: the REST server
startup and the persistent world factory should construct the feed and call
`attachRevocationFeed` on the identity service. If the channel is not ready,
record the gap in health rather than silently skipping the attach.

## Acceptance

- A non-test caller of `attachRevocationFeed` exists in `src/`.
- A test boots the server assembly and asserts the feed is attached and that a
  `revoke-token` record rejects a token on the next verify.
- `DEPLOYMENT.md` states the attach point and the health signal when the feed
  is absent.
