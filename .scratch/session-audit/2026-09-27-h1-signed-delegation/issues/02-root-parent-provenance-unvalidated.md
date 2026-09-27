Status: resolved (b1e8454)

Source: session-audit f62230d (session 2026-09-27)

## What's wrong

The `provenance` construction (src/capability.ts:187-189) sits OUTSIDE the
`authorityRequired` attenuation block (src/capability.ts:164-183). A root
issuer (`kind: 'authorization'`) that passes a `parent` records
`provenance.delegatedFrom` from an object whose signature, subject, tenant,
expiry, and consumption were never checked — `parentValidityError` only runs
for non-root issuers.

## Why it matters

The ADR-023 / Claim 6 language ("the chain link is recorded and walkable",
"set by issueCapability from the parent capability") implies validated links.
A root-minted capability can carry a `delegatedFrom` pointing at a fabricated
or forged parent, polluting the evidence plane with a chain link that fails
verification downstream. Latent today (no caller does root+parent), but it
violates the documented invariant the moment one does.

## Minimal fix

Validate whenever a parent is present regardless of issuer kind — move the
`parentValidityError` call out of the `authorityRequired` branch (root keeps
unlimited minting power; it just refuses garbage parents) — or set
`delegatedFrom` only inside the validated branch. Add a test: root + tampered
parent is refused (or carries no delegatedFrom).
