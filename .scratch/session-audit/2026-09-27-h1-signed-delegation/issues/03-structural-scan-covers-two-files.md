Status: resolved (b1e8454)

Source: session-audit f62230d (session 2026-09-27)

## What's wrong

The structural invariant test (tests/h1-signed-delegation.test.ts:288-293)
scans exactly two files — `src/capability.ts` and `src/pdp.ts` — for
`issuerAuthority|IssuerAuthority`, but the recorded claim (CURRENT_STATE.md,
"What H1 closed") says "no `issuerAuthority`/`IssuerAuthority` symbol remains
anywhere in `src/`". A third file could reintroduce the declared-authority
seam and the test would still pass.

## Why it matters

This test is the structural enforcement of the H1 trust boundary (the repo's
"one structural invariant test per new trust boundary" rule). A structural
test that covers less than the claim it enforces is exactly how a seam gets
reintroduced silently.

## Minimal fix

Glob all `src/*.ts` files in the test (e.g. `readdir` on `src/`, filter
`.ts`, scan each) instead of the two hardcoded paths. One loop, no framework.
