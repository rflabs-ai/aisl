Status: resolved (b1e8454)

Source: session-audit 2bb3498..06a03c0 (session 2026-09-27)

## What's wrong

`findOverreach` (src/capability.ts:296-310) checks four authority dimensions —
resourceIds, actions, maxClassification, expiresAt — and ignores two:
`constraints` and `singleUse`. A delegation child may therefore DROP the
parent's `network-host` / `param-equals` constraints and escape the parent's
single-use flag, minting strictly wider authority inside the same scope. The
parent proves what the issuer holds (H1) but the subset check does not cover
everything the parent holds. The H1 fuzz matrix (tests/h1-signed-delegation.test.ts:258)
is named "every field extreme refuses" but contains no constraints or
singleUse extreme; ROADMAP H1's test methodology says "attempt every
attenuation bypass in the harness".

## Why it matters

A parent constrained to `network-host: [a.example.com]` (or single-use)
delegates an unconstrained (or multi-use) child: the child authorizes at
verify time more than the issuer's held capability ever did. This is an
escalation within scope bounds — exactly what invariant 6 exists to prevent —
and it is reachable in the real delegation flow H1 just built.

## Minimal fix

In `findOverreach` (or `parentValidityError` + the derived-authority path),
when a parent is presented: (a) refuse a child whose constraints are not a
subset of the parent's constraints (every child constraint must be present in
the parent's list), and (b) refuse `singleUse: false` children of a
single-use parent (a single-use parent's children must be single-use). Add
both bypass cases to the H1 extremes matrix. Pre-existing shape
(`IssuerAuthority` never carried these fields) — newly live through the
delegation path.
