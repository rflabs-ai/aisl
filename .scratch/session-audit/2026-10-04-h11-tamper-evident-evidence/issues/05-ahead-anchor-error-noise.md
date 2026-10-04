# Ticket 05 — Anchor-ahead errors repeated once per line (noisy truncation reports)

Status: resolved (3f71244)
Source: session-audit b3e345b..HEAD (H11, ADR-031), Notes/N2

## What's wrong

`verifyAnchoredEvidence` pushed one `anchor is ahead of the bundle head` error
per anchor line above the bundle head, so a large truncation produced a wall
of near-duplicate source errors in addition to the single aggregate
`tail truncation suspected` error.

## Fix

Dropped the per-line push; the source report's `aheadOfBundle` flag plus the
one aggregate error carry the signal. Existing truncation tests still assert
`aheadOfBundle === true` and the aggregate message.

## Evidence

`git grep -F "an anchor source is ahead of the bundle head" HEAD -- src` →
`HEAD:src/anchors.ts:      errors.push('an anchor source is ahead of the bundle head: tail truncation suspected');`;
`git grep -F "anchor is ahead of the bundle head (" HEAD -- src` → no hits.