# verifyAnchoredEvidence carries a 54-cognitive function

Status: open
Source: code-health snapshot 2026-11-13, score model v2.
Repo: `ai-security-layer`.

## Evidence

`src/anchors.ts` is 665 lines and 31 functions, max CCN 36, max cognitive 54,
LCOM4 1/2, per-file score 5.09. The weight is in `verifyAnchoredEvidence`
(line 397), which parses sources, checks monotone and contiguous sequences,
binds lines to events, checks head coverage, detects truncation, and compares
two sources for a fork, in one function.

That one function is the H11 tamper-evidence proof. A single reader has to hold
six checks in their head, and a missing branch there is a false verify.

## Action

Extract named steps from `verifyAnchoredEvidence`, keeping the checks and their
order:

- `parseSource(text)` - the `extractEvents` and line-binding step
- `checkSequences(events)` - monotone and contiguous
- `checkHeadCoverage(events, head)`
- `detectFork(a, b)`

The function becomes a short sequence of calls that each return a typed
failure or ok. Do not change what counts as a failure.

## Acceptance

- The 39 H11 tests and the 23 H8 probe rows are green.
- The three red cases already captured (truncation, same-key rewrite, same-seq
  fork) still fail closed.
- Each extracted step has one test that calls it directly.
- No file under `src/` exceeds 700 lines after the change.
