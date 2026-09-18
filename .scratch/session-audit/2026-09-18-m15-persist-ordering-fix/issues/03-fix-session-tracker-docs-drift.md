Status: open
Source: session-audit M15 fix commit 465b67b

## What's wrong

The 465b67b fix session skipped AGENTS rule 8 (docs in the same commit):
- .scratch tickets 01/02 (2026-09-18-m15-stage0-cleanup) not annotated — 02 is
  fully fixed but still `Status: open` with no commit hash; 01 is half-fixed
  (approve done, submit ordering still open) with no annotation.
- AGENT-SESSION.md has no entry for the fix.
- CURRENT_STATE.md still reports 462 tests / 448 pass (now 475/460 on the M16
  tree; 464/450 on main at the fix merge).

## Why it matters

Docs that drift from code rot into lies (AGENTS preamble). The next session
reads tickets to pick up the still-open submit-ordering work; an unannotated
"open" on a half-fixed ticket hides which half is done.

## Minimal fix

Annotate both tickets with 465b67b/37c87df and the remaining scope; add an
AGENT-SESSION entry for the two fix commits; bump CURRENT_STATE counts (at
the next M-mainline commit, not mid-M16).
