# Ticket 03 — Dead `KNOWN_ACTIONS` hand-copy in `policy-testing.ts` has drifted from `KnownAction`

Status: open
Source: session-audit b3e345b..HEAD (H11, ADR-031)

## What's wrong

`src/policy-testing.ts:79` declares `const KNOWN_ACTIONS: ReadonlySet<string> =
new Set<string>([...])` — a hand-mirrored copy of `domain.ts`'s `KnownAction`
vocabulary. `git grep -n "KNOWN_ACTIONS" HEAD -- src` returns exactly one hit
(the declaration): the set is never read. It already drifted before this
milestone (`anchor.register`, added in M17, is absent) and H11's two new
actions deepen the drift (`evidence.hold`, `evidence.release` absent —
ledger row E15 lists the 13 members).

## Why it matters

Dead data that claims to be the action vocabulary invites the next maintainer
to "fix" it by hand instead of deriving it, and its name suggests an
enforcement role the code does not have (the validator's `asAction` only
shape-checks). AGENTS.md: no dead code; the seam IS the abstraction, and here
the abstraction has zero implementations of use.

## Minimal fix

Delete the `KNOWN_ACTIONS` set (the validator does not use it), or — if a
vocabulary check is actually wanted — derive it from `KnownAction` at module
load so it cannot drift.

## Evidence

Ledger rows E14-E16 (`.scratch/session-audit/2026-10-04-h11-tamper-evident-evidence/evidence.md`),
from `git grep`/`git show HEAD:src/policy-testing.ts` in this audit run.
Pre-existing drift (M17) extended by this milestone's two new actions; the
fix is a one-line deletion.
