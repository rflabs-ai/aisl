# Ticket 02 — Docs drift: stale `src/events.ts` line refs in Claims 8/19; CURRENT_STATE "exposes only" enumeration omits `flushAnchors`

Status: resolved (3f71244)
Source: session-audit b3e345b..HEAD (H11, ADR-031)

## Resolution

Claim 8 and Claim 19 mechanism refs are de-numbered (symbol names:
`eventBody`/`eventHash`, `signEventBody`/`verifyEventSignature`,
`appendAnchorLine`, `eventSigningKeyPair`, `eventPublicKey` — no line numbers
to drift); `CURRENT_STATE.md` now lists `flushAnchors` in the EventLog
surface enumeration.

## What's wrong

(a) Claim 8's mechanism cites five `src/events.ts` line numbers that no longer
match the file after H11's edits (and one predates H11):
`SECURITY_CLAIMS.md:251` → `src/events.ts:83` (actual GENESIS_HASH at 87),
`:252` → `:147` (actual `eventBody` at 253), `:257` → `:204` (actual trigger
at 430), `:258` → `:269` (actual `appendAnchorLine` at 122), `:260` → `:357`
(actual `verifyBundle` at 621). Claim 19 cites `src/events.ts:122` for
`generateKeyPairSync` (actual 352).

(b) `CURRENT_STATE.md:69-70`: "The EventLog class exposes only `append`, `all`,
`forTenant`, `verify`, `bundle`, `anchor`, and `close`" — H11 added
`flushAnchors` to the port (`src/events.ts:117`, `:504`), so "only" is now
false.

## Why it matters

These are citations inside security claims; a verifier following them lands on
the wrong code, and the "only" enumeration is the kind of structural statement
a maintainer relies on when reasoning about the store's mutability surface.
H11 touched both documents, so keeping stale refs after editing them is drift
introduced/left by this milestone.

## Minimal fix

Renumber (or de-number — name the symbols instead of lines) the Claim 8/19
mechanism references, and add `flushAnchors` to the CURRENT_STATE M3
enumeration.

## Evidence

Ledger rows E10-E13 (`.scratch/session-audit/2026-10-04-h11-tamper-evident-evidence/evidence.md`),
all from `git show HEAD:<path>` in this audit run.
