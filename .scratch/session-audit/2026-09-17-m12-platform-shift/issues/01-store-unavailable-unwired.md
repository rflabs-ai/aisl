Status: resolved (06eaf50)
Source: session-audit M12 (range 007a8a6..1298ed0)

## What's wrong

ADR-018 (DECISIONS.md, "Fail-closed (H15)") explicitly claims a distinct
`denyReason: 'store-unavailable'` — "new union member in `src/domain.ts`,
beside `'idp-unavailable'`". It does not exist: grep finds the string in no
src file, `src/domain.ts:177-198` has no such member, and no decision path
maps an unavailable store to it. Today an unreachable Postgres surfaces as
`evidence-write-failure` (append failure) or a raw unready-append throw —
the mechanism fails closed, but the documented distinct reason and the
"operator-visible difference from an attack" it buys (H15) are absent.

The same claim appears in four places: DECISIONS.md ADR-018 fail-closed
section, ROADMAP M12 marker, CURRENT_STATE known-gap #13, and
DEPLOYMENT.md Postgres-mode "Fail-closed" bullet — all describing behavior
the code does not have (Claimed-but-absent).

## Why it matters

H15's whole point is a loud, distinguishable degradation: with the reason
missing, operators cannot tell "Postgres down" from "evidence write failed"
from a security denial. The docs are the contract (AGENTS step 7/8: "does
the new code actually close the limitation you claim? If not, update the
claim or don't ship").

## Minimal fix

Add `'store-unavailable'` to the `DenyReason` union (src/domain.ts:177),
and where the runtime maps evidence-store failures to deny decisions
(the append-failure catch in src/runtime.ts around the `evidence-write-failure`
path, plus `PostgresEventLog.whenReady()` failure at connect), emit the
distinct reason + one loud health event. Then the existing fail-closed test
extends: DB down → deny with `store-unavailable`, not
`evidence-write-failure`. Add the wiring test in
tests/event-store-pg.test.ts (live-DB: unreachable/mid-failure store →
decision carries the reason).
