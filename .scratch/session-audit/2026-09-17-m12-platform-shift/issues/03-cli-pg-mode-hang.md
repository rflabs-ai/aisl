Status: resolved (06eaf50)
Source: session-audit M12 (range 007a8a6..1298ed0)

## What's wrong

src/cli.ts wires `whenWorldReady()` at the three PG-mode entry points
(lines 45, 490, 507) but never calls `world.eventLog.close()` at the end of
`demo()`/`attack()`/`benchmark()`. In `EVENT_STORE=postgres` mode the
`postgres` driver's pool keeps sockets open, so `npm run demo|attack|benchmark`
never exits — the process hangs after printing its output. Untested (no
PG-mode demo run happened in the milestone), so the bug is latent until an
operator first runs the CLI against Postgres.

## Why it matters

First real PG-mode CLI run appears to hang; an operator cannot tell
"hung" from "running", and the same latent path affects any future entry
point. Small but certain runtime bug in the main session's own wiring.

## Minimal fix

Close the world's store at the end of each command (after the final
output): `world.eventLog.close()` — or a tiny `closeWorld(world)` helper in
scenario.ts next to `whenWorldReady` — in all three cli functions. Verify
with `EVENT_STORE=postgres DATABASE_URL=... npm run demo` (needs the
scratch DB from DEPLOYMENT.md; assert the process exits).
