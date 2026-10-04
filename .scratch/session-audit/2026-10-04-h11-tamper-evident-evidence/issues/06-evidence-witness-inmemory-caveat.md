# Ticket 06 — `evidence witness` lacked the in-memory-world caveat its sibling branches print

Status: resolved (3f71244)
Source: session-audit b3e345b..HEAD (H11, ADR-031), Notes/N3

## What's wrong

`evidence status`/`hold` print "this process has an in-memory world — set
EVENT_STORE=postgres…" when not in Postgres mode; the `witness` branch
reconciled the default empty world without that note, so an operator could
read a `CONSISTENT` result as corroborating the running node.

## Fix

Added the same caveat line to the `witness` branch after the verdict.

## Evidence

`git show HEAD:src/cli.ts` (witness branch) — caveat printed before `return`;
CLI smoke: `node src/cli.ts evidence status` prints the note (this session's
runs); the audit's E25-era smoke recorded the sibling notes at
`cli.ts:1752,1818,1920`.