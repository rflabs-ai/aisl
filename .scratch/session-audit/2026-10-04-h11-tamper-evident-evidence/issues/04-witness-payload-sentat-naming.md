# Ticket 04 — Witness protocol field `sentAt` carried the event timestamp, not the send time

Status: resolved (3f71244)
Source: session-audit b3e345b..HEAD (H11, ADR-031), Notes/N1

## What's wrong

`src/anchors.ts` POSTs `sentAt: point.at` — but `point.at` is the anchored
event's timestamp, so the field name misdescribed the data for any witness
operator (the actual send time was never sent).

## Fix

Renamed the v1 wire field to `eventAt` (the payload, the module trust-boundary
docstring, the `HttpAnchorSink` test's deep-equal, and DEPLOYMENT.md's witness
protocol line all move together). No live witness exists yet, so this is the
cheap moment to fix the protocol spelling.

## Evidence

`git grep -F "eventAt: point.at," HEAD -- src` →
`HEAD:src/anchors.ts:            eventAt: point.at,`;
`git grep -F "sentAt" HEAD -- src tests DEPLOYMENT.md` → no hits.