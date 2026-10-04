# Ticket 10 — `benchmarks/results.json` left uncommitted at the merge boundary

Status: resolved (this follow-up commit)
Source: session-audit b3e345b..HEAD (H11, ADR-031), Notes/N7

## What's wrong

The H11 work regenerated `benchmarks/results.json` (benchmark run) and left it
modified in the working tree. The repo convention is "committed at milestone
boundaries only" — this follow-up is the boundary (audit closed, branch about
to merge), so leaving it dirty into `main` would carry a local artifact.

## Fix

`benchmarks/results.json` committed with this audit follow-up record (the
same pattern as the H8 audit boundary commit `b3e345b`). It remains a
snapshot with absolute timestamps that are never reproducible by design.

## Evidence

`git status --short` before this commit → ` M benchmarks/results.json`;
committed in the follow-up commit that also carries this ticket file.