# DECISIONS.md is past what a session can read

Status: open
Source: mining S6-D0088, shard-6.md.
Repo: C:\Users\kcpat\projects\ai-security-layer.

## Evidence

`DECISIONS.md` was 2,461 lines and 143,392 bytes when the candidate was
recorded. It is now 2,723 lines. A single file that large cannot be read in one
session, so ADR lookups degrade to grep and the file stops being a decision
record and becomes an archive.

Candidate text: "DECISIONS.md: 2461 lines, 143392 bytes".

## Action

Split the file into one file per ADR under `docs/adr/` (or `DECISIONS/`), keep
a short index at `DECISIONS.md` with id, title, status, and a link, and move
superseded ADRs to an archive folder. Do not rewrite the ADR bodies in the same
change.

## Acceptance

- No single decision doc exceeds a stated line budget (for example 300 lines).
- Every ADR id still resolves from the index.
- A link check passes over the index and the per-ADR files.
