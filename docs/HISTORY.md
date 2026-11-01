# HISTORY

Decisions about what this repository's git history may contain, and why.

## 2026-11-01 — `.scratch/` paths stay in history (accepted)

Scanning all 135 commits found **no credential-shaped material**: no `sk-`,
`ghp_`, `AKIA`, PEM block, or `.env`/`.pem`/`.key` file was ever committed.

What history does contain is local absolute paths (`C:\Users\<user>\...`) inside
`.scratch/` session-evidence captures. That is a username and a directory layout,
already visible in this project's own documentation, not a secret.

**Decision:** accept, do not rewrite.

**Consequences, to be honoured at release time:**

- `.scratch/` must be excluded from any published archive (ticket 02).
- If the repository is ever published as a commercial product behind a legal
  entity, revisit this — the alternative (a squashed `v1`) must be chosen
  *before* the first public push, never after.

Full evidence: `docs/SAFETY-2026-11-01.md`, gate 3.
