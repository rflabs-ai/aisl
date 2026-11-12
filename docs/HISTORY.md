# HISTORY

Decisions about what this repository's git history may contain, and why.

## 2026-11-12 - history rewritten: local paths replaced (supersedes 2026-11-01)

The 2026-11-01 decision accepted `C:\Users\<user>` paths in history. It is
reversed before the first public push.

A privacy pass over the full history found 193 lines carrying the personal home
path, mostly in old session logs and prompt files. Action:
`git filter-repo --replace-text` replaced the personal home path with
`C:\Users\<user>` and the old signing-key label with `dev key` across every
commit. The stray docs-only commit `5ccc86c` was removed by rebase before the
rewrite. The local relay was force-updated; no GitHub remote existed.

Consequences, to be honoured:

- **Commit SHAs recorded before 2026-11-12 in `AGENT-SESSION.md` and other docs
  refer to pre-rewrite history and will not resolve.** Treat the text as a log,
  not as a set of fetchable object ids.
- The security contact `@kcpatterson` in `SECURITY.md` is intentional and
  public. It is not part of the scrub.
- `tests/fixtures/tls/localhost-key.pem` is a self-signed localhost test key,
  not a credential. It is exempted in `scripts/pack-release.mjs` and is not
  shipped in the npm tarball.
- Canary values in tests (`HALCYON-...`, `CLASSIFIED-CANARY-...`) are deliberate
  fixtures. They are not secrets.

## 2026-11-01 - `.scratch/` paths stay in history (accepted, now superseded)

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
