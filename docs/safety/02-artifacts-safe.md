# Safety ticket 02 — artifacts safe

**Status:** closed 2026-11-04
**Evidence:** [`../SAFETY-2026-11-01.md`](../SAFETY-2026-11-01.md), gate 2

- [x] No tracked file over 200 KB; whole tree is 3.4 MB across 322 files
- [x] No binary payloads, models, databases or logs in the tree
- [x] **Exclude `.scratch/` from the published tree** — untracked and added to `.gitignore` (2026-11-01); the files stay on disk for local evidence use
- [x] **`node scripts/pack-release.mjs`** — refuses on a token-shaped string or a local absolute path; first run found six tracked files carrying the author's home path, now redacted
- [x] The script prints entry count, byte count and the forbidden-path result; `--write` produces `dist/aisl-<version>.zip` via `git archive`, so gitignored files cannot leak in

The `.scratch/` directory is session evidence. It is useful to keep in the working
tree and should not travel with a release.

## Done when

`npm run safety:pack` (or equivalent) produces an archive, prints
`files`, `bytes` and `forbidden: none`, and refuses if either the secret pattern
or the local-path pattern matches.
