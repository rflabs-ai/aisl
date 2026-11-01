# Safety ticket 02 — artifacts safe

**Status:** open (blocks publishing)
**Evidence:** [`../SAFETY-2026-11-01.md`](../SAFETY-2026-11-01.md), gate 2

- [x] No tracked file over 200 KB; whole tree is 3.4 MB across 322 files
- [x] No binary payloads, models, databases or logs in the tree
- [ ] **Exclude `.scratch/` from any published artifact** — 114 files, 776 KB, containing local absolute paths (`C:\Users\<user>\...`) from session evidence
- [ ] **Build the handoff with a script, never by hand**, and have it refuse on a token-shaped string or a `C:\Users\` path
- [ ] The archive prints its own entry count and forbidden-path check, so the recipient can verify the claim

The `.scratch/` directory is session evidence. It is useful to keep in the working
tree and should not travel with a release.

## Done when

`npm run safety:pack` (or equivalent) produces an archive, prints
`files`, `bytes` and `forbidden: none`, and refuses if either the secret pattern
or the local-path pattern matches.
