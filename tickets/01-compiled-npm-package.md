# Ticket 01: compiled npm package

**Status:** open
**Blocks:** `npm publish`, package release
**Area:** packaging

## Why

`bin/aisl.mjs` imports `src/cli.ts`. Node refuses type stripping under
`node_modules` (`ERR_UNSUPPORTED_NODE_MODULES_TYPE_STRIPPING`), so `npm i aisl`
installs a CLI that cannot start. The tarball itself is correct (91 files,
207 kB) and the extracted CLI runs.

## Done when

- [ ] `tsconfig.build.json` emits ESM to `dist/` with relative imports rewritten.
- [ ] `bin/aisl.mjs` points at `../dist/cli.js`.
- [ ] `files` ships `dist`; `dist/` is gitignored.
- [ ] `prepublishOnly` runs typecheck, tests, and build.
- [ ] A packaging test installs the tarball in a temp dir and runs `aisl demo`.
- [ ] An ADR records the buildless-dev / compiled-publish split.
- [ ] `docs/RELEASE.md` package row flips to ready.

## Notes

No new runtime dependency: `typescript` is already a devDependency. See
`docs/RELEASE.md`, "Package release", for the current blocker text.
