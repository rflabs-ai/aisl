# Ticket 01: compiled npm package

**Status:** done
**Blocks:** `npm publish`, package release
**Area:** packaging

## Why

`bin/aisl.mjs` imports `src/cli.ts`. Node refuses type stripping under
`node_modules` (`ERR_UNSUPPORTED_NODE_MODULES_TYPE_STRIPPING`), so `npm i aisl`
installs a CLI that cannot start. The tarball itself is correct (91 files,
207 kB) and the extracted CLI runs.

## Done when

- [x] `tsconfig.build.json` emits ESM to `dist/` with relative imports rewritten.
- [x] `bin/aisl.mjs` points at `../dist/cli.js`.
- [x] `files` ships `dist`; `dist/` is gitignored.
- [x] `prepublishOnly` runs typecheck, tests, and build.
- [x] A packaging test installs the tarball in a temp dir and runs `aisl demo`.
- [x] An ADR records the buildless-dev / compiled-publish split.
- [x] `docs/RELEASE.md` package row flips to ready.

## Notes

No new runtime dependency: `typescript` is already a devDependency. See
`docs/RELEASE.md`, "Package release", for the current blocker text.

## Result

- `npm run build` emits 60 files to `dist/` and deletes `dist` first, so a
  renamed module cannot survive in a stale artifact.
- `npm test`: 860 tests, 839 pass, 0 fail, 21 Postgres skips (was 859 tests;
  `tests/packaging-installed-cli.test.ts` is the new one).
- `npm pack --dry-run`: 151 files, 366,599 bytes packed.
- `node scripts/pack-release.mjs`: 259 entries, 2,827,395 bytes, forbidden none.
- `node dist/cli.js demo` exits 0; a `git`-less install exits 1 at demo section
  20, which is the demo's `git ls-files` tree digest (ADR-024), not packaging.
- ADR-044 records the split.
