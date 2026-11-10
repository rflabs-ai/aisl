# Safety ticket 05 — pre-commit hook must not leak GIT_DIR

**Status:** closed 2026-11-10
**Severity:** would have corrupted the checkout on the next commit

## What happened

The pre-commit hook runs `npm test` from inside a git hook. Git exports
`GIT_DIR`, `GIT_WORK_TREE` and `GIT_INDEX_FILE` into that environment. The
`m15-git` fixture shells out to git in a temporary directory, inherited the
variables, and operated on this repository instead of its own.

Two symptoms followed:

- a fixture's `git init --bare` set `core.bare = true` on the whole checkout, so
  every work-tree command failed with "this operation must be run in a work tree";
- a fixture's commit staged files into this repository's index.

A subagent hit both while landing the durable-keys change, reset the branch,
re-staged by hand, and committed with `--no-verify` after running the gate
manually. No bad commit entered history.

## Recovery

1. `git config core.bare false`
2. `git reset --hard HEAD` (the commit held all eight files; the working tree and
   index were stale). Named reason: poisoned index, commit is source of truth.
3. Gate re-run: 828 pass, 0 fail, 21 Postgres skips.

## Fix

- `scripts/pre-commit` is now **tracked** (it was only in `.git/hooks`, so a
  fresh clone had no gate at all) and unsets `GIT_DIR`, `GIT_WORK_TREE`,
  `GIT_INDEX_FILE`, `GIT_OBJECT_DIRECTORY` and `GIT_ALTERNATE_OBJECT_DIRECTORIES`
  before running the gate.
- Install with `cp scripts/pre-commit .git/hooks/pre-commit && chmod +x`.

## Fixture isolation (closed 2026-11-10)

- Every test fixture that shells out to git now goes through
  `tests/helpers/git.ts`. The helper sets `cwd` explicitly and removes
  `GIT_DIR`, `GIT_WORK_TREE`, `GIT_INDEX_FILE`, `GIT_OBJECT_DIRECTORY` and
  `GIT_ALTERNATE_OBJECT_DIRECTORIES` from the child environment.
- Fixtures routed through it: `tests/m15-git.test.ts`,
  `tests/h10-supply-chain.test.ts`, `tests/h12-secure-updates.test.ts`.
  `security-tests/` spawns no git.
- Regression: `tests/fixture-isolation.test.ts` exports a bogus `GIT_DIR` and
  `GIT_WORK_TREE` in the test process, commits in a temp repo through the
  helper, and asserts the commit landed in the temp repo, the poisoned path was
  never created, and the real repository's HEAD did not move. Against the old
  unisolated spawn the same sequence fails with
  `fatal: this operation must be run in a work tree`.

## Remaining, out of scope here

- `src/supply-chain.ts` still spawns `git ls-files` / `git rev-parse` with the
  inherited environment. That is production code and was not changed. It is
  benign when `GIT_DIR` points at the real repository (the hook case), and it
  fails closed when the variable points elsewhere. A future change can give it
  the same minimal environment as `src/git-reader.ts`.

## Done when

A commit from a clean checkout runs the full gate and leaves `git status` clean,
and the git fixtures pass identically whether or not the caller exported
`GIT_DIR`.
