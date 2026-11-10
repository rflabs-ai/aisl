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

## Still open

- The `m15-git` fixture should also isolate itself (`env` without `GIT_DIR`)
  rather than relying on the caller. The hook fix covers the observed path; the
  fixture fix covers every other caller.

## Done when

A commit from a clean checkout runs the full gate and leaves `git status` clean,
and `npm test` passes identically whether or not the caller exported `GIT_DIR`.
