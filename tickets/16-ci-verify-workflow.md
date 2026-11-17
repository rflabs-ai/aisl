# There is no CI; the gate is local only

Status: open
Source: release readiness review 2026-11-16.
Repo: `ai-security-layer`.

## Evidence

The tree has no `.github/` directory. The gate that every ticket and every
release depends on is three local commands:

```
npm run typecheck
npm test
node scripts/pack-release.mjs
```

The other released repos in the family run CI on push and pull request, and the
november release board treats a green CI as part of readiness. A stranger who
clones this repo gets no signal, and a regression can land on `main` with
nothing to catch it.

## Action

Add `.github/workflows/verify.yml` on `push` and `pull_request`:

1. `actions/setup-node` with Node 22 and 24 (the `engines` floor is 22.18, the
   dev machine runs 24).
2. `npm ci` (the repo ships `npm-shrinkwrap.json`).
3. `npm run typecheck`.
4. `npm test`. Postgres tests skip cleanly without `DATABASE_URL`; do not add a
   service container in the first version.
5. `node scripts/pack-release.mjs`, which also fails on a tracked absolute path
   or a token-shaped string.

Keep it one job. A matrix over two Node versions is the only fan-out.

## Acceptance

- The workflow is green on `main`.
- A deliberately broken typecheck fails it (prove it on a throwaway branch).
- The pack step fails when a tracked file contains a local absolute path
  (prove it the same way).
- Total runtime stays under the free-tier default; the local suite is about
  90 seconds plus install.

## Result

- `.github/workflows/verify.yml` added: `push` and `pull_request`, Node 22 and
  24, `npm ci`, typecheck, test, a clean-tree check, and the pack gate.
- Verified locally 2026-11-17: the YAML parses; `npm ci` installs 6 packages;
  the same commands pass on `main` (839 pass, 0 fail, 21 Postgres skips); the
  clean-tree check passes after a gate run.
- **Not verified:** the workflow has not executed on GitHub. The repo has no
  remote push yet, so this ticket stays open until the first green run. Flip it
  to done then.
