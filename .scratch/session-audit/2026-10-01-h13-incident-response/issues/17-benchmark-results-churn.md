Status: open

Source: session-audit 2026-10-01, `feat/h13-incident-response` (audit notes → ticketed on request)

## What's wrong

`benchmarks/results.json` is tracked and rewritten by every
`npm run benchmark` run, so it rides into diffs as pure measurement noise —
this session's diff includes it (`git diff HEAD --stat` →
`benchmarks/results.json | 20 +-`), and the previous H12 commit did too
(`git log -- benchmarks/results.json` → `b31987c H12: secure updates ...`).
The snapshot doc already treats the file as read-at-run
(`CURRENT_STATE.md` "read them from `benchmarks/results.json`"), and the audit
history has an old resolved ticket about copying its numbers
(`.scratch/session-audit/2026-09-17-m11-authz-depth/issues/01-measured-this-run-contradicts-results-json.md`).

## Why it matters

Reviewers cannot tell a behavior change from a benchmark rerun; the artifact
also carries absolute timestamps, so it is never reproducible.

## Minimal fix

Decide the convention and record it: either commit results.json only at
milestone boundaries (current practice — note it in `benchmarks/`'s README or
CURRENT_STATE), or stop tracking it (`git rm --cached` + `.gitignore`) and
publish results in docs/CI artifacts instead.

## Evidence:

- `git diff HEAD --stat` → `benchmarks/results.json | 20 +-`
- `git log --oneline -5 -- benchmarks/results.json` → `b31987c H12: secure updates — ...`
- audit report Notes
