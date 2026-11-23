# The test suite rewrites a tracked file, so the tree is never clean

Status: done
Source: release readiness review 2026-11-16.
Repo: `ai-security-layer`.

## Evidence

`npm test` includes the M10 benchmark integration test, which runs the
benchmark in-process. The benchmark writes `benchmarks/results.json` with a
fresh `generatedAt`, a new anchor `head`, and new latency numbers, so every test
run leaves a modified tracked file.

The repo has a pre-commit hook that runs the gate, so the sequence is: commit,
hook runs the tests, the tree is dirty again. `git status --short` is never
empty after a gate run. That breaks the clean-tree check a release and a
clean-clone test rely on, and it makes every commit look like it carries an
unrelated benchmark update.

Observed 2026-11-16: two consecutive gate runs produced two different diffs,
14 lines each, differing only in timestamp, head, and latencies.

## Action

Give the benchmark writer an output path and have the integration test write to
a temp file (or a gitignored `.scratch/` path). Keep `npm run benchmark`
writing the committed artifact deliberately, so the record still updates when
someone means to update it.

Do not make the test skip; the SLO block assertion is the point.

## Acceptance

- After `npm test`, `git status --short` is empty.
- `npm run benchmark` still updates `benchmarks/results.json`.
- The SLO gate assertion still runs and still fails on a fabricated hard miss.
- A test asserts the default output path is used only by the CLI entry point,
  not by the test.

## Result

- `src/cli.ts` writes to `aiSL_BENCHMARK_OUT` when it is set, otherwise to
  `benchmarks/results.json`. No flag, no new module, one conditional.
- `tests/slo.test.ts` runs the benchmark with the override pointed at a temp
  file, reads it from there, and asserts the tracked artifact is neither
  created nor rewritten by a test run.
- Verified 2026-11-16: after a full `npm test`, `git status --short` shows only
  the edited source files. `npm run benchmark` still updates
  `benchmarks/results.json`.
