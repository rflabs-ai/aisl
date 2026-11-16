# src/cli.ts is a 2,170-line file with a 113-CCN function

Status: open
Source: code-health snapshot 2026-11-13, score model v2.
Repo: `ai-security-layer`.

## Evidence

`src/cli.ts` is 2,170 lines and 86 functions. Its worst function reaches CCN
113 and cognitive complexity 109; seven functions run over 50 lines. It is
touched by 27 of the last 12 months of commits, so it is both the largest
file and the most frequently edited one. Per-file score 5.02, the worst
churn-weighted file in the repo.

`demo()` alone spans lines 152-1008. The command handlers after it
(`buildCommand`, `updateCommand`, `incidentCommand`, `evidenceCommand`,
`adversarialCommand`, `policyCommand`) are one function per subcommand, so the
file is a dispatcher plus seven programs.

## Action

Move each command into `src/commands/<command>.ts` and leave `cli.ts` as
argument parsing and dispatch. Do it one command at a time, starting with
`demo` because it is the largest. This is a move, not a rewrite: no output
text changes, no new flags.

`src/cli.ts` is the demo and operator surface, not a security boundary, so the
usual "do not refactor the core before a release" rule does not apply. It is
still a branch per command, not one branch for all seven.

## Acceptance

- `cli.ts` is under 300 lines and every command module is under 600.
- `npm run demo`, `npm run benchmark`, `npm run attack`, and
  `npm run adversarial` print the same sections and the same stable values
  before and after (capture both to `.scratch/` and diff; latency numbers are
  expected to move).
- `npm test` green, including the CLI and demo tests.
- No command gains or loses a flag.
