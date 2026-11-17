# Ticket 21: CLI design spec

Status: done
Area: product and design
Source: operator request, 2026-11-17.

## Why

`src/cli.ts` is 2,170 lines and the command surface grew one subcommand at a
time: demo, attack, benchmark, build, update, incident, evidence, adversarial,
policy. There is no shared help grammar, output model, error vocabulary, or
`serve` command. Before adding commands, write the design.

## Deliverable

`docs/CLI-SPEC.md`, plus a summary in this ticket. The spec covers:

- command tree and naming, including `serve`, `doctor`, `verify`, `demo`,
  `benchmark`, `policy`, `evidence`, `incident`, `build`, and `update`;
- help text and one runnable example per command;
- output model: human by default, `--json` for machines, stable field names;
- error model: typed messages, exit codes, no stack traces by default;
- config precedence: flags > env > config file > defaults; name every variable;
- security: no secret in argv, redaction in errors and logs, `NO_COLOR`;
- accessibility: no color-only meaning, readable at 80 columns;
- shell completion and `--version`;
- what `serve` does and does not do.

## Done when

- [x] `docs/CLI-SPEC.md` exists and covers every section above.
- [x] The command tree is reviewable as a table.
- [x] The `serve` shape is concrete enough for ticket 20 to implement without
      design decisions.
- [x] No `src/` change in this ticket.

## Notes

Design is its own pass. Build is ticket 20 or a follow-up, not this ticket.

## Result

Spec: `docs/CLI-SPEC.md`. It defines the target tree (`serve`, `doctor`, `demo`,
`verify`, `benchmark`, `corpus`, `policy`, `evidence`, `incident`, `build`,
`update`, plus `completion`, `help`, `version`), the help grammar, human and JSON
output models, typed errors and exit codes, config precedence with every variable
named, security and accessibility rules, and the full `serve` contract for
ticket 20.

Renames, with reasons in the spec: `attack` / `adversarial` to `corpus run` /
`corpus check`, `revoke-*` to `incident revoke <kind>`, the three `verify`
subcommands to `aisl verify build|update|evidence`, and `evidence witness` to a
`--witness` flag. Old spellings keep working until 1.0.0.

No `src/` change. Ticket 20 is unblocked. Open questions are in section 14 of
the spec.
