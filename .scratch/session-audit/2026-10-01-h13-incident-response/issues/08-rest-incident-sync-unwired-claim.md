Status: open

Source: session-audit 2026-10-01, `feat/h13-incident-response` (uncommitted working tree; no commits this session)

## What's wrong

The runbook states the property unconditionally:
`DEPLOYMENT.md:373: running server also pulls once per authorized REST request). In SQLite mode`
— but no in-repo assembly passes the hook. `incidentSync` exists only as
`src/rest-api.ts:165: readonly incidentSync?: () => void;` consumed at
`src/rest-api.ts:316: this.incidentSync?.();`; the only occurrences elsewhere
are the audit's own spy (`tests/h13-incident-response.test.ts:377`) and the
grep shows no caller of `createRestApi` (`src/rest-api.ts:182`) that passes it —
the sole in-repo caller is `tests/m15-ui.test.ts:39: const api = createRestApi({`.

## Why it matters

Session/audit-only traffic on a REST node relies on this per-request pull to
converge (the PDP syncs itself only on `authorize`/`issue` paths). As claimed,
it reads as wired; as shipped, it is opt-in and nothing opts in — a running
server's session routes never trigger the channel pull.

## Minimal fix

Either wire it where the full API is assembled (pass
`incidentSync: () => world.incident.sync()` at the `createRestApi` seam that
combines a `World` with the API) or soften the runbook sentence to "the server
pulls when the embedder wires `incidentSync` (see `RestApiDeps`); otherwise
convergence rides the PDP authorize path". Prefer wiring if an in-repo
server assembly exists; otherwise the doc fix plus a one-line example.

## Evidence:

- `Select-String src\*.ts,tests\*.ts -Pattern "incidentSync"` → only `rest-api.ts:165/197/209/316` + `h13-incident-response.test.ts:377`
- `Select-String ... -Pattern "createRestApi\("` → `rest-api.ts:182` (def), `m15-ui.test.ts:39` (only caller)
- ledger row 23 in `.scratch/session-audit/2026-10-01-h13-incident-response/evidence.md`
