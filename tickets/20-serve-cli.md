# Ticket 20: no `serve` command from the CLI

Status: open
Blocked by: 21 (CLI design spec)
Area: product
Source: ticket 06 residual, 2026-11-17.

## Why

`startRestServer` is the production assembly, but nothing in the repo invokes it
at process start. An embedder can call it, but `npm i aisl` has no `aisl serve`.
The honest sentence in the release docs is "safe to run locally; exposing it
needs TLS and a reverse proxy," and there is no first-class command to do the
local part.

## Done when

- [ ] `aisl serve` starts the REST server with the same key policy as
      `startRestServer` (fail closed on missing durable keys;
      `AISL_ALLOW_EPHEMERAL_KEYS=1` is the explicit override).
- [ ] `--host`, `--port`, `--tls-cert`, `--tls-key` are documented and tested.
      A non-loopback bind without TLS is refused before a socket exists.
- [ ] `/healthz` is reachable and reports `revocation` and `idp`.
- [ ] Graceful shutdown on SIGINT/SIGTERM.
- [ ] No secret in argv or process listing; keys come from the environment or
      files, by reference.
- [ ] The command shape comes from the CLI spec in ticket 21.

## Notes

Implementation is a separate pass from the spec. Do not design and build in the
same commit.
