# Sandbox limits do not isolate tool code from the host

Status: open
Source: mining S4-D0021, shard-4.md.
Repo: C:\Users\kcpat\projects\ai-security-layer.

## Evidence

The container sandbox enforces memory, CPU, and pid limits, but tool code still
runs on the host: `new Function()` inside the container cannot resolve module
imports, so the runner falls back to host execution. The `kind` string
documents the ceiling, but the isolation claim is incomplete.

Candidate text: "The container sandbox enforces limits but tool code still runs
on the host because `new Function()` inside the container cannot resolve module
imports; the `kind` string documents the ceiling but isolation is incomplete."

## Action

Pick one and record it:

1. Run tool code inside the container with a real module loader (write the
   module to a temp dir and import it), so host execution is not the fallback.
2. Keep host execution and narrow the claim: state in `SECURITY_CLAIMS.md` and
   `RELIABILITY.md` that the sandbox bounds resources but does not isolate the
   filesystem or network, and name the residual.

## Acceptance

- A test proves tool code cannot read a host-only path or reach a host-only
  port, or the claims docs state the ceiling with a named residual.
- The `kind` string and the docs agree on what the sandbox actually enforces.
