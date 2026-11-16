# Postgres setup script has no restart policy

Status: open
Source: mining D0159, cont-1.md.
Repo: `ai-security-layer`.

## Evidence

`scripts/setup.ps1` generates a throwaway password, passes it to the container
by reference, and tells the operator to read it from the container env. The
`docker run` at line 83 has no `--restart` flag, so the scratch database does
not come back after a Docker or host restart. The candidate asks for the
repo's own setup script, password by reference, and restart policy
`unless-stopped`.

Candidate text: "Use the repo's own setup script for Postgres, keep the
generated password in the container env, read it by reference, and set restart
policy unless-stopped".

## Action

Add `--restart unless-stopped` to the `docker run` in `scripts/setup.ps1` and
the matching command in `scripts/setup.sh`. Keep the password by reference and
the existing warning that the container is scratch-only.

## Acceptance

- Both setup scripts start the container with `--restart unless-stopped`.
- A fresh setup survives a Docker restart and the database is reachable.
- The password is still read from the container env, never printed.
