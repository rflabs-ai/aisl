# Safety ticket 01 — code safe

**Status:** closed 2026-11-01
**Evidence:** [`../SAFETY-2026-11-01.md`](../SAFETY-2026-11-01.md), gate 1

- [x] No token-shaped string in any tracked file (`sk-`, `syt_`, `ghp_`, `AKIA`, PEM blocks)
- [x] Every credential read from the environment; none at rest in the tree
- [x] `.env` and `.build-keys/` are gitignored
- [x] The process starts with no credentials set and prints a sentence per missing key

Closed. The one follow-up — turning the ephemeral-key fallback into a fail-closed
check for production starts — is tracked in ticket 04, because it is a runtime
property, not an at-rest one.
