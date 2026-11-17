# Ticket 04: decide whether internal project names ship

**Status:** done
**Area:** privacy
**Source:** 2026-11-12 privacy pass

## Why

`HEAD` is free of personal home paths, and history was rewritten to remove them.
But `AGENT-SESSION.md` and `PROMPTS/` still name private sibling projects
(`project-raven`, `control-plane`, `local-ai-system`). The scanner did not
classify them as personal data, so they were not scrubbed.

## Done when

- [x] Decide: ship them as provenance, or genericize them.
      **Decision 2026-11-17: ship as provenance (ADR-045).** They are project
      names, not personal data, credentials, or paths, and they are load-bearing
      in ADR-022, M17/M18, README, ROADMAP, and SECURITY_CLAIMS. 116 lines
      across 28 files.
- [x] If genericizing, run the same `git filter-repo` pass and record it in
      `docs/HISTORY.md` before the first public push.
      **Not applicable:** no rewrite. Reversible until the first push.
