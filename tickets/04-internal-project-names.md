# Ticket 04: decide whether internal project names ship

**Status:** open
**Area:** privacy
**Source:** 2026-11-12 privacy pass

## Why

`HEAD` is free of personal home paths, and history was rewritten to remove them.
But `AGENT-SESSION.md` and `PROMPTS/` still name private sibling projects
(`project-raven`, `control-plane`, `local-ai-system`). The scanner did not
classify them as personal data, so they were not scrubbed.

## Done when

- [ ] Decide: ship them as provenance, or genericize them.
- [ ] If genericizing, run the same `git filter-repo` pass and record it in
      `docs/HISTORY.md` before the first public push.
