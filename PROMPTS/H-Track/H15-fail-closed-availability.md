# H15 — Fail-closed availability engineering (ROADMAP Stage 2)

Status: [ ] — NEXT in the pick list (H10 → H12 → H13 → H15 per ROADMAP
working order). Federation flag: structurally necessary at federation
(ADR-022).

Spec of record: ROADMAP.md "H15". This stub is the queue placeholder, not
the spec.

Known context from the build so far: distinct degraded modes exist for IdP
outage (`idp-unavailable`, M2), Postgres unavailability
(`store-unavailable`, M12), and a health endpoint (`GET /healthz`, M14);
the open part is the full engineering — fault injection per dependency,
degraded-mode definition and tests, decision-latency p99 with/without
persistence, and rate limiting (named non-goal of M14, deployment territory).

At kickoff: Phase 0 ADR first; expand to the full M4–M16 prompt format;
tests first (red), gate before commit.
