# H13 — Incident response mechanisms (ROADMAP Stage 2)

Status: [ ] — NEXT in the pick list (H10 → H12 → H13 → H15 per ROADMAP
working order). Federation flag: structurally necessary at federation
(ADR-022).

Spec of record: ROADMAP.md "H13". This stub is the queue placeholder, not
the spec.

Known context from the build so far: in-process revocation is immediate
(M4), Postgres mode gives the storage a multi-node revocation broadcast
needs (M12, single-writer — a second node must land this first); game-day
measurements are kill-switch latency, revocation propagation (target ≤ 5 s
in-process, tested), and evidence-export completeness.

At kickoff: Phase 0 ADR first; expand to the full M4–M16 prompt format;
tests first (red), gate before commit.
