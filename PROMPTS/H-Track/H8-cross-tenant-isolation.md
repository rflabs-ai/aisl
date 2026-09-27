# H8 — Cross-tenant isolation, cryptographic and physical (ROADMAP Stage 2)

Status: [ ] — queued behind the H10/H12/H13/H15 pick window. Federation gate
(ADR-022): must close (or its residual be explicitly accepted per deployment)
before any non-personal tenant joins.

Spec of record: ROADMAP.md "H8". This stub is the queue placeholder, not the
spec.

Known context from the build so far: Postgres mode enforces FORCE RLS +
per-tenant evidence keys (M12, live-tested); SQLite mode stays app-level;
the shared PROCESS remains in both modes (known-gap #7) — one memory-safety
bug crosses every boundary.

At kickoff: Phase 0 ADR first; expand to the full M4–M16 prompt format;
tests first (red), gate before commit.
