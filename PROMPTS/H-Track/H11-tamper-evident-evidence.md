# H11 — Tamper-evident evidence: signatures, anchoring, retention (ROADMAP Stage 2)

Status: [ ] — queued behind the H10/H12/H13/H15 pick window.

Spec of record: ROADMAP.md "H11". This stub is the queue placeholder, not the
spec.

Known context from the build so far: M3 closed the in-process part (per-event
Ed25519, append-only triggers, head-hash anchor file, offline verifyBundle);
the open part is durability — the anchor living OUTSIDE the runtime's trust
domain (residual: anchor rewrite by an attacker with host access, Claim 8);
federation clients anchor INTO this plane (ADR-022/M17).

At kickoff: Phase 0 ADR first; expand to the full M4–M16 prompt format;
tests first (red), gate before commit.
