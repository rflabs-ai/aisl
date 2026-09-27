# H2 — Short-lived credentials and workload identity (ROADMAP Stage 2)

Status: [ ] — queued behind the H10/H12/H13/H15 pick window. Federation flag:
structurally necessary at federation (ADR-022) — cross-repo REST clients are
long-lived bearer tokens today.

Spec of record: ROADMAP.md "H2" (attack surface, failure modes, assumptions,
test methodology, residual risk). This stub is the queue placeholder, not the
spec.

Known context from the build so far: IdP tokens carry expiry (M2, `jose`);
REST deployment tokens in `data/secrets.json` posture are long-lived; no
workload identity for non-human principals.

At kickoff: Phase 0 ADR first (DECISIONS.md, newest last); expand this stub
to the full M4–M16 prompt format; tests first (red), gate before commit.
