# H7 — Data-flow enforcement and egress DLP (ROADMAP Stage 2)

Status: [ ] — queued behind the H10/H12/H13/H15 pick window. Home-agent flag:
its unclassifiable personal-data egress needs exactly this (ADR-022).

Spec of record: ROADMAP.md "H7". This stub is the queue placeholder, not the
spec.

Known context from the build so far: the egress proxy + PDP gate + canary
exfiltration suite exist (M1); the M13 egress gate classifies declared
content maps — free text absent from the map is named territory (Claim 27);
encoding/compression bypass and volume-anomaly detection not implemented.

At kickoff: Phase 0 ADR first; expand to the full M4–M16 prompt format;
tests first (red), gate before commit.
