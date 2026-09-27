# H4 — Prompt-injection-resistant architecture (data-flow enforcement) (ROADMAP Stage 2)

Status: [ ] — queued behind the H10/H12/H13/H15 pick window. Home-agent flag:
its web→model→shell path needs exactly this (ADR-022).

Spec of record: ROADMAP.md "H4". This stub is the queue placeholder, not the
spec.

Known context from the build so far: `detectInjectionSignals` is telemetry,
not a control (known-gap #9); the M8 guard detects (D2–D5) downstream of the
model; taint tracking through serialization is not implemented; the corpus is
12 cases.

At kickoff: Phase 0 ADR first; expand to the full M4–M16 prompt format;
tests first (red), gate before commit.
