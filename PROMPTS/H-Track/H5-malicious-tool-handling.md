# H5 — Malicious tool handling (ROADMAP Stage 2)

Status: [ ] — queued behind the H10/H12/H13/H15 pick window.

Spec of record: ROADMAP.md "H5". This stub is the queue placeholder, not the
spec.

Known context from the build so far: `ContainerSandbox` (M1) + lifecycle
(M16) enforce non-root/read-only rootfs/no-network/seccomp/memory-CPU-PID
limits when Docker is present; `LocalSandbox` fallback is honestly zero
isolation; known-escape corpora, resource-bomb tests, and scope-expansion
tests are the ask.

At kickoff: Phase 0 ADR first; expand to the full M4–M16 prompt format;
tests first (red), gate before commit.
