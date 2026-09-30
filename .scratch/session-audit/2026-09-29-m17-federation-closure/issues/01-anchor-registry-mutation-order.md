# 01 — `AnchorRegistry.record` mutates `lastHeadByTenant` before the event append
Status: resolved (2026-09-29, same session)

Resolution: `src/rest-anchors.ts` — `this.lastHeadByTenant.set(...)` moved to
after `eventLog.append` with a comment naming the invariant (the head advances
only when the evidence append landed). Red-first test added:
`tests/m17-federation.test.ts` describe "AnchorRegistry: a throwing event
append must not poison the registry" (failing pre-fix with
`actual: true, expected: false` on "a failed append must leave the last
accepted head unchanged"; green post-fix). Full gate green: 540 tests
(525 pass, 15 PG skips), typecheck clean. The durable-persistence upgrade
path remains documented at the ponytail marker (`src/rest-anchors.ts:11-14`).

Source: session-audit 2026-09-29 (target: uncommitted M17 federation closure).
Probe P3 in `.scratch/session-audit/2026-09-29-m17-federation-closure/evidence.md`.

## What's wrong
`AnchorRegistry.record` updates `lastHeadByTenant` (the in-memory "last accepted
head" map used to flag `tamper`) at `src/rest-anchors.ts:61`, *before* calling
`eventLog.append` at `src/rest-anchors.ts:63`. If the append throws (synthetic
EventStore, disk full, Postgres `StoreUnavailableError`, etc.), the registry is
poisoned: the in-memory state claims a head the evidence plane never recorded,
so a subsequent honest anchor that chains to the *evidence's* last head is
silently flagged `tamper`.

This is the same divergence class the Ponytail marker at `rest-anchors.ts:11-14`
warns about (in-memory registry vs append-only EventStore); the marker names
durable-persistence as the upgrade path, but the order of mutations means the
divergence can occur in a single call, not just across restarts.

## Why it matters
The `tamper` flag is observable in the response (`rest-anchors.ts:132`) and
landed in the evidence plane (`rest-anchors.ts:77`). The control-plane client
does not act on it (it does its own prefix-based detection at
`control-plane/src/asl/anchor.ts:106-115`), so this is advisory — but it is
still a divergence the operator can read, and any future ASL-side consumer of
the tamper flag would inherit the bug. Claim 33 currently calls the registry
"advisory" without naming the in-flight mutation-order divergence.

## Minimal fix
- **Cheap (this session):** move `this.lastHeadByTenant.set(...)` to *after*
  the `eventLog.append` call, and only on success. The current anchor is the
  last accepted head only when the append landed.
- **Honest (upgrade path):** persist the accepted-head map to the same
  durable store as the evidence (or fold it into a header on the
  `anchor.register` event and recompute on restart). Eliminates the
  in-memory/evidence divergence entirely.

## Evidence
```
PROBE-P3 caught expected first-anchor throw: synthetic append failure
PROBE-P3 fourth anchor (honest chain against poisoned registry): {
  id: 'f9b8e868-2cce-4340-8c33-87f71460dd30',
  acceptedAt: 1790730928448,
  tamper: true
}
✔ first anchor with append failure leaves registry poisoned; subsequent anchor silently flags tamper
```

Command: `node --test tests/probe-m17-poisoned-registry.test.ts` (probe deleted after run per audit discipline).

Source line: `src/rest-anchors.ts:61` —
`this.lastHeadByTenant.set(input.tenant, input.headHash);` runs before
`this.eventLog.append({...})` at `src/rest-anchors.ts:63`.
