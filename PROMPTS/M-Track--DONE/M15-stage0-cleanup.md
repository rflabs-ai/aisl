# M15 — Stage 0 cleanup: ingestion, Git, setup script, minimal UI

Baseline: M14 (REST API) complete and verified — the minimal UI row (39)
depends on it (its dep column names the REST API); rows 37/38/40 do not and
could run beside M14, but sequencing M14 first keeps this milestone the
single remaining one before Stage 0 is fully [DONE]. Zero new runtime
dependencies planned; the Git integration shells out to the installed git
CLI via argv (the `CommandCheck` precedent, src/check-command.ts — no shell
string), and the UI is static HTML/JS served by the same `node:http`
server. The still-open M12 seam (`capability_requests` has a table but no
API methods) folds into Phase 1 here — it is the same surface.

Scope (ROADMAP rows): Basic document ingestion (chunk, label, classify),
Basic Git integration (read-only repo access), Developer setup script
(`curl | bash`-free reproducible env), Minimal UI (task + evidence view) —
the four remaining Stage 0 rows.

Environment note: nothing new; the Postgres container workflow from M12
already exists if the setup script wants to bootstrap it.

## 0. Phase 0 — ADR-020 (docs only; UNBLOCKED)

- **ADR-020**: Stage-0 closure decisions. Must decide:
  - **Document ingestion:** chunking is deterministic (fixed-size with
    boundary awareness, no model in the loop); every chunk is labeled with
    the source document's id as `derivedFrom` (M11 propagation already
    computes `derivedClassification` — reuse, do not reimplement);
    chunk-classification can only RAISE (M11 raise-only rule); chunks are
    registry resources (capability-scoped like any resource); ingestion is
    an event (`document.ingest` per chunk with the derived label — no
    plaintext content in events beyond what sealing already does).
  - **Git integration: read-only only.** Allowed verbs: `log`, `show`,
    `diff`, `status` — a config-time allowlist (the `CommandCheck`
    posture: argv array, NEVER a shell string, no interpolation). The repo
    path is a configured root; traversal outside it is refused at the
    trust boundary. Output is untrusted content: it enters as a document
    (ingestion pipeline), is labeled with the repo's classification, and
    the agent's use of it is gated by the ordinary PDP path. No write, no
    push, no fetch, no submodules.
  - **Setup script: no `curl | bash`.** Plain scripts (`scripts/setup.ps1`
    + `scripts/setup.sh`) that check the Node version, run `npm install`,
    typecheck, and tests, print next steps, and OPTIONALLY bootstrap the
    disposable Postgres container from M12's DEPLOYMENT workflow. No
    remote fetches, no pipe-to-shell, no sudo.
  - **Minimal UI: static HTML/JS served by the M14 server** (zero deps —
    vanilla `fetch` against `/v1`). Server-rendered HTML or a single
    static page; no bundler, no framework, no node_modules. Task run +
    evidence view only (row 39's purpose). Accessibility basics are NOT a
    simplification target (WCAG-lite: semantics, labels, keyboard).
- Implementation must match the ADR or the ADR gets amended — no drift.

## 1. Subagents + parallelization (explicit)

- **Phase 1 (after ADR-020): A — capability-request API methods (the M12
  seam: CRUD over the existing table) ∥ B — document ingestion, in
  PARALLEL.** A owns `src/rest-sessions.ts` additions + a small
  `src/persistence.ts` extension (`createCapabilityRequest`/
  `getCapabilityRequest`/`listForTenant`); B owns new `src/ingestion.ts`
  (chunker + labeling + propagation + registry) + tests. C (Git) **waits**
  — the ingestion pipeline is what Git output flows into.
- **Phase 2 (after A/B): C — Git integration (read-only) — consumes B's
  ingestion as its output surface. ∥ D — minimal UI (served by the M14
  API), in PARALLEL.** C owns new `src/git-reader.ts` + tests; D owns new
  `tools/ui/` (static HTML/JS) + the server wiring for static files
  (main-session edit of `src/rest-api.ts` — one seam, no conflict).
- **Shared-file rule:** only the main session edits `src/rest-api.ts`
  route registration, `src/cli.ts` (a UI section in the demo if useful),
  and benchmark additions — the M10 gate must stay green.

## 2. Hard requirements (never simplify away)

- **Ingestion:** chunk ids are deterministic (`doc/<id>/chunk/<n>`); the
  label flow is the M11 machinery (`derivedFrom` → max-by-rank, raise-only);
  hostile document content stays hostile (invariant 3: it never mints
  authority); sealed content stays sealed (Claim 13); every ingest produces
  its audit event (invariant 7).
- **Git:** argv-array exec only, allowlist at config time, no shell, no
  traversal outside the configured root (path-normalization test), read
  capability per the ordinary issuance path, output treated as hostile
  document content (same as any ingested text — no path from text to
  authority, ADR-011).
- **Setup script:** no `curl | bash`, no network fetches at setup (env is
  reproducible offline); prints what it checked; exits nonzero on any
  failed check (fail-closed posture applies to tooling too).
- **UI:** no new authorization surface (it is a client of `/v1`; the PDP
  rules do not change); no content rendered from model text without the
  guard having gated it (the UI shows the trace, never bypasses it);
  accessibility basics hold (semantic HTML, labels, keyboard reachability).

## 3. Tests / acceptance

- Ingestion: chunk + label + classify roundtrip (deterministic ids;
  derived classification ≥ source; chunks registered as resources;
  plaintext never in events beyond the sealing the runtime already does);
  a malicious document stays injection-inert (corpus precedent).
- Git: read-only verbs only (a write verb is refused at config time);
  traversal outside the root is refused; output flows through the
  ingestion path with the repo's classification (a poisoned-source
  response is still guarded — documented D2 ceiling, unchanged).
- Setup: checks pass on a clean checkout; nonzero exit on a missing
  prerequisite; the optional Postgres bootstrap matches DEPLOYMENT.md's
  steps.
- UI: served by the same server (loopback); the task view uses
  `POST /v1/tasks`, the evidence view uses `GET /v1/audit` — both
  authorized; no canary/secret/URL in any served page (secret-scan test).
- SLO gate green; demo/benchmark unchanged; no new runtime dependencies.

## 4. Docs sweep (main session)

- ROADMAP rows: Basic document ingestion, Basic Git integration, Developer
  setup script, Minimal UI → `[DONE]` with milestone refs. Stage 0 is then
  fully done.
- DECISIONS.md: ADR-020.
- CURRENT_STATE: counts; what-works entries; Stage 0 status line.
- DEPLOYMENT.md: setup-script mention (reproducible env, offline).
- AGENT-SESSION entry.

## 5. Constraints

- No runtime dependencies (git shells out to the installed git; the UI is
  static files). No bundler, no framework, no ORM. Raw SQL only where
  persistence is touched (`capability_requests` methods via tagged
  templates).
- No `as any`/`as never`; chunk content and git output are hostile input —
  whitelist-parsed, never cast.
- No secrets in logs/events/errors.

## 6. Acceptance + skip list

Acceptance: gate green; new suites green; SLO gate green; demo/benchmark
unchanged; Stage 0 rows all `[DONE]`; docs updated.

skipped: write-side Git operations, ingestion pipelines beyond chunking
(OCR, embeddings), UI beyond the task+evidence view, i18n.
add when: a real workflow or customer demands them.

skipped: git fetch/clone over the network (read-only, local repos only) —
add when a task actually needs a remote and the egress proxy has a story
for it.
