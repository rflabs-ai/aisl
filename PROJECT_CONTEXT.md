# PROJECT_CONTEXT

Reconnaissance and working context for the repository, recorded before any
substantial code was written and updated as the foundation landed. The live
snapshot — counts, test totals, known gaps — is `CURRENT_STATE.md`; this file
holds the stable map.

## 1. Repository state at start

| Item | Finding |
| --- | --- |
| Git | Initialised, **zero commits**, single branch, no remote |
| Source files | None |
| Existing docs | `initial-idea-CONTEXT.md` (87 KB: the project brief) |
| Package manager | None (no `package.json`) |
| Build system | None |
| Test framework | None |
| Language | None |
| Deployment assumptions | None |
| OS assumption | Windows (win32) development workstation |

Everything in this repository except `initial-idea-CONTEXT.md` was created in
this session.

## 2. Environment discovered

| Tool | Version / status |
| --- | --- |
| Node.js | v24.18.0 |
| npm | 11.16.0 |
| pnpm | present |
| Python | 3.11 (not used) |
| Docker | present — used by the M1 container sandbox when available; falls back to in-process |
| PostgreSQL | **not installed locally** |
| Bun / Deno / Go | absent |

Node 24 gives three things that shaped the foundation:

1. **Native TypeScript execution** (type stripping, no build step, no `tsc` in
   the run path).
2. **`node:test`** — a capable built-in test runner with no dependency.
3. **`node:sqlite`** — a built-in durable store for the evidence plane.

Together these mean the security substrate runs with **one runtime dependency**
(`jose` — JWT/JWK verification, ADR-015); everything else is Node built-ins.
For a system whose trust story depends on what it does *not* include, that is a
property worth buying.

## 3. What was built

```text
src/
  domain.ts           shared vocabulary; ActionRequest (intent) vs Capability (authority)
  policy.ts           policy-as-data evaluator: default deny, deny-overrides, idPatterns
  capability.ts       capability minting, HMAC signing, attenuation, verification
  events.ts           hash-chained, signed, append-only audit log (+ SQLite persistence)
  pdp.ts              policy decision point: capability AND policy, auth required, fail closed
  registry.ts         resource registry, data ingestion, injection telemetry (not a control)
  model.ts            model gateway: whitelist parser for untrusted provider output
  runtime.ts          policy enforcement point: agent session, tool + sandbox seams, guard wiring
  gates.ts            network egress gateway, secret broker
  verification.ts     verification plane: post-execution checks, evidence records
  identity.ts         OIDC token verification (jose), sessions, revocation, IdP health
  session-manager.ts  session binding: capabilities + approvals attach to an authenticated human
  seal.ts             AES-256-GCM per-classification sealing of output content
  envelope-secrets.ts envelope-encrypted secret broker (HKDF per-secret DEKs)
  container-sandbox.ts Docker-backed tool isolation, LocalSandbox fallback
  sandbox-runner.ts   sandbox execution seam used by the runtime
  egress-proxy.ts     HTTP proxy enforcing PDP egress decisions
  audit-query.ts      authorized, tenant-scoped evidence query/export service
  policy-testing.ts   simulate / diffDecisions / loadFixtures policy harness
  policy-diff.ts      `npm run policy:diff` entry point
  guard.ts            output reliability layer: D2-D5, fallback ladder, sealed originals
  capability-request.ts agent request -> human approval -> narrow capability (M4)
  policy-config.ts    versioned, hash-verified policy/role bundles (M11, Claim 26)
  model-http.ts       OpenAI-compatible provider adapter + classification egress gate (M13, Claim 27)
  check-command.ts    allowlisted argv command checks for the verification plane (M13)
  telemetry.ts        TelemetryPort + zero-dep JSONL sink; observability, never a control (M13, Claim 28)
  persistence.ts      Postgres control-plane state tables + tenant-bound CRUD (M12)
  event-store-pg.ts   Postgres EventStore backend + forward-only migrations (M12)
  tenant-rls.ts       FORCE-RLS migration for security_events (M12)
  rest-api.ts         node:http whitelist REST router + bearer-JWT authn (M14, ADR-019)
  rest-sessions.ts    /v1/sessions + /v1/capability-requests routes (M14)
  rest-audit.ts       /v1/audit + /v1/tasks routes (M14)
  rest-anchors.ts     /v1/anchors federation anchor registration (M17)
  ingestion.ts        deterministic document chunking + sealed ingest events (M15)
  git-reader.ts       read-only allowlisted git verbs (M15)
  sandbox-registry.ts sandbox lifecycle: create/limit/destroy/attest (M16)
  supply-chain.ts     SBOM gate + signed build manifests (H10, ADR-024)
  updates.ts          signed update channel, anti-rollback mark, canary halt (H12, ADR-025)
  incident.ts         kill switch + revocation channel + evidence preservation (H13, ADR-026)
  incident-store-pg.ts Postgres revocation channel + migration 4 (H13, ADR-026)
  health.ts           fail-closed availability: observed health + clock guard (H15, ADR-027)
  anchors.ts          external anchor sinks + multi-source reconciliation + signed checkpoints (H11, ADR-031)
  retention.ts        recorded legal holds replayed from the event log (H11, ADR-031)
  slo.ts              assurance-target catalog + gate (ADR-014, M10)
  attacks.ts          declarative adversarial harness
  adversarial.ts      H14 lanes: corpus/drift/differential + digest baseline (H14, ADR-033)
  policy-analysis.ts  policy conflict/dead-rule analysis + on-load refusal (H3, ADR-034)
  mutation.ts         policy mutation lane against the golden set (H14, ADR-035)
  taint.ts            one-directional data-flow labels carried across session steps (H4, ADR-036)
  dlp.ts              content-level egress DLP: canaries, encodings, byte cap (H7, ADR-037)
  tool-protocol.ts    tool declarations, schema/param validation, mandatory provenance (H6, ADR-039)
  tool-manifest.ts    tool declarations as data, strict binding (ADR-040)
  artifacts.ts        artifact admission: sniff, mismatch, quarantine, tenant bound (H9, ADR-041)
  scenario.ts         assembled MVP world (shared by demo, tests, benchmark)
  cli.ts              demo | attack | benchmark | build | update | incident | evidence
  testing.ts          test wiring only

tests/             unit + integration + the 12 security invariants + milestone suites
security-tests/    adversarial suites (attack corpus, guard invariants, model compromise)
security-attacks/  12 declarative attack cases (JSON)
security-fixtures/ legitimate-task cases + document corpus
threat-models/     per-boundary threat models
benchmarks/        measured results (results.json, incl. the gated slo block)
```

## 4. How to run

```bash
npm install                 # only to get typescript + @types/node for typechecking
npm test                    # assertions across unit, integration, security tests (see CURRENT_STATE.md)
npm run typecheck           # tsc --noEmit
npm run demo                # MVP acceptance walkthrough (section 23 of the brief)
npm run attack              # adversarial harness
npm run benchmark           # writes benchmarks/results.json; exits nonzero on a hard assurance-target miss
```

Requires Node >= 22.5. `CAPABILITY_SIGNING_KEY` should be set; without it the
system generates an ephemeral key and emits a warning (fail-closed still holds,
capabilities just are not portable across restarts).

## 5. Conventions

- TypeScript, ESM, **erasable-syntax only** (no enums, no parameter properties,
  no decorators) so the runtime stays buildless.
- Explicit `.ts` import extensions.
- Immutable data: capabilities and events are replaced, never mutated.
- Every module states which invariant it enforces. If a module enforces none, it
  is a seam or a fixture, and it says so.
- No dependency is added without an ADR.

## 6. Non-goals for this stage

Containers, microVMs, Kubernetes, a UI, a real model provider, a real network
proxy, a real secret store, multi-node anything. The seams exist; the
implementations are deliberately trivial and are labelled as such.

(Stage note: M1 has since made the container sandbox, egress proxy, and
envelope secrets real; the remaining rows are still non-goals. The authoritative
status list is ROADMAP.md.)
