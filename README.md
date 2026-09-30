# AI Security Layer (ASL)

A high-assurance execution environment for AI agents.

The premise is one sentence:

> **The model is not the authority. The infrastructure is.**

ASL lets a capable model act on sensitive code, documents, and data while an
infrastructure layer — not the model's good behavior — decides what it may
actually do, executes it in a controlled environment, and records evidence of
every decision.

## The one boundary that matters

Two types, never convertible:

| Type | Meaning | May be produced by |
| --- | --- | --- |
| `ActionRequest` | intent — "I want to do X" | a model, a document, a tool |
| `Capability` | authority — "I may do X" | exactly one function, `issueCapability` |

A capability is minted in one place (`src/capability.ts`) and that function's
first act is to reject any issuer whose kind is `model`, `tool`, or `agent`.
Hostile text therefore has no parser from text to authority to attack. Nothing
executes without **capability AND policy** both passing, through a single
enforcement path (`AgentSession.attempt`).

See `ARCHITECTURE.md` §2 for the full boundary and `docs` links below for the
rest of the story.

## What it does

- **Identity (M2):** OIDC/OAuth2 verification via `jose`, MFA enforced for
  approvals and session creation, sessions bound to an authenticated human.
- **Authorization:** policy-as-data evaluator (default deny, deny-overrides,
  hierarchical resource matching), capability minting / signing / attenuation /
  revocation, RBAC roles as first-class data, signed delegation chains.
- **Enforcement:** one path for every agent action; container sandbox with
  non-root, read-only rootfs, no network namespace, seccomp, resource limits.
- **Gates:** network egress proxy and encrypted secret broker, both PDP-gated.
- **Model gateway:** provider-agnostic port; untrusted output through a
  whitelist parser; a classification egress gate on every provider call.
- **Verification + evidence:** post-execution checks; a hash-chained,
  Ed25519-signed, append-only event log with per-classification sealed content,
  head-hash anchor, offline bundle verification, and authorized audit query.
- **Reliability:** output guard (evidence-bound claims, fallback ladder,
  sealed originals) so the text channel is constrained too.
- **Platform:** REST API (`node:http` whitelist router), Postgres control plane
  with RLS-enforced tenant isolation + per-tenant evidence keys, backup/restore,
  document ingestion, read-only Git integration, and a zero-dependency UI.

## Quick start

Requires **Node.js >= 22.5** (uses native TypeScript execution, `node:test`,
`node:sqlite` — no build step).

```bash
npm install                 # devDeps only: typescript + @types/node
npm run typecheck           # tsc --noEmit
npm test                    # unit + integration + security suites
npm run demo                # MVP acceptance walkthrough
npm run attack              # adversarial harness
npm run benchmark           # writes benchmarks/results.json; exits nonzero on a hard SLO miss
```

Optional environment:

- `CAPABILITY_SIGNING_KEY` — without it an ephemeral key is generated and a
  warning is emitted (fail-closed still holds; capabilities just don't survive
  restarts).
- `EVENT_STORE=postgres` + `DATABASE_URL` — opt into the Postgres event backend.
  Ambient `DATABASE_URL` alone flips nothing.

Convenience setup: `scripts/setup.ps1` (Windows) or `scripts/setup.sh`; pass
`-WithPostgres` / `--with-postgres` to bootstrap a Postgres 16 container.

## Running ASL

ASL is a **library + proof suite**, not a running service. There is no
start/daemon command today — the commands above are the whole surface. The M14
REST API (`createRestApi`) exists and is fully exercised by the test suite, but
it is wired to an HTTP server **only in tests**; there is no production
entrypoint yet. Cross-repo federation (control-plane as an ASL client,
ADR-022) is **opt-in and currently off**; turning it on is what would require a
`serve` command, which is not built. For how to run every project in this stack
(start/stop/status/ports, on-demand vs always-on), see
`../shared-docs/RUNBOOK.md`.

## Status

Stage 0 (conventional engineering) is **[DONE]**, and Stage 1/2 milestones
(M2–M17, H1, H10) have landed. The system is a **foundation, not a product** —
the seam exists everywhere, but several implementations are deliberately
trivial and labelled as such. Where a component is a stub, the docs say so.

Honest current gaps are listed in `CURRENT_STATE.md` under *Known
vulnerabilities and gaps* and mirrored as limitations in
`SECURITY_CLAIMS.md`. Do not mistake the attack corpus (12 cases, written by
the same author as the code) for evidence of security against a competent
adversary.

## Documentation

| Document | What it is |
| --- | --- |
| `ARCHITECTURE.md` | Planes, trust boundaries, request lifecycle, extension seams |
| `SECURITY_CLAIMS.md` | Every claim, its mechanism, test, and known limitation |
| `THREAT_MODEL.md` | Assets, actors, boundaries, per-boundary threat models |
| `SECURITY_PRINCIPLES.md` | The bar: zero trust, least privilege, fail closed, … |
| `CURRENT_STATE.md` | Live snapshot: what exists, what works, what failed, what's missing |
| `ROADMAP.md` | EASY → IMPOSSIBLE+ plan with status markers |
| `DECISIONS.md` | Architecture decision records (ADRs) |
| `COMPLIANCE.md` | Mappings to NIST CSF/800-53/800-207, OWASP, SOC 2, ISO 27001, HIPAA |
| `RELIABILITY.md` | Output guardrails and the fallback ladder |
| `DEPLOYMENT.md` | Deployment shapes, hardware tiers, operating model |
| `PROJECT_CONTEXT.md` | Stable repository map (the live snapshot lives in CURRENT_STATE) |
| `AGENTS.md` | Build discipline for contributors and agents |
| `initial-idea-CONTEXT.md` | The original product brief this repository distills |

## Contributing

`AGENTS.md` is the contract. Short version: grep every caller before editing,
write the failing test first, one seam at a time, one structural invariant test
per new trust boundary, and land only after `npm run typecheck && npm test`
passes. No runtime dependency without an ADR. No secrets in logs, events, or
error messages.

## Runtime dependencies

Two, both exact-pinned and admitted by ADR: `jose` (JWT/JWK verification,
ADR-015) and `postgres` 3.4.9 (Postgres event backend, ADR-018). Everything else
is a Node built-in. For a system whose trust story depends on what it does *not*
include, that is a property worth buying.
