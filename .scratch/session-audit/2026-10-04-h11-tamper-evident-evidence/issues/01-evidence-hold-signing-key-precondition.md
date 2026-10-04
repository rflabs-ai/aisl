# Ticket 01 — `evidence hold`/`release` lacks the cross-process signing-key precondition H13 enforces

Status: open
Source: session-audit b3e345b..HEAD (H11, ADR-031)

## What's wrong

On the Postgres CLI path (`EVENT_STORE=postgres` + `DATABASE_URL`), the
`evidence hold` and `evidence release` commands append to the shared evidence
chain through a fresh CLI process without any event-signing-key precondition:

- `src/cli.ts:1916-1917` — `const ledger = new RetentionLedger(world.eventLog); const hold = ledger.hold(world.user, { tenantId, fromSeq, toSeq, reason });`
- `src/cli.ts:1929-1930` — same pattern for `release`.

Without `EVENT_SIGNING_*_PEM` set on that process, `events.ts:355` warns
`'EVENT_SIGNING_*_PEM unset: using ephemeral Ed25519 event signing key (not
durable across restarts)'` (`src/events.ts:343` reads the env) — so the
appended hold event carries a signature the deployment's key can never verify.
H13 solved the identical problem for `incident preserve` by refusing
fail-closed with an actionable hint:

- `src/incident.ts:765` — `chain.detail === 'signature mismatch' && !process.env.EVENT_SIGNING_PUBLIC_KEY_PEM`
- `src/incident.ts:766` — `? ' (event-signing key mismatch: set EVENT_SIGNING_PRIVATE_KEY_PEM + EVENT_SIGNING_PUBLIC_KEY_PEM on the signing node and in this process, or preserve in the signing process)'`
- `src/incident.ts:768` — `throw new IncidentEvidenceError(...)`.

DEPLOYMENT.md:490-492 documents that precondition for the incident `preserve`
path only; the H11 section's hold/release runbook carries none.

## Why it matters

One operator CLI invocation silently degrades Claim 19's per-event
attribution on the shared chain: the hash chain stays valid (so the node still
opens and appends), but `verify({ publicKey })` reports a signature mismatch
for the hold event — exactly the ambiguity a tamper-evidence plane must not
introduce. H13 named this failure mode and made it loud; H11's new append path
regressed the posture.

## Minimal fix

Mirror H13: in the `evidence hold`/`release` CLI branches (Postgres mode),
before appending, verify the chain under the local public key (or check the
`EVENT_SIGNING_*_PEM` precondition) and refuse with the same actionable hint;
add the precondition line to DEPLOYMENT.md's H11 runbook section.

## Evidence

Ledger rows E06-E09 (`.scratch/session-audit/2026-10-04-h11-tamper-evident-evidence/evidence.md`),
all from `git show HEAD:<path>` in this audit run. Scope note: the behavioral
claim is about the PG CLI path (no live-DB probe was possible in this run — no
`DATABASE_URL`); the in-process path is unaffected (same-process key).
