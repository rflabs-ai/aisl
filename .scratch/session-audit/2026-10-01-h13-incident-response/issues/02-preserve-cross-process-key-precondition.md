Status: open

Source: session-audit 2026-10-01, `feat/h13-incident-response` (uncommitted working tree; no commits this session)

## What's wrong

`src/incident.ts:546-547` verifies the whole chain with *this process's* event
signing key — `546: const publicKey = eventPublicKey();` /
`547: const chain = this.eventLog.verify({ publicKey });` —
and `src/incident.ts:257` then hard-fails the bundle when that comes back
false (`if (!bundle.chainValid) errors.push('bundle recorded an invalid live chain at preservation time')`), so `preserve` throws at
`src/incident.ts:571: if (!verification.valid) {` (followed at `:572` by
`throw new IncidentEvidenceError(\`incident bundle failed verification: ...\`)`).

Without `EVENT_SIGNING_*_PEM` (the default — `src/events.ts:314: 'EVENT_SIGNING_*_PEM unset: using ephemeral Ed25519 event signing key (not durable across restarts)',`)
every process has a different key, so the operator CLI — a *different process
from the node that signed the events* — fails closed. Probe: process A's fp
`1c281001bee9d4d6` vs B's `7516b60078d6cb72`; B's verify of A's store:
`valid = false | detail = signature mismatch`; `preserve` threw
`IncidentEvidenceError - incident bundle failed verification: bundle recorded
an invalid live chain at preservation time; offline: seq 0: signature
verification failed`.

Neither the runbook step that promises it
(`DEPLOYMENT.md:396-398: node src/cli.ts incident preserve ... — pages the
authorized audit export past the 1000-event cap, verifies the bundle offline`)
nor the claim headline
(`SECURITY_CLAIMS.md:1635: ## Claim 35 - ... preserved evidence verifies offline (H13)`)
names `EVENT_SIGNING_*_PEM` as a precondition.

## Why it matters

"Cannot preserve evidence" is one of the four ROADMAP H13 failure modes. On a
default deployment the documented incident-runbook preserve step produces no
artifact and an error that never mentions the key — exactly the outcome H13
exists to prevent, during an active incident.

## Minimal fix

Name the precondition where the promise is made: DEPLOYMENT runbook step 5
(+ step 6's `chainValid` output) and Claim 35's known limitations must state
that cross-process preserve/report requires `EVENT_SIGNING_*_PEM` to be set on
both the node and the operator CLI (fail-closed otherwise), and the thrown
message should say so (`... (event-signing key mismatch: set
EVENT_SIGNING_*_PEM on both sides, or verify in-process)`).

## Evidence:

- `node probe-p4a-write.mts` → `P4 process A fp: 1c281001bee9d4d6`
- `node probe-p4b-preserve.mts` → `P4 mixed-signature chain verify (B key): valid = false | detail = signature mismatch`
  → `P4 cross-process preserve: THREW IncidentEvidenceError - incident bundle failed verification: ...`
- ledger rows 15–16 in `.scratch/session-audit/2026-10-01-h13-incident-response/evidence.md`
