# SECURITY PRINCIPLES

Each principle below is followed by the mechanism that implements it, the code
that enforces it, and the test that would fail if it were removed. A principle
with no mechanism is a slogan; there are none here.

## Zero Trust

Nothing is trusted by default: not the model, not the document, not the tool,
not the session, not the network.

- **Mechanism**: every action passes `AuthorizationService.authorize`. There is
  no "already checked" path and no cached decision.
- **Code**: `src/pdp.ts:113`, `src/runtime.ts:133`.
- **Test**: `tests/invariants.test.ts` — invariants 1, 9, 12.

## Least Privilege

- **Mechanism**: capabilities name explicit `resourceIds` and `actions`, carry a
  `maxClassification` ceiling, an expiry, and optional constraints.
- **Code**: `src/capability.ts:39` (shape), `src/capability.ts:217` (checks).
- **Test**: invariants 1, 5, 11.

## Capability-Based Authority

- **Mechanism**: scoped, signed, expiring capabilities instead of broad
  credentials. Single-use is available and is consumed on execution.
- **Code**: `src/capability.ts:128` (mint), `src/pdp.ts:96` (consume).
- **Test**: `tests/capability.test.ts` — signature tampering, single-use,
  constraints.

## Separation of Duties

- **Mechanism**: approval is a separate record (`Approval`) that a rule may
  require; issuing a capability and executing an action are distinct operations
  performed by distinct principals.
- **Code**: `src/policy.ts:53` (`requiresApproval`), `src/pdp.ts:70`.
- **Test**: `tests/policy.test.ts` — approval-gated rules; demo step 8/9.

## Defense in Depth

- **Mechanism**: an action must clear resource existence, tenant, capability,
  signature, expiry, scope, classification, constraints, and policy. Compromise
  of one check does not grant access.
- **Code**: `src/pdp.ts:147` -> `src/capability.ts:217` -> `src/policy.ts:137`.
- **Test**: `tests/invariants.test.ts` invariant 1 ("capability alone is not
  enough") — a valid capability for a policy-denied action is still denied.

## Fail Closed

- **Mechanism**: default deny at the engine; any thrown error inside
  `evaluate()` becomes a deny; unknown classifications rank at the ceiling;
  unknown resources are denied.
- **Code**: `src/policy.ts:131` (`NO_MATCH`), `src/pdp.ts:212`,
  `src/domain.ts:70` (unknown classification rank 100).
- **Test**: invariant 12; `tests/policy.test.ts` unknown-classification case.

## Explicit Trust Boundaries

- **Mechanism**: B1–B10 enumerated in `ARCHITECTURE.md` §4, each with an
  enforcement point and a stated failure direction. B10 (operator -> policy) is
  documented as open rather than assumed away.

## Data Classification

- **Mechanism**: `Classification` is extensible (`KnownClassification | string`),
  ranked, and enforced at both the capability ceiling and the policy rule
  ceiling. Unrecognised labels rank at maximum, so new domains fail closed.
- **Code**: `src/domain.ts:57`, `src/capability.ts:239`, `src/policy.ts:117`.
- **Test**: `tests/policy.test.ts` — unknown classification is denied.

## Model Agnosticism

- **Mechanism**: the model is behind `ModelPort` (`src/model.ts:26`). Nothing in
  the security path depends on a vendor, a model family, or the model's
  behaviour. `ScriptedModel` and `compromisedModel` are interchangeable.
- **Test**: `security-tests/model-compromise.test.ts` — the same suite runs
  against a model assumed to be hostile.

## DATA != AUTHORITY (the central invariant)

- **Mechanism**: `ActionRequest` cannot carry authority; `Capability` can only
  be minted by `issueCapability`, which rejects `model`, `tool`, and `agent`
  issuers; model output is parsed through a field whitelist.
- **Code**: `src/domain.ts:109`, `src/capability.ts:134`, `src/model.ts:42`.
- **Test**: invariants 2, 3, 4; the entire attack corpus.

## Accounting and Evidence

- **Mechanism**: every decision appends an event; events are chained by
  SHA-256 over canonical JSON; `verify()` detects mutation.
- **Code**: `src/events.ts:45`, `src/events.ts:119`.
- **Test**: invariants 7, 8.

## Claim Discipline

- **Mechanism**: no claim exists without a test. `SECURITY_CLAIMS.md` lists
  every claim the platform makes and the test that backs it. Numbers in
  `benchmarks/results.json` are produced by a run, never written by hand.
