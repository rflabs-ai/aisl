# TM-001 — Compromised or hostile model

## Scope

The reasoning component behind `ModelPort` (`src/model.ts:26`). Includes a model
that is actively malicious, a model that is manipulated by its input, a model
that is simply wrong, and a hostile provider response.

## Adversary

The model, or whoever controls it. Full knowledge of the prompt, the tool list,
and the policy. No access to infrastructure.

## Entry points

1. `ModelPort.complete()` return value — the only channel.
2. Model-influenced parameters (`params`) on an otherwise valid request.

## Attack paths

| Path | Expected outcome |
| --- | --- |
| Request an action with no capability | denied (`no-capability`) |
| Request `capability.issue` | denied; model is not an issuer |
| Hallucinate a resource id | denied (`unknown-resource`) |
| Retry a denied action N times | denied every time, logged every time |
| Read above the capability ceiling | denied (`classification-ceiling`) |
| Manipulate `params` past a constraint | denied (`capability-scope`) |
| Emit authority-shaped JSON in output | dropped by `parseModelOutput` whitelist |

## Controls

- `parseModelOutput` (`src/model.ts:42`) constructs a fresh object from a
  whitelist of fields; unrecognised keys are discarded.
- `AgentSession.attempt` re-authorizes every request; no decision is cached.
- Model output is never an argument to `issueCapability`.

## Assumptions

- The runtime process itself is not compromised.
- The attacker cannot edit the policy set (B10).

## Failure modes

- Detection gap: a model that never requests anything (refusal) is a
  availability failure, not a security failure. Not currently detected.
- A policy that is too permissive converts model misbehaviour into real access.

## Test methodology

`security-tests/model-compromise.test.ts` — ten hostile behaviours, each asserted
to be denied and non-executing. Retry case asserts 50 separate audit events.

## Residual risk

If an operator issues a capability broad enough to cover the abuse, the model's
request is legitimate by definition. Capability scope, not model behaviour, is
the binding constraint — which is the design intent, and also the limit.
