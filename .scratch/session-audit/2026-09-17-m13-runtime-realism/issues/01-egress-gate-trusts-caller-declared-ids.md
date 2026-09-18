# Egress gate classifies by caller-declared ids, never by the content actually sent

Status: resolved (2026-09-17)
Source: session-audit 440ba58..89ec9db

Resolution: the proposed value-scan is subsumed by existing behavior —
`deriveClassification` already takes the max over the WHOLE content map, so
map-covered confidential content with undeclared ids was always refused
(regression tests added pinning it). The real residual was a missing content
map: `complete()` now fails closed (`egress: 'refused-unclassifiable'`) when
context is non-empty and no map exists. Text absent from the map is free text
— same class as `prompt`, unclosable at this seam without content-level DLP
(H7) — so Claim 27's limitations were narrowed to say exactly that, per this
issue's alternative path. Hostile ingested text MUST stay sendable (actions
are gated, not content), which rules out deny-on-unmatched.

## What's wrong

`src/model-http.ts:128-133` derives the egress classification from
`input.contextResourceIds` and the adapter's `content` map — it never inspects
the `input.context` strings that are about to be POSTed (`model-http.ts:252`
sends them verbatim). A caller that passes above-ceiling text as `context`
without declaring its resource ids, or that constructs the adapter without a
matching `content` map, sends that text through the gate unexamined. Today the
only path that sets `contextResourceIds` is `AgentSession.run()`
(`src/runtime.ts:287`); a direct `adapter.complete({...})` caller — which the
demo itself does at `src/cli.ts:443-448` — controls the classification input.
`tests/model-http.test.ts` has no case for above-ceiling content arriving with
NO ids.

The M13 spec (`PROMPTS/M13-runtime-realism.md` §2.2) says the ceiling is
enforced "over the content being sent (reuse deriveClassification over the
prompt/context)". The implementation gates over ids, not over content.
`SECURITY_CLAIMS.md:1068` (Claim 27) claims "A provider receives nothing above
the configured classification ceiling" — unconditionally — and its limitations
block names only the coarse-derivation and in-document-canary gaps, not this
caller-declared-ids bypass. AGENTS.md step 7: if the code doesn't close the
claim, fix the claim or don't ship it.

## Why it matters

This is the milestone's security control. "Default-deny, never bypassable by
config" is true of the *configuration*, but the gate's input is *input data*
the caller supplies. Under the project's own doctrine (the model is hostile,
the runtime is the trusted assembly point), any disclosure control whose
classification input is supplied by the thing doing the disclosing is a hole,
and the claim text is already overclaiming relative to what the tests prove.

## Minimal fix

In `HttpModelAdapter.complete`, before the ceiling check: for each string in
`input.context`, look it up by value in `this.cfg.content` (and flag when
`cfg.content` is absent/uncovered), and fold every classification of a matching
resource — plus the classifications of `contextResourceIds` — into the derived
label. Fail closed when a context string matches a registry resource above the
ceiling that the caller did NOT declare. Add one test: same confidential text
in `context` with `contextResourceIds: []` → refused, fetch not called. If the
value-scan is deemed too coarse, the alternative is to narrow Claim 27 to
"nothing classified above the ceiling via the session's content map and
declared context ids is sent", and record the bypass as a limitation.
