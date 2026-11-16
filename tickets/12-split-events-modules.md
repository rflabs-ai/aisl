# src/events.ts carries hashing, signing, bundles, and the log in one file

Status: open
Source: code-health snapshot 2026-11-13, score model v2.
Repo: `ai-security-layer`.

## Evidence

`src/events.ts` is 714 lines and 41 functions: 128 duplicated lines, LCOM4 1/1
(the `EventLog` methods split into disjoint field groups), max CCN 24, max
cognitive 34. Per-file score 3.38, the worst file in the repo.

The duplication sits in the verify paths: `verifyChain`, `bundleFromEvents`,
and `verifyBundle` each parse a bundle, walk the chain, and re-check the same
fields. Because the checks are copied, a new rule has to be added in three
places or one path silently lags.

## Action

Split into `src/events/`:

- `hash.ts` - `eventBody`, `eventHash`, `signatureBody`
- `sign.ts` - `eventSigningKeyPair`, `signEventBody`, `verifyEventSignature`
- `bundle.ts` - `bundleFromEvents`, `verifyBundle`, `verifyChain`
- `log.ts` - `EventLog`, `StoreUnavailableError`
- `timestamps.ts` - `collectTimestampAnomalies`

Keep `src/events.ts` as a re-export barrel in the same change so no importer
moves. Dedupe the three verify walks behind one internal helper, with the
public functions calling it.

## Acceptance

- A fixed event fixture produces a byte-identical bundle before and after.
- `tests/*events*`, `tests/*tamper*`, and the H11 suite are green.
- The H8 probe rows for event-store reads and the global chain are unchanged.
- jscpd duplicated lines for the `events` group drop by at least half.
- No exported symbol disappears from `src/events.ts`.
