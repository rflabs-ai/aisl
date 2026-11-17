# Issuance signs four malformed values the fuzz table carried

Status: done
Source: ticket 05 result, `tickets/05-fuzz-coverage-structural-check.md`.
Repo: `ai-security-layer`.

## Evidence

Ticket 05 gave every `IssueRequest` key an extreme row but marked four rows
`carried`, because `src/` had no issuance-time check and the malformed value
reached the signed capability. Before this change, in
`tests/h1-signed-delegation.test.ts` at commit `af24278`:

| row | line | value | behavior before |
|---|---|---|---|
| empty subject | 465 | `subject: ''` | signed as the capability subject; never matches a real principal at verify time, but the artifact exists |
| non-boolean singleUse | 506 | `singleUse: 'yes'` | signed truthy; the capability is treated as single-use with a non-boolean field in the signed body |
| unknown constraint kind | 521 | `{ kind: 'file-path', pattern: '**' }` | signed unread: `verifyCapability` takes the `param-equals` fallback branch, where `c.key` is `undefined` and the check passes |
| unknown provenance source | 541 | `{ source: 'bogus' }` | signed; the provenance source is outside `CapabilitySource` and no consumer can act on it |

The constraint row is the dangerous one: it is not inert, it is silently
satisfied. The other three produce capability artifacts the type system says
cannot exist.

Candidate text: "four extreme rows are marked carried because src does not
check them at issuance".

## Decision

Refuse all four at issuance. None is intentionally valid:

- Capability `subject` is the principal the capability is bound to.
  `verifyCapability` compares it to the caller's subject, and no issuance path
  in `src/` (root, delegation, role, approval, REST) uses an empty subject, so
  there is no root case that needs one.
- `singleUse` is a boolean in the signed body; a truthy string is a type
  violation, not a shortcut.
- `Constraint.kind` has exactly two known members. An unknown kind cannot be
  evaluated, and the current fallback treats it as satisfied.
- `CapabilitySource` has exactly four known members. An unknown source makes
  the provenance unauditable.

## Action

`issueCapability` now runs a shape check before the parent and attenuation
checks (`src/capability.ts:167`), using the same `CapabilityIssuanceError` as
the existing issuance refusals. The check is `issueRequestError`
(`src/capability.ts:267`):

- `subject` must be a string with non-whitespace content.
- `singleUse`, when present, must be a boolean.
- Every constraint kind must be in `CONSTRAINT_KINDS`
  (`network-host`, `param-equals`, `src/capability.ts:258`).
- `provenance.source` must be in `CAPABILITY_SOURCES`
  (`src/capability.ts:27`), now the single source of truth for
  `CapabilitySource`.

The public capability shape is unchanged. The four table rows are now
`refuses`; the `carried` outcome was removed from the `Extreme` type and the
loop asserts `CapabilityIssuanceError` for every row. The structural test that
parses `IssueRequest` and requires a row per key is kept
(`tests/h1-signed-delegation.test.ts:540`).

## Acceptance

- Each of the four values throws `CapabilityIssuanceError` from
  `issueCapability` before a capability is signed.
- The extremes table has 18 rows over all 9 `IssueRequest` keys, with zero
  `carried` rows; the suite fails if a key has no row.
- `npm run typecheck` passes.
- `npm test` passes, including `tests/h1-signed-delegation.test.ts`.

## Result

Done 2026-11-17, `fix/issuance-validation`.

- Validation point: `issueCapability` in `src/capability.ts`, after the
  expiry check and before `parentValidityError` and `findOverreach`.
- The four rows flipped from `carried` to `refuses`; the type and test loop no
  longer have a `carried` path.
- File-level suite: 40 tests, 40 pass, 0 fail. Full gate result recorded in the
  commit run.
- Residual: the check validates shape only, not every semantic property. An
  empty `network-host.hosts` list or an empty `param-equals.key` is still
  signed; neither is in the ticket scope and neither is exercised.
