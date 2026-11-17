# Fuzz coverage claim needs a structural check

Status: done
Source: mining S3-D0078, shard-3.md.
Repo: `ai-security-layer`.

## Evidence

The H1 issuance fuzz suite is titled "every field extreme refuses"
(`tests/h1-signed-delegation.test.ts:416`), but its `extremes` table has no
case for `constraints` and no case for `singleUse`. The claim is a prose
assertion, not an enumerated contract, so a new `IssueRequest` field can be
added without an extreme case and the suite still reads as complete.

Candidate text: "the fuzz suite claims every field extreme
(tests/h1-signed-delegation.test.ts:258) yet constraints and singleUse have no
extreme cases".

## Action

Add extreme cases for `constraints` (for example an unknown constraint kind, a
constraint that widens the parent, and an empty constraint list) and for
`singleUse` (a non-boolean value and a child that flips the parent's value).
Then add a structural check that enumerates the keys of `IssueRequest` and
fails when a key has no entry in the extremes table.

## Acceptance

- `constraints` and `singleUse` each have at least one refusing extreme case.
- A test fails when a new `IssueRequest` field is added without an extreme
  case, proven by temporarily adding a field and watching it go red.
- The suite title matches what the table actually covers.

## Result

Done 2026-11-17, test-only.

- The fuzz suite is now "every IssueRequest field has an extreme case": 18 rows
  over all 9 keys. Rows may name their own parent, so the constraint cases run
  against a constrained parent.
- Refusing extremes: a child that widens the parent network hosts, a child that
  sends an empty constraint list, and a child that flips a single-use parent to
  non-single-use. The earlier constraint/single-use tests stay.
- A structural test parses the `IssueRequest` interface out of
  `src/capability.ts` and fails when a key has no row. Proven by temporarily
  adding `readonly budget?: number;` (failed with "no extreme case for
  IssueRequest.budget"), then removing it. `src/` is unchanged.
- Not refused today, so marked `carried` instead of claimed as refusals: an
  unknown constraint kind, a non-boolean `singleUse`, an empty `subject`, and
  an unknown `provenance.source` all reach the signed capability. Those rows
  turn red if `src/` starts validating them; closing the gaps needs a src
  change and is out of scope here.
