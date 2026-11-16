# Fuzz coverage claim needs a structural check

Status: open
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
