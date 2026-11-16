# NetworkGateway and SecretBroker repeat the same authorize-and-record block

Status: open
Source: code-health snapshot 2026-11-13, score model v2.
Repo: `ai-security-layer`.

## Evidence

`src/gates.ts` is 162 lines with 73 duplicated lines, 45% of the file, and a
per-file score of 8.14. There are two classes and they carry the same three
collaborators, the same constructor shape, and the same tail:

- `NetworkGateway.request` authorizes, appends an event with the same eight
  fields, and maps the decision to a result (lines 59-81).
- `SecretBroker.request` does the same with a different action and metadata
  (lines 138-160).

The event append is a security record, so a field added to one copy and not
the other is a silent audit gap.

## Action

Extract one internal helper that takes the principal, action, resource, and
metadata, calls `authorization.authorize`, appends the decision event, and
returns the decision. Both gates call it. Keep the `metadata.phase` strings
(`network-gateway`, `secret-broker`) exactly as they are, because tests and
audit queries read them.

## Acceptance

- jscpd duplicated lines for `src/gates.ts` fall under 10%.
- Invariants 10 and 11, the egress tests, and the secret-break-glass test are
  green.
- The recorded event for a network allow and a secret deny is field-for-field
  identical to today's output.
- No change to who sees the secret value; only the broker returns it.
