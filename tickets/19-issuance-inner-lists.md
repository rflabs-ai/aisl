# Ticket 19: issuance shape check does not descend into constraint values

Status: open
Area: security
Source: ticket 18 residual, 2026-11-17.

## Why

`issueCapability` now refuses an unknown constraint kind, but the shape check
only validates the top-level entry. Two malformed values are still signed:

- `{ kind: 'network-host', hosts: [] }` - an empty allowlist.
- `{ kind: 'param-equals', key: '' }` - an empty key.

Neither is a refusal today, and `verifyCapability` has nothing to match. A
capability with an empty allowlist or an empty key is a configuration bug that
should fail at issuance, not at enforcement.

## Done when

- [ ] Issuance refuses an empty `network-host.hosts` list and an empty
      `param-equals.key` with a typed `CapabilityIssuanceError`.
- [ ] The H1 extremes table has a refusing row for each.
- [ ] The structural check still passes.
- [ ] `npm test` is green.

## Notes

Ticket 18 added `issueRequestError` in `src/capability.ts`. Extend it; do not add
a second validator.
