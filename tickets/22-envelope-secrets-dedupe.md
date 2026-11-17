# Ticket 22: envelope-secrets repeats the authorize-and-record tail

Status: open
Area: security and maintainability
Source: ticket 14 follow-up, 2026-11-17.

## Why

Ticket 14 extracted `authorizeAndRecord` in `src/gates.ts`, so NetworkGateway
and SecretBroker share one authorize, append, and return path.
`src/envelope-secrets.ts` still holds a third copy of the same tail. Its
metadata adds `encrypted` and `value`, so it is not a pure duplicate, but the
event fields and the decision mapping are copied.

A field added to one copy and not the others is a silent audit gap.

## Done when

- [ ] `envelope-secrets` uses the shared helper, or the helper moves to a
      module both can import without a cycle.
- [ ] The envelope event keeps its `encrypted` and `value` metadata and every
      existing field.
- [ ] No new dependency cycle: `npm run typecheck` and the dependency-direction
      test pass.
- [ ] The secret and evidence tests are green.

## Notes

Check the import direction first. If `envelope-secrets` is lower-level than
`gates`, move the helper to a shared module rather than importing upward.
