Status: open
Source: session-audit M14 (commit c9641b8)

## What's wrong

src/rest-sessions.ts:140-145 catches errors from
`CapabilityRequestService.approve()` and maps them to HTTP status codes by
string-matching the error message:
```
if (message.includes('not found')) → 404
if (message.includes('not pending')) → 409
else → 403 capability-request-denied
```
`CapabilityRequestService.approve()` throws plain `Error` objects with
specific messages (src/capability-request.ts:129,130,134,139). If those
messages change, the REST layer silently breaks: a new error message that
doesn't contain 'not found' or 'not pending' becomes a 403, and a message
that happens to contain 'not found' in a different context becomes a 404.
The mapping is correct TODAY but fragile by construction.

## Why it matters

The defect bar (SECURITY_PRINCIPLES.md) classifies "a fallback that
silently disables a control" as a defect. A message change that turns a
409 into a 403 would be a silent control degradation: double-approvals
become capability-request-denied instead of the correct not-pending. Not a
current bug, but a bug waiting to happen on the next error-message edit.

## Minimal fix

Give `CapabilityRequestService.approve()` (and `.deny()`) a typed error
class (e.g. `RequestNotFoundError`, `RequestNotPendingError`) and have
rest-sessions.ts catch on type, not message text. The test at line 497
(double-approve → 409) already pins the behavior; the fix is structural,
not behavioral.
