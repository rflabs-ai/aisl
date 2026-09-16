# AGENTS

Project-level instructions for every session in this repo.

## Build discipline

Every non-trivial change follows this ritual. No exceptions.

### Before writing code

1. **Grep every caller** of the function/module you're about to touch. The bug is
   usually in a caller you didn't know existed, not in the code you're editing.

2. **Write the test that should fail** before writing the code that makes it pass.
   The test defines the contract. The code fills it in.

### While building

3. **One seam at a time.** Land the smallest change that proves the seam works,
   then expand. Each commit must be bisectable and green.

4. **One structural invariant test per new trust boundary.** If a new module
   touches secrets, network, capabilities, or the event log, add a test that
   asserts the boundary holds (e.g., "context has no secret values", "event log
   has no plaintext").

### Before committing

5. **Run the gate:**
   ```
   npm run typecheck && npm test
   ```
   Both must pass. No exceptions. No "it passes on my machine."

6. **Scan ponytail debt.** Grep for `ponytail:` in changed files. Every new
   marker must name a ceiling AND an upgrade path. Markers with no trigger rot.

7. **Read SECURITY_CLAIMS.md** for the claims your change affects. Does the
   new code actually close the limitation you claim? If not, update the claim
   or don't ship.

### After the milestone

8. **Update CURRENT_STATE.md.** Move items off known-vulnerabilities only when
   a test proves they are closed. Add new gaps introduced by the milestone.

9. **Run `npm run demo && npm run benchmark`** and verify the output is sane.

## What this project does NOT do

- No runtime dependencies without an ADR.
- No `as any`, `as never`, or type casts that hide errors at trust boundaries.
- No secrets in logs, event output, or error messages.
- No commented-out code. Delete it or document why it stays.
- No abstractions with one implementation. The seam IS the abstraction.
