# Safety ticket 03 — git history clear

**Status:** closed with one accepted risk, 2026-11-01
**Evidence:** [`../SAFETY-2026-11-01.md`](../SAFETY-2026-11-01.md), gate 3

- [x] 135 commits scanned for secret-shaped strings — **0 findings**
- [x] No `.env`, `.pem`, `.key` or `.p12` ever added in any commit
- [x] No credential-shaped material in commit messages
- [x] Personal data in history identified: local absolute paths inside `.scratch/` evidence

## Accepted risk (decided before first push, as required)

`.scratch/` evidence files contain `C:\Users\<user>\...` paths from captured test
output. A Windows username is already public in the project's own documentation
and is not a credential. **Decision: accept, do not rewrite history.**

Reopen this decision only if the published surface changes (for example, if the
repository becomes a commercial product with a legal entity behind it). The
alternative — publishing a squashed `v1` — remains available and must be chosen
*before* the first public push, never after.

## Done when

Either (a) the tree ships without `.scratch/` and this decision is stated in the
release notes, or (b) a squashed `v1` is published and this ticket is superseded.
