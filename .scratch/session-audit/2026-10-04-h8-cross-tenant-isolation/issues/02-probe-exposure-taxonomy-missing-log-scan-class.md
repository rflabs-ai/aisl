Status: resolved (f61817e)
Source: session-audit 2026-10-04 (H8 cross-tenant isolation, feat/h8-cross-tenant-isolation)

## What's wrong

The probe's `exposure` union has two labels (`'enforced' | 'global-by-design'`),
but ADR-030 defines three assertion classes — isolation, log-scan property,
and global-by-design — and rows that assert only the log-scan/no-leak property
are labelled `enforced`:

- `DECISIONS.md:2191: of: (a) isolation in both directions, (b) a log-scan property (no foreign`
- `tests/h8-cross-tenant-probe.test.ts:401` `id: 'rest-healthz-and-static-page',` with `:403 exposure: 'enforced',` — the row asserts only marker absence in the healthz body and the static page.
- `tests/h8-cross-tenant-probe.test.ts:623` `id: 'log-scan',` with `:625 exposure: 'enforced',`.

## Why it matters

Code labels and the ADR vocabulary disagree; run output shows `[enforced]` on
no-leak-only rows, which can mislead a reviewer scanning the probe report.

## Minimal fix

Add `'log-scan'` to the `ProbeCase.exposure` union and the file-header class
comment, and relabel the `rest-healthz-and-static-page` and `log-scan` rows.

## Evidence

- `Select-String tests\h8-cross-tenant-probe.test.ts -Pattern "id: 'rest-healthz","id: 'log-scan'"` → `401: id: 'rest-healthz-and-static-page',` / `623: id: 'log-scan',`
- `Select-String DECISIONS.md -Pattern 'log-scan property'` → `2191: of: (a) isolation in both directions, (b) a log-scan property (no foreign`
