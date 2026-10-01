Status: resolved (7c30aad)
Source: session-audit 2026-10-01, `feat/h12-secure-updates` (uncommitted working tree) — audit nit

## What's wrong

`createPublicKey` (a `node:crypto` builtin) is imported after the local
imports in `src/cli.ts`, unlike every other builtin:

```
cli.ts:11: import { mkdirSync, mkdtempSync, readdirSync, readFileSync, rmSync, writeFileSync, existsSync } from 'node:fs';
cli.ts:12: import { dirname, join } from 'node:path';
cli.ts:13: import { tmpdir } from 'node:os';
cli.ts:14: import { fileURLToPath } from 'node:url';
cli.ts:15: import { runAttackCorpus } from './attacks.ts';
...
cli.ts:58: import { createPublicKey } from 'node:crypto';
```

## Why it matters

Style/consistency only — no behavior. Builtins grouped at the top is the
existing file convention; a stray builtin below the local block reads as an
accident and will be copied as one.

## Minimal fix

Move `import { createPublicKey } from 'node:crypto';` into the builtin block
(after line 14). No other change.

## Evidence

`Read src/cli.ts` lines 10-21 and `Select-String -SimpleMatch "import { createPublicKey }"` (both this run), quoted above.
