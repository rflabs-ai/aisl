Status: open
Source: session-audit 2026-10-01, `feat/h12-secure-updates` (uncommitted working tree) — audit nit F-04

## What's wrong

`update sign` accepts an empty `channel` and writes a signed descriptor that
can never verify. The CLI takes the channel with `??`, which catches only
nullish:

```
cli.ts:1035: const channel = process.argv[5] ?? 'stable';
```

Sign-time validation covers releaseVersion and stages (`cli.ts:1037-1048`),
not channel. `descriptorStructure` then refuses the empty channel at verify
time:

```
updates.ts:157: if (typeof d.channel !== 'string' || d.channel === '') return { reason: 'not-an-update' };
```

So `update sign 1 ""` (or an accidentally empty shell variable) emits
`artifacts/update.json` + `.sig` that `update verify`/`apply` will refuse
forever with `not-an-update`.

## Why it matters

A signed release artifact that is structurally invalid is a footgun: the
operator signs a release, ships it, and the target refuses it with a reason
that does not name the actual mistake (`channel`). Fail-closed is correct;
the sign side just shouldn't produce it.

## Minimal fix

After `const channel = ...`, refuse empty/whitespace:
`if (channel.trim() === '') { error 'channel must be non-empty'; exit 1; }`
— or run the built descriptor through the same structural check the verifier
uses before signing.

## Evidence

Code read, this run: `cli.ts:1035` (above) and `updates.ts:157` (above); no
channel validation exists between them (stage validation only at
`cli.ts:1037-1048`). Behavioral note: not probe-run (sign needs a real key +
fresh manifest); the two citations are the finding.
