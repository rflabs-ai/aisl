Status: open
Source: session-audit M15 fix commit 465b67b + M16 prompt handoff

## What's wrong

PROMPTS/M16-sandbox-lifecycle.md:31 claims `ContainerSandbox` already takes
`memoryBytes` / `cpuShares` in its constructor. The actual
`ContainerSandboxOptions` (src/container-sandbox.ts:53-59) are
`memoryLimit?: string`, `cpuPeriod?: number` + `cpuQuota?: number`,
`pidsLimit?: number`, `timeoutMs?: number`.

## Why it matters

M16's next session codes against the prompt; nonexistent param names mean a
confused first compile and either a rename of real options (drift) or a
parallel limits type that doesn't bind to Docker's flags.

## Minimal fix

Correct the prompt to the real option names (`memoryLimit` docker-format
string, `cpuPeriod`/`cpuQuota`, `pidsLimit`), or rename the options in a
dedicated commit if the M16 ADR-021 wants byte/quota semantics — but the
prompt must not name APIs that do not exist.
