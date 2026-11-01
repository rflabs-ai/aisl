# Security policy

## Reporting a vulnerability

**Do not open a public issue for a security problem.**

Use GitHub's private vulnerability reporting on this repository:
**Security → Report a vulnerability**. That opens a private advisory visible only
to the maintainers.

If that is unavailable, email the maintainer at the address on the GitHub profile
for `@kcpatterson`, with `AISL` in the subject line.

### What to include

- The version or commit you tested, and how you ran it.
- A reproduction: the smallest sequence of calls that shows the problem.
- What you expected, and what happened.
- Whether you believe it is exploitable, and by whom (an unprivileged agent, a
  tenant, a host attacker, a malicious tool author).
- If you have a fix in mind, say so — but send the report first.

### What to expect

This is a pre-1.0 project maintained by one person, and the response time
reflects that honestly: acknowledgement within 7 days, an assessment within 30.
There is no bug bounty and no SLA. If you need a contractual commitment before
testing, ask first.

## Scope

**In scope** — the enforcement properties the project claims:

- A capability can be obtained or used beyond what its issuer held (attenuation
  bypass, signature forgery, tenant crossing).
- An action executes without both capability and policy passing.
- A denial is recorded, or an event is recorded, with content that should have
  been sealed.
- Cross-tenant reads through any REST route, query surface, or evidence key.
- Egress that bypasses the network gateway, the proxy, or content-level DLP.
- An artifact admitted as released when it should have been quarantined.
- Secret material reaching an event, an error message, a log line, or a served
  page.

**Out of scope** — stated limitations, not bugs. See `SECURITY_CLAIMS.md` and
`CURRENT_STATE.md` for the full list. In particular:

- Anything that requires **prior control of the host process**. Keys are
  environment variables; an attacker who owns the process owns the keys. HSM and
  attestation are Stage 3 work, not shipped.
- **Sandbox escape** beyond what `LocalSandbox` claims. It is
  `in-process/no-isolation` by design (ADR-003).
- **Model behaviour**: jailbreaks, refusals, or a model doing something harmful
  *inside* the scope it was granted. This project constrains authority, not
  intent.
- **Denial of service by inducing a dependency failure.** Fail-closed is the
  accepted trade (ADR-027).
- Reports generated solely by an AI system without a human-verified reproduction.

## Supported versions

Pre-1.0: only the tip of `main` is supported. There are no backports and no
maintained release branches yet.

## Disclosure

We will credit you in the advisory unless you ask otherwise. Please give us 90
days before public disclosure, or less if a fix ships sooner.
