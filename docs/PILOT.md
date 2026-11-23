# aiSL design-partner pilot

**Six weeks. One agent workflow. One question answered: can you prove what your
agents did?**

This is a pilot for organizations that have already put AI agents in front of
data they care about — and have discovered that "the agent said it did X" is not
an answer a security team, an auditor, or a regulator will accept.

---

## Who this is for

You have agents (or are about to) touching documents, tickets, code, or
customer records. You have a policy about what they may do. What you do not have
is a mechanism that **enforces** that policy at the action, and a record that
**proves** what happened — independent of the model's own account of itself.

Good fits: regulated engineering teams, security teams with an agent rollout
stuck in review, platform teams who have been asked "how do you know?".

---

## The problem, stated plainly

Today's agent security is guardrails: classifiers that read prompts and flag
things. They are advisory. When they are wrong, nothing stops the action — and
when they are right, they leave a log line, not evidence.

Three consequences you have probably already met:

1. **Authority leaks through the model.** If the agent can be talked into
   requesting something, and the request path trusts the agent, the model is the
   authority. It should never be.
2. **Data leaves through allowed channels.** The destination was permitted, the
   credentials were valid, and the bytes were the attack.
3. **The record is a narrative.** Application logs say what the agent *claims*.
   They are not signed, not chained, and not anchored anywhere the attacker
   cannot rewrite.

aiSL is built on the opposite premise: **the model is not the authority, the
infrastructure is.**

---

## What the six weeks produce

| Week | Work | Output |
| --- | --- | --- |
| 1 | Map one real workflow: what the agent reads, decides, writes, and sends | A boundary diagram and the enforcement points that will exist |
| 2–3 | Deploy aiSL in front of that workflow, in a sandboxed copy of your environment | An agent running under capability-scoped authority |
| 4 | Policy in your terms: who may do what, to which classification, with whose approval | A policy file you own and can read |
| 5 | Adversarial pass against *your* workflow, not the demo corpus | A written findings list, with each finding reproduced |
| 6 | Evidence review and handover | A signed, anchored audit bundle for the pilot period, plus a runbook |

**The deliverable is not a demo.** It is an evidence bundle you can hand to
someone who was not in the room: every action, the authority that permitted it,
and a hash chain that proves nothing was rewritten afterwards.

---

## What aiSL enforces during the pilot

- **Capability-based authority.** Every action carries a signed capability that
  names the resource, the action, the classification ceiling, and the expiry.
  The model cannot mint one. Delegation is attenuation-checked against the
  parent, not declared by the caller.
- **One enforcement path.** Nothing executes unless both a capability and the
  policy allow it, through a single code path.
- **Containment and egress control.** Taint labels follow data across a session;
  egress is classified, canary-scanned, and byte-capped before it leaves.
- **Evidence.** Hash-chained, per-event signed, externally anchored, with
  operator-held checkpoints and recorded legal holds. Rewriting the log is
  detectable without trusting the host.
- **Fail-closed with a loud health signal.** A broken dependency denies, with a
  distinct reason and an operator-visible transition, rather than silently
  degrading.

---

## What it does not do — read this before you start

Honesty here saves us both a wasted quarter:

- **It does not contain a hostile host.** The sandbox is in-process. If an
  attacker already owns the machine, they own the keys. Real isolation
  (microVM, HSM, attestation) is not shipped.
- **It does not judge intent.** A model doing something harmful *inside* the
  scope it was granted is out of reach. aiSL constrains authority, not meaning.
- **It does not replace your DLP, SIEM, or IdP.** It produces evidence; it does
  not ship a dashboard, a SOC, or a compliance certificate.
- **It is pre-1.0.** Expect sharp edges, expect to be the person who finds them,
  and expect direct access to the person who fixes them.

---

## What we need from you

- One workflow owner who can say yes to a six-week sandboxed deployment.
- A non-production copy of the data and credentials the workflow touches.
- Two hours a week from someone technical, and thirty minutes a week from
  whoever owns the risk.
- Agreement that findings may be written up publicly, anonymized, at the end.

---

## Commercials

**$7,500 for six weeks**, fixed scope as above.

The first two design partners pay **$4,000**, in exchange for a named reference
call at the end. Either amount is credited in full against the first year of a
licence if you continue.

Pilot terms include a mutual NDA and a written scope before work starts. No
auto-renewal; at week six you decide yes or no, and either answer is fine.

---

## Not a fit if

- You need a vendor with SOC 2, an SLA, and a support line today. (That is a
  legitimate need; this is not that yet.)
- You want prompt filtering and a monthly report on model behaviour.
- You cannot give a sandboxed copy of the workflow, only production.
- Your agents do not touch anything sensitive yet — you have time, and you
  should spend it on something else first.

---

## Who you would be working with

aiSL is a one-person project. There is no sales team and no support tier: the
person who signs the pilot is the person who writes the code, answers the
security questionnaire, and picks up when it breaks at 2am. For a six-week
engagement that is an advantage; for a five-year contract it is not, and you
should weigh it that way.

## Start

Email the maintainer with:

1. What the agent does today, in two sentences.
2. What data it touches, and how that data is classified.
3. Who, internally, has to say yes.

That is enough to decide whether a pilot makes sense in one call.
