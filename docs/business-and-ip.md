# Business model, IP, and the open-core seam

Status: working position, 2026-11-12. Not legal advice. Every factual claim
about the repo was checked against the files named at the bottom; every claim
about the market is labelled as the speaker's unless sourced.

This document exists because two questions kept coming back in separate
sessions and were being re-argued from scratch each time:

1. What is ours to own, and what is ours to give away?
2. What do we charge for, if the code is free?

It also records a correction. An earlier session concluded "add an `ee/`
folder so a fork cannot capture the enterprise value." That was right for a
product and wrong for a standard. The corrected position is at
[The seam that works for both](#the-seam-that-works-for-both).

---

## 1. Where AISL sits in the open-source taxonomy

The source video (`Q6PYuNwft-g`, Elie Steinbock, "How Open Source Founders
Make Millions", uploaded 2026-11-02) splits open source into three kinds and
only gives a monetization playbook for the third:

| Type | Examples he gives | His position |
| --- | --- | --- |
| 1. Packages | zod, lodash, bun | Very hard to monetize, sponsorships or acquisition |
| 2. Infrastructure | MongoDB, Elasticsearch, Terraform | Real money, but he explicitly excludes it as "difficult to start" |
| 3. SaaS | Inbox Zero, Papermark, PostHog, Sentry, GitLab | The playbook: subscription revenue |

AISL is a **type 2 / type 3 hybrid**. The enforcement plane is infrastructure
(you adopt it, it sits underneath everything). The thing a customer actually
buys, an operated plane with custody, attestation, and support, is SaaS.

The practical consequence: his type-3 playbook applies to the **operated
product**, not to the library. Do not read his advice as "make the enforcement
plane a subscription."

He does make one claim that inverts for AISL. He says the winning SaaS
deliberately hides the word "open source" because users do not care, and that
it "happened by chance that the code was open." For AISL, auditability *is* the
product. Openness is the marketing and the trust mechanism, not a footnote. His
own four reasons to open source (marketing, privacy, security, contributors)
are the ones to lean on; his "keep it quiet" tactic is the one to ignore.

---

## 2. Two different IP problems, often conflated

| Problem | Whose asset | What actually protects it | Status |
| --- | --- | --- | --- |
| Protecting the customer's IP | The customer's | Taint tracking, egress DLP, sealed content, capability authority, signed audit log | Built (M2 to M17) |
| Protecting the company's IP | Ours | Trademark, copyright, trade secret, and operating competence | Partly, see §3 |

The first is the product. The second is the business. They use the word "IP"
for both, which is why the conversation loops.

A security product has an unusual property here: **hiding the enforcement
logic is a liability.** Nobody buys an unauditable enforcement plane. Code
secrecy is not available as a moat for the thing you are selling, so the moat
has to live somewhere else. `initial-idea-CONTEXT.md` already says where: "AI
security infrastructure" underneath every harness, which is a position and an
operating record, not a secret.

---

## 3. The legal stack, honestly

| Instrument | What it covers here | Current state | Action |
| --- | --- | --- | --- |
| **Copyright** | The code, docs, the BRAND.md copy | Held automatically on creation. Apache-2.0 grants use, does not transfer ownership | None required. Optional US registration only if statutory damages matter |
| **Trademark** | The name customers say, the mark on the pilot page | **Gap.** KEPT is blocked (Janus AI Solutions LLC, serial 50171161, classes 9, 41, 42, filed 2026-10-20). `AISL` is descriptive and weak. Nothing registered | This is the only registerable asset and it is missing. See `docs/naming-method.md` |
| **Patent** | A specific novel mechanism, if one exists | None filed | Probably skip. Software patents are slow and expensive, and the value here is operational, not algorithmic. Revisit only if a specific verification mechanism is genuinely novel and a competitor could not design around it |
| **Trade secret** | Pricing, the customer list, deployment playbooks, incident response, the parts of the roadmap not published | Exists by default, unprotected by process | Write down what stays private and who may see it. A trade secret with no boundary is not one |

Conclusion: **this is not an IP problem, it is a trademark problem and a
trade-secret boundary problem.** The code is deliberately public under
Apache-2.0, so copyright is doing its normal job and no patent is in play. The
one asset that could be registered, the mark, is the blocked one.

---

## 4. The license seam

Elie's toolbox, from the video, with what each one costs you:

| Mechanism | How it works | Cost |
| --- | --- | --- |
| AGPLv3 core | Fork must also stay open | Forkers who want to host commercially cannot. Also makes you a *vendor* standard, not an industry standard (see §5) |
| `ee/` folder with a separate commercial license | Public repo under an open license plus one directory that requires a paid agreement in production | Requires that the directory hold something a customer genuinely cannot get otherwise |
| Enterprise code kept out of the repo | Public repo stays liberal, enterprise features live elsewhere | Same requirement as above, harder to develop in the open |
| Relicense closed | Cal.com (about a year ago) and Dub (recently) did this | Goodwill, and the contributors you attracted on the open promise |

AISL today: Apache-2.0, one license, everything in `src/`, no `ee/`, no dual
license. By the video's own taxonomy AISL is fully open and therefore fully
forkable and hostable by anyone, including a cloud provider. There is currently
no license-based protection of any kind. That is a deliberate choice
(`README.md`, "the patent grant is why it is not MIT"), not an oversight, but it
does mean the paid line has to be drawn somewhere real.

### The seam that works for both

The earlier "add an `ee/` folder" advice assumed the product path. If the goal
is the standard path, gating enforcement semantics behind a license destroys
the thing you are trying to become. There is a version that survives both, and
it follows the split already recorded in the standard note:

| Layer | Examples | License | Why |
| --- | --- | --- | --- |
| **Format and verification** | Evidence bundle wire shape, hash chain, signature scheme, anchor format, offline verification algorithm, conformance vectors | Apache-2.0, and eventually a free `SPEC.md` | This is the standardizable part. Competitors must be able to implement a producer and a verifier. The CycloneDX / Syft split |
| **Enforcement plane** | `issueCapability`, policy evaluation, `AgentSession.attempt`, taint tracking, event log | Apache-2.0 | Auditability is the product promise. Gating it makes the promise conditional |
| **Operated trust** | Key custody and HSM, anchoring service, multi-tenant control plane, attestation report generation, SSO/MFA at scale, conformance certification, SLA, incident response | Commercial (`ee/` or hosted only) | This is what a regulated buyer pays for and what a fork cannot manufacture by copying code |

Put it in one sentence: **the format and the denial are free; the custody, the
certificate, and the person who answers the phone are paid.**

That split is compatible with the video's playbook (there is a paid tier that
is not crippleware) and with the standard ambition (a competitor can implement
the format, which is the whole point).

---

## 5. Standard or product

Recorded separately in
`notes-vault/ideas/2026-11-12-aisl-standard-vs-product.md`, and it should be
read before this document is used to justify anything.

The short version, because it decides the license question:

- A standard is a **format** two parties can implement independently. AISL as a
  whole is a **runtime**, and it *is* the security model, so nobody "interoperates"
  with it.
- The standardizable asset is the **evidence bundle**: hash-chained events,
  per-event signatures, external anchors, checkpoints, legal holds, and an
  offline verification algorithm.
- You cannot decide to be a standard. You can only decide to be
  **standardizable**. Adoption decides the rest, and that starts with one
  design partner whose data is actually in the format.
- The end states differ: a standard hands control to a foundation and earns
  from support, certification, and enterprise features. A product keeps control
  and earns from market share.

Does this contradict Elie? **No, it is a different destination.** He describes a
product company. But two specific pieces of his advice actively fight the
standard path, and should not be copied:

1. **AGPL on the core.** It makes the format legally fork-hostile, which is the
   opposite of what a standard needs.
2. **An `ee/` gate on core semantics.** A standard with a paid gate on its own
   semantics is a vendor format, not an industry format.

What transfers cleanly from him: marketing (GitHub Trending, Product Hunt),
openness as trust, enterprise and on-prem as the revenue tier, and the licence
fee model for regulated buyers.

One more constraint, added after the first naming batch
(`docs/naming-batch-2026-11-12.md`): **the category is not empty.** At least three
live companies describe this thesis almost word for word (Sigilith, "the
authorisation layer for AI decisions"; Custodel, "the oversight layer for
autonomous agents"; Testari, "the independent record of consequential
decisions"). So the standard ambition competes with vendors who own plainer words
than "AI bailment". Distinctive and unused is weaker than plain and shared. Read
that batch before any further positioning work.

---

## 6. The paid line, concretely

Drawn from `initial-idea-CONTEXT.md` §24 and §25, which already had this shape,
mapped onto the seam above.

| Tier | Buyer | What they pay for | Open or paid |
| --- | --- | --- | --- |
| Self-serve | Individual developer | Nothing. This is distribution | Open |
| Team / platform | Team deploying agents | Hosted control plane, multi-tenant RLS, evidence retention, dashboards, SSO | Paid subscription, per organisation, not per seat |
| Enterprise | Regulated org, security review | Private SaaS or customer VPC, key custody, anchoring, attestation and compliance reports, SLA, named support | Platform licence plus deployment plus review |
| On-prem | High-security, air-gapped | Annual licence plus support plus updates, plus the conformance certification | Paid |

Deliberately not the model: per-seat pricing (he agrees, and it misprices a
plane that sits under every agent rather than next to every person), and
compute resale as the primary line (it invites a race to the bottom against
whichever cloud the customer already has).

Movement from a free user to a paid team happens because of custody and
attestation, not because a feature is locked. That is the standard-compatible
version of Elie's "why do people pay if the code is free" answer: self-hosting
the plane is possible, but running an enforcement plane with key custody, HA
Postgres, anchoring, and incident response is exactly the "maintenance and
security is on you" burden a security buyer will pay to avoid.

---

## 7. What the company actually is

The question that keeps returning: is AISL the product, or a shop that
implements AISL for people? It is both, in a fixed order, and the order is the
business model.

| Shape | What it sells | Cycle | Ceiling | Fits now? |
| --- | --- | --- | --- | --- |
| **Product company** (SaaS plus on-prem) | A subscription to the operated plane | Months | High | Not yet. No serve command, no containment, pre-1.0 |
| **DFY / services first** | A deployed, operating plane in the customer's environment, then a retainer | Weeks | Low, but fast | **Yes** |
| **Standard body** | Conformance certification on a free format | Years | Medium | Later, only after two independent implementers |
| **OEM / component** | The plane licensed inside another vendor's product | Months | Medium | Possible. Different buyer, other software companies |

**Recommendation: start as DFY, convert to product as the same deployment
repeats.**

This is not a compromise. It is the only shape that fits the artifact. The
system is a library plus proof suite with no serve command, no containment, and
keys in environment variables (`README.md`). You cannot sell an operated plane
you cannot yet operate at scale. You *can* deploy one for one client.

### What DFY means here, concretely

Not "we build AI agents for you". That is an agency with unbounded scope and no
product. The deliverable is the security plane and its evidence, not the agents.

| Element | Content |
| --- | --- |
| Offer | "We deploy and operate an AI agent enforcement plane in your environment: policy as code, capability issuance, egress control, and a signed evidence log your auditors can verify offline" |
| Scope | Fixed, 4 to 6 weeks |
| Deliverables | Running plane in their VPC or on-prem; a policy set mapped to their real agent use cases; an evidence-bundle verifier they can run without you; one attestation report for their security team |
| Then | Monthly retainer: updates, incident response, evidence retention |
| Pricing | Engagement fee plus retainer. Not per seat |

### Why this does not betray the standard ambition

Every deployment is a producer of the evidence format. The standard note's first
step is "one design partner whose data is in the format". A DFY engagement *is*
that step, and it is paid. It also generates the case studies, the policy
templates, and the conformance vectors a product would need later.

### The guard against staying a consultancy

Every engagement must produce at least one reusable product artifact: a policy
template, an attestation report generator, a conformance vector, or a deployment
script. If it would not, decline it. Two engagements that produce the same
artifact means the product is ready; build it and stop taking bespoke work.

### The side effect that matters

DFY requires a legal entity, a contract, and a signature now rather than later.
That closes the naming loop by force, which is the correct forcing function.

---

## 8. Why AISL is a poor attention honeypot

This matters for the "bring customers, investors, and cofounders to me"
ambition, and it is not obvious.

AISL's demo is a **denial**. Nothing happens, visibly, when the system works.
The value is the absence of an event. That is a hard thing to make someone
watch for fifteen seconds, and it is a hard thing to put on Product Hunt.

Compare: `vkeys` shows a key that cannot be printed. `kgp` shows a cited answer
from a video. Both produce a visible artifact in one command.

So the honeypot and the revenue product are different assets, and AISL is the
revenue product, not the honeypot. See `docs/portfolio-wedge.md` for the survey
and the recommendation.

---

## 9. Decisions this document asks for

| # | Decision | Blocking what |
| --- | --- | --- |
| 1 | Standard or product, or a declared period of deliberately standardizable | The license question, the `ee/` boundary, and whether a `SPEC.md` gets written |
| 2 | Ratify the three-layer split in §4 | Any packaging or pricing work |
| 3 | Name the trade-secret boundary in writing | Any conversation with a design partner under NDA |
| 4 | Pick the company mark, file in classes 9 and 42 | Any signed agreement, incorporation, or first payment |

---

## Sources

Repo: `package.json`, `LICENSE`, `README.md`, `BRAND.md`, `docs/brand-check.md`,
`initial-idea-CONTEXT.md` §24 to §25, `notes-vault/ideas/2026-11-12-aisl-standard-vs-product.md`.

Video: `D:\kgp-data\derived\AI Biz\Q6PYuNwft-g\` (`transcript.jsonl`,
`slides.jsonl`, `ocr.jsonl`). The transcript is machine ASR, marked untrusted,
and one stretch was machine-translated to Ukrainian. Figures quoted from the
video are the speaker's and unverified: GitLab "1B a year" and "9B market cap",
Papermark "4M", Postiz "4M", Cal "7 to 9M", "50% of Fortune 100".
