# Naming method: legal first

Status: working method, 2026-11-12. Replaces "think of names, then check them."

Applied as a skill: `~/.agents/skills/name-project/SKILL.md`. The skill is the
reusable version and also covers creative names (characters, places, books,
games). This document is the worked commercial case, including the failure that
produced it.

## Why the last attempt failed

Not because the name was bad. Because the order was wrong.

`BRAND.md` records the sequence honestly: "Kept was chosen, checked, and
dropped." `docs/brand-check.md` records the check itself failing: a 405 from
the USPTO search API, no `USPTO_API_KEY` set, a 403 from Justia, a bot challenge
from DuckDuckGo, and both in-scope classes left unsearched. By that document's
own rule ("a name is not marked clear if any in-scope class was not searched"),
the name was never screened at all. It was adopted, used for a placeholder
domain and a placeholder org, and only then found to be blocked by an identical
live mark filed three weeks earlier.

The lesson is structural, not personal: **creative work ran before the
constraint was known, so the constraint was discovered after attachment.**

## The inversion

Legal work is not the last gate before printing. It is the first filter, and it
should be cheap enough and fast enough to run before any emotional investment.

```
wrong:  invent -> fall in love -> screen -> blocked -> invent again
right:  scope -> map the occupied space -> invent inside the empty space -> screen -> file
```

The second path has one more property that matters more than the cost saving:
it produces a name you can actually own, and ownership is the thing this
company is short of.

---

## Step 0: know which USPTO you are on

The confusion is real and it is not your fault: six different USPTO surfaces look
alike and only one has the key. This map is the fix.

| Surface | What it is for | Has the key |
| --- | --- | --- |
| `uspto.gov` | The agency site. Marketing, news, fee schedule, forms | No |
| `data.uspto.gov` | **Open Data Portal (ODP). This is the one** | **Yes, at `data.uspto.gov/apikey`** |
| `developer.uspto.gov` | Legacy API catalog and PTAB search. Partly stale | Old paths, several return 405 |
| `account.uspto.gov` | MyUSPTO sign-in, and the TSDR "API Key Manager" | Yes, different key |
| `tsdr.uspto.gov` | Trademark status and documents by serial number | No, read-only UI |
| `tmsearch.uspto.gov` | Trademark search UI, with its own export | No, but the export works |

There are **two separate key systems**, which is the second reason this is
painful:

- **ODP API key**, for the Open Data Portal (file wrapper, bulk products, and the
  REST search). Sign in at `data.uspto.gov/apikey` with a USPTO.gov account. API
  access requires the account to be verified with ID.me, and the account needs
  MFA enrolled as a required step.
- **TSDR API key**, a separate "API Key Manager" reached through MyUSPTO
  (`account.uspto.gov/api-manager`). Sent as a header and rate-limited per key.
  Official guide: `data.uspto.gov/documents/documents/TSDR-API-Key-Manager-user-guide.pdf`.

**Correction to an earlier claim in this repo.** A previous session concluded the
API key was the blocker. It was not. `brand-check.md` records the name actually
being screened on 2026-11-11 through the **public Trademark Search UI's own
export** (220 results, saved as an `.xlsx`). The export needs no key. The real
failure was ordering, not access.

So the practical split is:

- **Screening a batch of candidates** uses the search UI export and, for volume,
  the ODP bulk trademark products. Neither is blocked by a missing key.
- **Automating per-serial status** uses the TSDR key. That is a convenience, not
  a prerequisite.
- Neither replaces a lawyer's opinion, which is a separate purchase.

Primary sources only for a verdict: USPTO (US), EUIPO (EU, only if selling there),
WIPO Global Brand Database (international). Secondary indexes (Justia,
Trademarkia, search engines) are for discovery, never for a verdict.

A working directory that persists raw payloads, `data/tm/`, one file per source
per candidate, so the screen is reproducible and can be re-run in minutes.

If no records were retrieved, the honest state is "no candidate is screened,"
and no name may be used in print, on a domain, or on an org. That is the rule
`brand-check.md` already states. Keep it.

## Step 1: fix the scope before the name

A mark is clear or blocked *in classes*, not in general. This is already
answered for this business and should not be re-derived:

| Field | Value |
| --- | --- |
| Classes | 9 (downloadable software), 42 (SaaS and technology services). Confirm whether 41 (education) or 35 (business services) is needed once the offer is fixed |
| Jurisdiction | US first through USPTO. EU only when selling there |
| Goods and services wording | The actual sentence that will be filed. Fix it before searching, because it defines the comparison |

Scope is an input, not a discovery.

## Step 2: map the occupied space before naming

This is the step that would have killed "Kept" before anyone liked it, and it is
the step everyone skips.

Do not search a candidate. Search the **semantic field** you intend to enter,
and read the results as a map:

1. Take the verbs and nouns of the product: hold, keep, contain, bound, confine,
   custody, bailment, key, keyring, broker, fence, ward, vault, ledger, proof,
   record, custody, chain, anchor.
2. Run each through the USPTO export for classes 9 and 42.
3. Record, per field, how many live marks exist and how close the closest one
   is.
4. Mark each field: **saturated** (a dozen live marks, one of them identical),
   **crowded**, or **thin**.

`BRAND.md` already contains the output of this exercise for the containment
field, which is why it lists nineteen live marks containing "kept". That
knowledge existed. It just arrived after the decision instead of before it.

The map is the deliverable. It tells you which lanes are closed, and it is
reusable for every future candidate in that lane.

## Step 2b: check the namespace before generating

Added 2026-11-12 after the first real batch, which produced zero survivors twice
for different reasons. See `docs/naming-batch-2026-11-12.md`.

**Domain availability is a generator, not a filter.** In a saturated namespace,
the set of usable names is defined by what is available, so generating first
wastes the batch.

Measured in that batch:

| Approach | Candidates | Usable survivors |
| --- | --- | --- |
| Concept field, screen after generating | 21 | 0 |
| Two syllable pure coinage, screen after | 20 | 0 |
| Three syllable coinage, **domain checked first** | 38 | 2 |

Cheap check: `https://dns.google/resolve?name=<name>.com&type=NS`. `NXDOMAIN` or
`Status: 0` with no `Answer` means likely free. A parked domain still has NS
records, so treat this as a generator signal and confirm before buying.

Prefer three or four syllables with distinctive letter clusters. Every two
syllable sound that reads as a plausible brand is already registered, usually by
an unrelated small business or a domain investor.

## Step 3: generate inside the negative space

Now the creative work, with the map as a constraint rather than an afterthought.

Rules that survive from `BRAND.md` (these were good and are cheap to keep):

- One syllable, pronounceable in every major language, no unfortunate rhyme.
- Must not read as exclusion when the product means containment.
- The ear is the test. `Kepha` died on the ear, unprompted. That instinct was
  correct and should be kept as a veto.

New rules from the failure:

- Prefer a **coined or compound** mark over a real English word. `BRAND.md`
  already recorded the finding: every real English word tested was taken on all
  four surfaces. Twenty names, empty set. The namespace land rush ended around
  2015. Stop testing dictionary words as if one will be free.
- Generate a batch of at least twenty inside the thin lanes, not one at a time.
  Screening is a batch operation; attachment happens one at a time. Widen the
  top so the losses at the bottom cost nothing emotionally.

## Step 4: screen the batch, mechanically

For each candidate, in this order, cheapest test first:

| Check | Source | Failure means |
| --- | --- | --- |
| Exact and near match, classes 9 and 42 | USPTO export and TSDR | Blocked or caution |
| EU | EUIPO | Blocked if selling there |
| International | WIPO Global Brand Database | Caution |
| Domain | `.com`, `.dev`, `.io`, `.ai` | Practical, not legal |
| Package namespaces | npm, crates.io, PyPI, GitHub org | Practical, not legal |
| Common-law use in the wild | Web search, product directories | Caution, and the thing a register search cannot see |

Save the raw response per candidate per source. The verdict must be
reconstructable without re-running anything.

## Step 5: the verdict gate

Three outcomes only. No fourth.

| Verdict | Condition | May be used |
| --- | --- | --- |
| **Blocked** | Identical or confusingly similar live mark in a class in scope | Never |
| **Caution** | Crowded field, or a close mark in an adjacent class, or unsearched foreign jurisdiction that matters | Not for print, domain purchase, or org creation without a lawyer's opinion |
| **Unverified** | Any in-scope class not searched, or no API key | Nothing. Treated as blocked |
| **Clear** | Every in-scope class searched, primary source, nothing close, and the goods wording differs | Usable, with the payloads kept |

The gate is binary on "may be used." That is the whole point: it removes the
option of proceeding on a feeling.

## Step 6: only now, the ear test

Everything above is mechanical and can be run by an agent. This step cannot.

Read the survivors aloud. Say them in a sentence. Say them on a phone call. One
of them should stop feeling like a word you are evaluating and start feeling
like the thing's name. If none does, widen the batch in the same cleared lane,
which is cheap, rather than relaxing the gate, which is expensive.

## Step 6b: dogfood the engine, with controls

The decision engine (`eyewright`) can rank candidates, but only if it is shown to
discriminate. Run it as a blind panel with controls:

1. Put the real candidates in one batch with at least two controls: a name you
   would accept, and the blocked name from the last failure (`KEPT`).
2. Give the engine the same evidence for every entry. No extra help for the
   candidates.
3. Accept its ranking only when the good control lands above the candidate set
   and the blocked control lands below it. If the engine cannot separate the
   controls, it is not deciding anything and the decision stays human.
4. Record the input file, the engine version, and the ranking. The output is
   evidence to review, not a verdict to adopt.

Dogfooding here has a second purpose: it exercises the product on a real,
high-stakes decision, which is the only test that shows whether the engine is
ready to be sold. A demo that only ever sees curated inputs proves nothing.

The ear test (step 6) stays with the operator. The engine narrows the batch; it
does not hear the name.

## Step 7: two names, two jobs

Do not make one name carry both jobs. This is the structural fix for the
current situation.

| Name | Job | Property needed | Current |
| --- | --- | --- | --- |
| **Company mark** | The entity that signs agreements, owns the trademark, and appears on the contract | Registerable. Coined beats descriptive | **Missing.** This is the blocked slot |
| **Product mark** | The CLI, the package, the thing in the terminal | Descriptive is fine. Availability and familiarity matter more than registrability | `aisl`, npm free, usable |

`aiSL` is a good product mark precisely because it is descriptive and weak, the
same way `terraform` or `syft` are. It is a bad company mark for exactly that
reason. The two were being asked of one name, which is why the failure took the
whole thing down.

## Step 8: file before you print

The legal-first move that actually buys something.

- A US **intent-to-use** application (Section 1(b)) locks your priority date
  before the product ships, which is the whole reason to file early rather than
  after launch.
- Budget roughly $250 to $350 per class in filing fees, so two classes is in the
  hundreds, not the thousands. Confirm the current fee schedule; these move.
- A clearance **opinion** is a separate purchase, roughly $500 to $1,500 for a
  US search in two classes per `brand-check.md`. An API screen and a lawyer's
  opinion are not the same product, and the document should keep saying so.
- Do not file in a class you do not use. An unused registration is vulnerable.

## Step 9: keep the map

The occupied-space map from step 2 is a reusable asset, not a one-off. Every
future candidate, every new class, and every renewal reads from it. Rebuild the
payloads, not the conclusions.

---

## What this method deliberately does not do

- It does not pick the name. That is step 6, and it is yours.
- It does not replace a lawyer. It replaces *guessing*, which is what happened
  last time.
- It does not make a weak mark strong. If the chosen company mark is descriptive,
  it will stay hard to defend, and the method will say so at step 5.

## The honest answer to "I should not have to ask you"

You should not, for the mechanical half. Steps 2, 4, and 5 are a batch job: take
a list, run it against primary sources, emit a verdict table with the payloads
attached. That is exactly what an agent should do, and it is the part that was
never done.

What stays with you is the part no screen can produce: which semantic lane you
want the company to live in, and the ear test. That is a smaller job than the
one you have been doing, and it is the only part that needed you.

## Automation, and what actually blocks it

The screen is a batch job, so build it on the path that has no access gate:

| Input | Path | Key needed |
| --- | --- | --- |
| Trademark search export | `tmsearch.uspto.gov` UI export, one per query | No |
| Bulk trademark products | ODP bulk datasets, `data.uspto.gov` | Yes, ODP key |
| Per-serial status | TSDR, `tsdrapi.uspto.gov` | Yes, TSDR key |
| EU | EUIPO eSearch | Depends |

Output shape:

```
data/tm/<candidate>/tmsearch-<date>.xlsx     raw export, unmodified
data/tm/<candidate>/tsdr-<serial>-<date>.json raw payload
data/tm/<candidate>/verdict.md               per class, with the closest mark
data/tm/<candidate>/sources.md               source, query, date, result count
```

The script reads payloads and regenerates the verdict table. It does not query
and judge in one step, because a verdict that cannot be reconstructed is not
evidence.

Build it with the first real batch. Building it before there is data would be
theatre, which is what `brand-check.md` already concluded.

## The semantic map is the reusable asset

Steps 2, 4 and 5 produce an occupied-space map per semantic lane. That map is
worth more than any single name: it tells you which lanes are closed before you
spend an evening in one, and it survives the name. Keep it next to the payloads.

## Sources

`BRAND.md` (chosen-and-dropped record, rejected names, availability facts),
`docs/brand-check.md` (the failed check, the blocking mark, the verdict rules,
the cost estimates). Blocking mark: KEPT, serial 50171161, Janus AI Solutions
LLC, classes 9, 41, 42, filed 2026-10-20.
