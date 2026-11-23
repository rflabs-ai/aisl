# Naming batches 1 to 3: the authority field, pure coinage, and the domain-first inversion

Run 2026-11-12. Method: `docs/naming-method.md`. Skill: `name-project`, mode A.

Three batches, 79 candidates, one method correction. Batch 1 tested the concept
field. Batch 2 tested pure coinage. Batch 3 inverted the funnel and is the first
one that produced usable survivors.

## Read this before the table

This is a **discovery pass, not a clearance pass.** Every legal status below is
**unverified**, because the primary sources were gated at run time:

| Source | Result on 2026-11-12 |
| --- | --- |
| `api.uspto.gov` (ODP API host) | `401 {"message":"Unauthorized"}` without a key |
| `tsdrapi.uspto.gov` | 401, "you'll need to register for an API key" |
| `tmsearch.uspto.gov/api-v1-0-0/tmsearch` | 404 / 405 from S3. The old path is gone |
| `bulkdata.uspto.gov` | DNS does not resolve. Moved into ODP |

So the discovery pass used a secondary index (DuckDuckGo Lite) exactly as the
method permits: **discovery only, never a verdict.**

In this document, **blocked** means *practically unusable*, not legally barred.
A live company using the name in the same category is a hard practical block
whatever the register says. Legal clearance still needs the export or the key.

## The lanes

Five semantic lanes, 21 candidates, all coined or compound, chosen because the
`kept` lane is already recorded as saturated in `BRAND.md`.

| Lane | Root meaning | Why it looked thin |
| --- | --- | --- |
| Seal / sigil | a seal is verifiable authority | On-theme, and sigil is a nicer word than kept |
| Token / tessera | a Roman tessera was a token of authority | Historical, short, unexpected |
| Warrant | a warrant is authority to act | Legal register without the word "legal" |
| Custody / ward | the duty of care over another's property | Matches the bailment category |
| Attestation | witnessing that something happened | Matches the evidence bundle |

## Results

| # | Candidate | Lane | What discovery found | Verdict |
| --- | --- | --- | --- | --- |
| 1 | Sigilith | seal | `sigilith.com`: "The authorisation layer for AI decisions" | **Blocked, direct competitor** |
| 2 | Sigillary | seal | Dictionary adjective, plus a street name | Open, but weak and descriptive |
| 3 | Sigilmark | seal | Sigilmark Studios, a YouTube channel, occult-sigil content | Caution, same word other space |
| 4 | Sigillum | seal | `sigillum.pl`, `sigillumalexio.com`, Sigillum Dei, game wikis | **Blocked, multiple live uses** |
| 5 | Signetry | seal | `signetry.com` "Seal of Excellence", `signetry.ai` "One shared record for every agreement" | **Blocked** |
| 6 | Cashal | seal | Collides with Cashel (Irish town, horse-gear company, 2 more) | Reject, and it reads as "cash" |
| 7 | Tesseral | token | `tesseral.com` "B2B user management", `tesseral-ai.com`, `tesseral-geo.com` | **Blocked** |
| 8 | Tessarite | token | Dictionary and tiling materials only | Open, but obscure |
| 9 | Tessarion | token | A Game of Thrones dragon owns every search result | **Blocked, discoverability** |
| 10 | Warrantia | warrant | Legal dictionaries only (`warrantia chartae`, `warrantia custodiae`) | Open, but legalistic |
| 11 | Warrantal | warrant | Dictionary only | Open, but an adjective |
| 12 | Custodel | custody | `custodel.ai`: "Oversight makes AI agents trustworthy" | **Blocked, direct competitor** |
| 13 | Custodara | custody | `custodara.com` plus the whole `custodia.*` family | **Blocked, crowded** |
| 14 | Wardmote | custody | Dictionary and Wikipedia only (a historical ward court) | Open, but obscure, and "ward" reads exclusion |
| 15 | Wardstone | custody | `wardstone.ai`: "LLM Security API for Prompt Injection Detection" | **Blocked, direct competitor** |
| 16 | Custodial | custody | Dictionary only | Reject, purely descriptive |
| 17 | Attestral | attest | `simgen.dev/attestral`, PyPI `attestral`, `attestral-labs` | **Blocked** |
| 18 | Attestra | attest | `attestra.com`, `attestra.ai`, `attestrasign.com` | **Blocked** |
| 19 | Vouchral | attest | Dictionary and `vouch.us` only | Open, but awkward |
| 20 | Testari | attest | `testari.com`: "The independent record of consequential decisions" | **Blocked, direct competitor** |
| 21 | Sealwrit | attest | Legal dictionaries only | Open, but obscure |

**Eleven blocked, two caution, six open-but-weak, two rejected as descriptive.
Zero survivors that are both unoccupied and strong.**

## The finding that matters more than the names

The batch did not fail. It produced a market signal.

Four of the eleven blocked candidates are **live companies in this exact
category**, and three of them describe aiSL's own thesis almost word for word:

| Company | Their line | Relation to aiSL |
| --- | --- | --- |
| Sigilith | "The authorisation layer for AI decisions. We sit in the path: the decision doesn't go out until it's policy-checked and sealed" | **Direct.** Same thesis, including "in the path" and "sealed" |
| Custodel | "The oversight layer for the autonomous agents moving into compliance and risk. Observe, govern, audit, improve" | **Direct.** Governance and audit |
| Testari | "The independent record of consequential decisions" | **Direct.** The evidence log, as a product |
| Wardstone | "LLM Security API for Prompt Injection Detection" | Adjacent. Filtering rather than authorization |
| Attestral | "Machine-Checked Verification for AI-Generated Code" | Adjacent. Verification of output, not authority to act |

Verified by fetching the landing pages, not inferred from titles, except Testari
where the site reset the connection and only the search title is available.

Three consequences:

1. **The semantic field is closed.** Seal, custody, and attestation names are
   owned. Generating a batch 2 in the same field is waste.
2. **aiSL is not alone in the category.** The "authority for AI agents" space has
   at least three direct entrants naming themselves right now. That changes a
   business assumption in `business-and-ip.md`, which assumed the category coinage
   ("AI bailment") was open ground.
3. **The category coinage is a liability if nobody uses it.** "AI bailment" is
   distinctive but unowned, and competitors are converging on plainer words
   ("authorisation layer", "oversight layer", "independent record"). Distinctive
   and unused is worse than plain and shared.

## What batch 2 should do differently

Do not generate in the concept field. The concept is where everyone is standing.
Two directions that avoid it:

1. **Consequence, not concept.** Name what the buyer gets or what the system
   stops, in plain language the buyer already uses. This trades distinctiveness
   for recognition and searchability.
2. **Pure coinage with no semantic tie.** No seal, no custody, no attest, no
   warrant. Invent a sound and then let the brand give it meaning. Slower to
   mean something, fastest to clear, and it cannot be pre-empted by a competitor
   naming themselves from the same dictionary.

Also: run batch 2 against a primary source. The key is now genuinely required,
because the export path needs a browser and this pass cannot drive one.

## Reproducible

- Query form: `https://lite.duckduckgo.com/lite/?q=<candidate>`, one per
  candidate, 2026-11-12.
- Extracted log: `data/tm/2026-11-12/discovery.jsonl` (gitignored).
- Full HTML was **not** retained for this pass, because it is a secondary index
  and must be re-fetched for any clearance use. A clearance pass retains raw
  payloads; this one does not, and says so.
- Landing-page verification: `sigilith.com`, `custodel.ai`, `wardstone.ai`,
  `simgen.dev/attestral`, `attestrasign.com` fetched 2026-11-12.

## Consequence for the repo docs

`docs/business-and-ip.md` §5 says you cannot decide to be a standard, only
standardizable. This batch adds a second constraint: you also cannot assume the
category is empty. Both should be read together before any further positioning
work.

---

## Batch 2: pure coinage (20 candidates)

Instruction was to leave the concept field entirely, so no seal, custody, attest,
or warrant roots. Two to three syllables, invented sounds.

**Result: 14 blocked, 5 caution, 1 open. Zero survivors.**

| Candidate | Discovery | Verdict |
| --- | --- | --- |
| Vantir | `vantir.se`, `vantir-group.com` (mortgage tech), `vantir.com` | Blocked |
| Orvane | `orvane.com`, `.store`, `.in`, all live | Blocked |
| Corvane | `corvane.com` (survey platform), `.in`, `.dk`, `corvanesystems.com` | Blocked |
| Sennara | `sennara-thailand.com`, `trysennara.com`, `senara.ai` | Caution |
| Torvane | `torvane.ai`, plus a real soil-testing instrument | Blocked |
| Avellin | `avellin.com`, `.online`, `.co.uk` | Blocked |
| Marrick | `marrick.com`, `marrickmedical.com`, `marrickcorp.com` | Blocked |
| Quillon | `quillon.ai`, plus the real sword term | Blocked |
| Brannoch | `brannoch.com`, Wikipedia, Forgotten Realms | Blocked |
| Sylvarre | `sylvarre.com`, `sylvaralabs.com`, Guild Wars | Blocked |
| Halden | Norwegian city, `haldenluxury.com`, `thehalden.com` | Caution |
| Veyric | `shopveyric.com`, `veyrictech.com` | Caution |
| Ossian | `ossian.com`, a real name and legend | Blocked |
| Pellara | `pellera.com` (IT solutions), `pellara.ca` | Blocked |
| Rennick | Real surname, `rennickauctions.com`, 3 more | Caution |
| Talvor | `talvor.app`, `talvorsystems.com`, Talvor motorhomes | Blocked |
| Wrenna | Baby-name sites and `wrennamusic.com` only | Open, but it is a given name |
| Zephyra | `zephyra.tech`, `app.zephyra.tech` | Blocked |
| Kestrian | `kestrian.io` (pharma), `kestrian.ai` | Blocked |
| Solvend | Dictionary, plus `solvend.com` | Caution |

### What batch 2 proved

The concept field was not the only problem. **The `.com` namespace is saturated
for short, pronounceable coinages too**, not just for dictionary words. Every
two-syllable sound that reads as a plausible brand is already registered, usually
by an unrelated small business or a domain investor.

That is a different constraint from trademark. It means the binding limit on
naming is **domain availability**, and the method had it in the wrong place.

---

## Batch 3: the inversion

Instead of generate then check the domain, generate a large space and **filter by
domain first**, then screen only the survivors.

Method used:

1. Generate 38 three-syllable coinages with distinctive letter clusters, which
   are far less likely to be registered than two-syllable ones.
2. Check `.com`, `.ai`, `.dev`, `.io` availability through DNS over HTTPS
   (`dns.google/resolve`, type `NS`). `NXDOMAIN` or no NS record means likely
   free. A parked but registered domain still has NS records, so this is a good
   generator signal, not a purchase guarantee.
3. Screen only the domain-free survivors against discovery.

**Result: 9 of 38 had all four domains free. 2 of those 9 had no meaningful
collision. That is a yield of about 5 percent from raw coinage, against 0 percent
from the two earlier approaches.**

| Name | Domains (.com/.ai/.dev/.io) | Discovery collision | Verdict |
| --- | --- | --- | --- |
| **velethra** | all free | A D&D NPC, "Velethra Dren". No company | **Survivor**, but reads fantasy |
| **nirastra** | all free | Sanskrit dictionary: "unarmed, weaponless". No company | **Survivor**, but the meaning is wrong for a security pitch |
| lorbeth | all free | Instagram handle, YouTube channel, a Bizapedia company entry | Caution |
| belthara | all free | Belthara Road, a town in India | Caution, geographic |
| ostrev | all free | "Ostrev", a Kingdom Come character | Caution, fiction |
| dromath | all free | Star Wars character | Caution, fiction |
| eirendal | all free | Too close to Arendal and to Tolkien's Eärendil | Caution |
| falxen | all free | Reads as Falken Tires or "flaxen" | Caution, weak |
| hollivar | all free | A furniture line at Coleman Furniture | Caution |

### The honest read on the two survivors

Both pass the mechanical gate and both fail the ear test for different reasons:

- **Velethra** sounds like a fantasy character, which is the wrong register for
  infrastructure.
- **Nirastra** means "weaponless" in Sanskrit, which is nearly the opposite of an
  authority layer.

So the funnel now works, and the generator still needs a better aesthetic target.
The next iteration is not more names in the same voice. It is a specified sound
profile: how the name should feel when read in a terminal, in a sentence, and on
a contract, then the same domain-first filter.

## The method correction

Recorded here and applied to `docs/naming-method.md` and the `name-project`
skill:

> **Domain availability is a generator, not a filter.** Check the namespace
> before generating, not after. In a saturated namespace, the set of names that
> survive is defined by what is available, so generating first wastes the batch.

The corrected order is: scope, map the semantic field, **check the namespace**,
generate inside what is both thin and available, screen the survivors, gate,
ear test, file.
