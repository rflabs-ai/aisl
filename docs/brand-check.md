# Brand check: KEPT

**Status: BLOCKED. An identical word mark is live and pending in classes 9 and 42,
filed 2026-10-20.**

This is a knockout screen, not legal advice. A lawyer decides registrability and
clearance.

## Scope

| Field | Value |
| --- | --- |
| Mark | KEPT (word mark, all caps, single word) |
| Goods and services | Software for AI agent security: policy enforcement, capability issuance, audit and evidence logging, egress control. Sold to organizations deploying AI agents. |
| Classes in scope | **9** (downloadable software), **42** (SaaS, security services, technology services) |
| Jurisdictions | **US** first (USPTO); **EU** only if selling there (EUIPO) |
| Launch date | Not set |
| Search date | 2026-11-10 |

## What was attempted

| Source | Attempt | Result |
| --- | --- | --- |
| USPTO Trademark Search API (`tmsearch.uspto.gov/api-v1-0-0/tmsearch`) | POST query for `kept` | **405 MethodNotAllowed** (endpoint path no longer serves this API) |
| USPTO TSDR API | Not attempted | Requires `USPTO_API_KEY`; **not set** on this machine |
| EUIPO eSearch | Not attempted | Requires an API path or interactive session; no key available |
| Justia trademarks (secondary index) | GET `trademarks.justia.com/search?q=kept` | **403** |
| DuckDuckGo HTML (secondary index) | GET search | Bot challenge |

**No official record was retrieved.** Per the knockout rule, a name is not
marked clear if any in-scope class was not searched. Both classes are unsearched.

## Result: retrieved 2026-11-11

Source: USPTO Trademark Search export, 220 results for `kept`. Saved locally as
`KEPT-tmSearchResults2026-11-11.xlsx`. No API key was used; this is the public
search UI's own export.

### The blocking mark

| Field | Value |
| --- | --- |
| Mark | **KEPT** (word mark) |
| Serial | **50171161** |
| Status | Live (filed, not yet registered) |
| Classes | **IC 009, IC 041, IC 042** |
| Filed | **2026-10-20** (three weeks before this check) |
| Owner | Janus AI Solutions LLC, Raleigh, North Carolina |
| Goods (9) | Downloadable software for organizing personal healthcare and treatment information; symptom, mood and biomarker tracking; meal planning; personal budgeting |
| Services (42) | Software as a service |

Identical word mark. The two classes that matter. Filed three weeks ago, so it
is a **prior-filed application** for any application filed after it.

### Verdict

| Name | Class | Closest live mark | Serial | Status | Verdict |
| --- | --- | --- | --- | --- | --- |
| KEPT | 9 | KEPT (Janus AI Solutions) | 50171161 | Live, pending | **blocked** |
| KEPT | 42 | KEPT (Janus AI Solutions) | 50171161 | Live, pending | **blocked** |

"Blocked" here means: **do not file, and do not build a company on it.** An
examiner comparing an identical word mark in identical classes would refuse or
require a strong argument about the relatedness of the goods. Wellness software
versus agent-security software is a real difference, but it is an argument, not
a clean path, and it would be argued against a party that filed first.

### The field is crowded regardless

19 live marks in classes 9 or 42 contain "kept": KEPT, KEPPT, BESTKEPT,
KEPTHAVEN, MATTERSKEPT, EVERKEPT, WELLKEPT, WELLKEP, UPKEPT, TRUSTJAR. WHERE
PROMISES ARE KEPT, SOME THINGS ARE BEST KEPT PRIVATE, and others. Even if the
identical mark did not exist, this word is a bad bet for a registerable brand.

### Use is not the same as register

Common-law use of KEPT for security software is defensible, because the goods
differ from wellness. That is not the same as owning it. The realistic outcome of
building on this name is a brand you cannot register, in a class where an
identical mark was filed first, with a holder who may enforce once their
application matures.

**Recommendation: drop KEPT as the company name.** Keep AISL as the product name,
which is what the code, the CLI and the pilot page already say.

## What the market screen did show

Separate from trademark records, availability of the names people type:

| Check | Result | Date |
| --- | --- | --- |
| `kept.security` | resolves free, priced $2k by the registrar | 2026-11-01 |
| `kept.dev` | SERVFAIL, treat as unavailable | 2026-11-01 |
| `kept.io`, `kept.ai` | registered | 2026-11-01 |
| Kepthq variants (`kepthq.dev`, orgs `kepthq` / `kepthqdev`) | checked 2026-11-01; abandoned 2026-11-12 with the dropped Kept name | 2026-11-01 |
| npm `aisl` | free | 2026-11-01 |

Market availability says nothing about registrability. A word can be free to
register as a domain and still be blocked as a mark.

## To finish this properly

1. **Get a USPTO API key** (free, `developer.uspto.gov`), then re-run the
   documented queries and save raw payloads under `data/tm/`.
2. **Or pay for a clearance search.** Roughly $500 to $1,500 for a US search in
   two classes, and it includes an opinion, which the API does not.
3. **Or both**: API key for the repeatable screen, lawyer for the opinion.

Until one of those happens, treat the name as **unverified**, not as safe.

## If it comes back blocked

The order of fallback matters less than having one ready:

1. **AISL** as the product name, with a different company name.
2. A coined mark with no dictionary meaning (fastest to clear, slowest to mean
   something).
3. Buy a name that is already cleared by its owner.

## Reproducible output

No payloads were retrieved, so there is no rebuild script. When the API key
exists, the script should read `data/tm/*.json` and regenerate the table above.
Building that script before there is data would be theatre.
