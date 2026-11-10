# Brand check: KEPT

**Status: not cleared. Blocked on records access, not on effort.**

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

## Verdict

| Name | Class | Closest live mark | Serial | Status | Verdict |
| --- | --- | --- | --- | --- | --- |
| KEPT | 9 | not retrieved | n/a | n/a | **unknown** |
| KEPT | 42 | not retrieved | n/a | n/a | **unknown** |

### Prior expectation (not evidence)

"Kept" is a high-frequency English word with an established commercial use
(consumer apps, retail, HR and finance brands). Class 9 and class 42 are the two
most crowded classes in software. The base rate of at least one live or pending
registration on a common word is high.

**Expect caution at best. Do not expect clear.**

That is a prior, not a finding. It should make you want the records, not decide
the question for you.

## What the market screen did show

Separate from trademark records, availability of the names people type:

| Check | Result | Date |
| --- | --- | --- |
| `kept.security` | resolves free, priced $2k by the registrar | 2026-11-01 |
| `kept.dev` | SERVFAIL, treat as unavailable | 2026-11-01 |
| `kept.io`, `kept.ai` | registered | 2026-11-01 |
| `kepthq.dev` | free | 2026-11-01 |
| GitHub org `kepthq` | reserved by GitHub (API 404, UI refuses) | 2026-11-01 |
| GitHub org `kepthqdev` | free, created | 2026-11-01 |
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
