# BRAND

Working brand decisions for this project, recorded so later sessions do not
relitigate naming. Every claim here was checked; every rejection has a reason.

Last updated: 2026-11-01.

---

## The system

| Layer | Value | Notes |
| --- | --- | --- |
| **Company** | **Kept** | One syllable. "Kept" = held, looked after, preserved. |
| **Domain (canonical)** | `kepthq.dev` | `.dev` is HSTS-preloaded — plaintext HTTP cannot be served, which is the right default for a security brand. |
| **Domain (deferred)** | `kept.security` | Free to resolve but priced at $2k. Not bought. Revisit only when a pilot pays for it. |
| **Domain (optional)** | `kept.engineering` | Free at ~$15/yr. Defensive redirect only, never canonical. |
| **GitHub org** | `kepthqdev` | `kepthq` is **reserved by GitHub** — the API reports it free (404) but the UI refuses it, which is the signature of a name held back after a deletion. `kepthqdev` mirrors the domain. Owned by the personal account: add a second owner before the first customer. |
| **CLI / artifact** | **`aisl`** | npm `aisl` is free. Spoken as "aisle". The name in the repo, the terminal, and the logs. |
| **Category** | **AI bailment** | Our coinage. A bailment is the legal relationship of holding another's property under a duty of care, with a duty to return and account. |
| **Company line** | **Nothing leaves without a record.** | Hero, deck, footer, sticker. |
| **Logo lockup** | **Held in. Accounted for.** | Under the mark only, small, permanent. |
| **Positioning (contrast)** | **The fence, not the guardrail.** | Comparison page and sales conversations. Never in the hero. |

### Pronoun and casing

- **Kept** — always capitalised, never "KEPT", never "Kept™" in prose.
- **aisl** — always lowercase, monospace when referring to the binary, "AISL"
  never. In speech: "aisle".
- **AI bailment** — lowercase "bailment". It is a category, not a product.

---

## Copy discipline

One hero line. Each line has exactly one home. The failure mode is stacking all
three in the hero block, which reads as noise — big brands run **one** line for a
decade (Mastercard "Priceless" since 1997, CrowdStrike "We stop breaches" since
2011).

| Surface | Line |
| --- | --- |
| Homepage hero, deck, footer | Nothing leaves without a record. |
| Logo lockup | Held in. Accounted for. |
| Comparison page, sales call | The fence, not the guardrail. |

The tagline never repeats the company name. "Kept — everything is kept" makes the
sentence eat itself.

---

## Why "Kept"

- It is the past participle of the exact verb the product performs: data is
  **held**, **maintained**, and **not released**.
- It is one syllable, pronounceable in every major language, and has no
  unfortunate rhyme.
- It carries the containment sense (kept in), the care sense (well-kept), and the
  confidentiality sense (a well-kept secret) — three meanings, one word.
- The archaic "kept man" reading is a dictionary footnote, not a live mental
  category. Accepted risk, recorded here so nobody re-raises it.

---

## Rejected — do not revisit without a new fact

| Name | Why it died |
| --- | --- |
| Nemean | Org, `.com` and `.dev` all taken. Only npm was free. |
| Keephold | Rhymes with "cuckold". Founder heard it unprompted; once heard it cannot be unheard. |
| Bailment | Exact, but reads as a legal term to non-lawyers. Survives as the **category**, not the name. |
| Wardenry | "Ward" reads as *exclusion* (warding off), which is the opposite of containment. |
| Holda | Sounded slangy. |
| Kepha | Sounded like a slur to the founder's ear. The ear is the test. |
| Castellan | Sounds like enterprise software, not security. |
| Dungeon Keeper | EA owns the trademark (class 9), and "dungeon" search results are disqualifying for a B2B brand. |
| Cordon / Palisade / Bastion / Aegis | Obvious to us means obvious to everyone; all taken or generic. |
| EyeHold / EyeKeep | Apple-derived `i-` pattern, and "eye" now reads as eye-tracking. |
| `ASL` | Collides with American Sign Language and the "age/sex/location" chat acronym. Survives only as the historical repo name. |

---

## Availability facts

Checked 2026-10-27 → 2026-11-01 across GitHub orgs, npm, and `.com`/`.io`/`.dev`:

**Every single real English word tested was taken on all four.** Roughly twenty
names, including `kept`, `held`, `bound`, `berth`, `trove`, `redoubt`,
`holdfast`, `safekeep`, `donjon`, `coffer`, `holt`, `fafnir`, plus Greek, Hebrew,
Finnish and Japanese words for guardian. A meaningful, unmodified, free name is
an empty set — the namespace land rush ended around 2015.

What survived was always either a compound (`kepthq`, `kept.security`) or a
coinage (`aisl`, `nemion`).

---

## Open questions

- **Trademark search** in class 9 (software) and 42 (SaaS/security) — not done.
  A lawyer, $500–1500, before anything is printed.
- **`kept.security` at $2k** — verify whether that is one-time or annual. If
  annual, never buy it.
- **Second org owner** — required before the first customer, so the org does not
  depend on one personal account surviving.
- **Contact email** — currently a personal address. Move to a domain address
  once `kepthq.dev` mail is set up.
