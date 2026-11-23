# Portfolio survey: which project is the type-3 wedge

Status: revised, 2026-11-12. Supersedes the first version of this document,
which was built from `control-plane/project-registry.yaml` and therefore from
project descriptions rather than evidence.

## Correction

The first version was wrong about its source. It surveyed the control-plane
registry, which lists projects and one-line descriptions. The authoritative
source is `shared-docs/CLAIMS-INDEX.md` plus the per-project summaries, which
carry the hard numbers and the "never say" rules. Reading that first would have
changed the ranking, so this version does.

Two consequences of using the right source:

1. **Ranking changes.** `mcp-weight` has the only measured demand signal in the
   portfolio. `fixture-cad` has a shipped package and a measured benchmark win.
   Neither was credited properly before.
2. **A drift item.** The claims index is stale for at least two projects. See
   [Index drift](#index-drift-worth-fixing).

## The question, split

"Easier to get customers" is three different questions. They do not have the
same answer, and conflating them caused the earlier confusion.

| Question | Answer |
| --- | --- |
| Easiest to get a stranger to try it | `mcp-weight`, proven |
| Easiest to get a stranger to pay | `fixture-cad`, shipped with a measurable advantage |
| Best wedge that feeds aiSL specifically | `vkeys`, because it shares the buyer |

## The rubric

| Criterion | The question |
| --- | --- |
| Buyer reachability | Reachable without a sales team, or needs a warm intro and a review? |
| Cycle length | Minutes, days, months to paid? |
| Trust required | Does the buyer bet their job before value appears? |
| Pain obviousness | Do they already know, or must you teach them? |
| Demoability | One command, visible artifact, or is the value an absence of events? |
| Defensibility | What stops the next person? |
| Ships now | Can a stranger use it this week? |

## Evidence table

Every number below has a source. Status lines are from the claims index unless
marked otherwise.

| Project | Hard evidence | Ships now | Buyer | Verdict |
| --- | --- | --- | --- | --- |
| **mcp-weight** | npm 0.1.0 and 0.2.0 on 2026-10-09, 0.2.1 on 2026-10-13; **458 downloads in the first week** (2026-10-05 to 2026-10-11); 6 MCP clients; read-only, secret-redacting | **Yes**, npm | Developer | **Only proven demand.** Type 1, no revenue model |
| **fixture-cad** | PyPI `fixture-cad` 0.2.0, Apache-2.0; pytest 140, FreeCAD 92/0, Blender 29/0; **60-case planner benchmark 96.7-98.3% versus 57.6-74.6%** for the closest open-source assistant | **Yes**, PyPI | CAD and 3D professional | **Best shipped product with a verifiable advantage.** Narrow market |
| **vkeys** | No `get` command by design; named profiles, rotation, scrubbed audit log; CI green; shipped (user, 2026-11-12) | **Yes** | Agent operator | **Best wedge for aiSL.** No recorded traction number |
| **eyewright** | PyPI v0.4.0 on 2026-10-12, Apache-2.0, zero required deps; 4 surfaces; 2,000-decision replay with Brier and KL; source private since 2026-11-07 | Yes, PyPI | Unclear | Shipped, buyer unresolved |
| **control-plane** | 296 commits in about 5.5 weeks; 459 tests, 3 skipped; 2 runtime deps; **79% of commits agent-authored**; shipped and used daily | Yes, local | Developer | Credibility asset. Thin moat |
| **aiSL** | 122 commits in 26 days; 716 tests (695 pass, 21 Postgres-gated skips); 32 ADRs; 39 claims; ~14k lines, 48 modules; 2 runtime deps | No, library plus proof suite | Security lead | Highest ceiling, hardest door |
| **SQWease** | Zero-dep static app, 5 languages, SM-2; WCAG 2.2 AA, Lighthouse accessibility 1.0 on all six pages | Yes, GitHub Pages | Language learner | Live, free, no revenue shape |
| **LSM** | 240+ tests; 8 benchmark suites; 1.000 versus 0.100 preference recall; QLoRA about $8 and 9.3h | No | Researcher | Preprint in preparation. Not a product |
| **kgp** | P0 end-to-end plus evals (repo, 2026-10-27); claims index says zero pipeline code (summary dated 2026-10-15) | No | The author | Kept personal, by decision |
| **NextDish** | 339 commits, 131+ components, 20+ tables, 50+ RLS policies, ONNX Llama 3.2 1B offline; YC S24 applied, not accepted | Dead, domain lapsed | Consumer | **0 users.** Not a lead |
| **allSoft** | PX4 SITL plus Gazebo in Docker; 4/4 reference scenarios pass live | No | Robotics | Harness, not product |
| **immortal-ide** | Fork of Void; 37 commits; 5-scenario agent benchmark | Packaging in progress | Developer | Saturated category |
| **creative-os** | 43 commits; zero npm runtime deps; SUGGESTION != CANON invariant | Stage 0 | Creator | Early |

## The finding

My earlier answer was half right. Restated precisely:

- **`vkeys` is better than aiSL at getting customers.** It has an easier door
  (self-serve, minutes, low trust, sharp pain) and it now ships. But it is *not*
  better as a business: it is a per-machine developer tool with a low price
  ceiling and a thin moat.
- **`mcp-weight` has the only proof that strangers show up.** 458 downloads in
  week one is the single hardest datapoint in this portfolio on adoption. It is
  also a type 1 package with no revenue model, so it proves distribution, not
  commerce.
- **`fixture-cad` is the best example of a stranger being able to verify a claim
  and pay for it.** A published PyPI package, three green gates, and a 60-case
  benchmark showing a 20-point-plus gap over the closest open-source assistant.
  The market is narrow, which is exactly what the video warns about, but the
  evidence is stronger than anything else here.
- **`kgp` was never a candidate.** I raised it because it was the pipeline that
  ingested the source video, then evaluated it as a honeypot. That was a
  category error: it is personal tooling by your own decision, and its audience
  is not aiSL's audience. Dropped.

So the wedge recommendation stands, with a sharper reason:

> **`vkeys` and aiSL are the same story at two altitudes.** `vkeys` is "the agent
> never holds the key." aiSL is "the agent never holds authority." Same buyer,
> same trust story, demoable in fifteen seconds.

That is what makes it a wedge rather than a detour. `mcp-weight` and
`fixture-cad` have better standalone evidence but build the wrong list.

## What to do about vkeys now that it shipped

The sequencing question is closed. It fired. The open question is measurement,
and there is no traction number recorded anywhere in the index or the repo.

So: do not build more. Instrument it. A download count, a GitHub star count, and
one sentence from a stranger about why they installed it is worth more than the
next feature. If it converts, it is the wedge. If it does not, the wedge is
`fixture-cad` and the buyer changes from agent operators to CAD professionals,
which is a different company than aiSL.

## Index drift worth fixing

Reconciliation, not blame. The claims index is compiled from summaries that are
now older than the repos.

| Project | Claims index says | Repo or newer evidence says | Action |
| --- | --- | --- | --- |
| `kgp` | "Skeleton and verified environment. Zero pipeline code. Do not claim a working pipeline" (summary 2026-10-15) | `kgp/README.md` records P0 complete 2026-10-27, an eval at 18/20 QA with 20/20 citations valid, and the four-stage run executed on 2026-11-12 | Refresh the summary, then the index line |
| `vkeys` | "CI green, published repo" | `.scratch/release/0.1-state.md` describes a private repo with a pending release, and the user reports it shipped on 2026-11-12 | Confirm which is true, then update |
| `aiSL` | "ASL" naming, library plus proof suite | `BRAND.md` dropped ASL and KEPT; the product is `aisl` and the company name is open | Update the name and add the open decision |

The last one matters outside this document: the index is the page used under
pressure, and it currently uses a name that `BRAND.md` says not to use.

## What would change this answer

- `vkeys` shows no traction after a measured period: the wedge moves to
  `fixture-cad`, and the buyer changes.
- A design partner with data arrives for aiSL: the standard path in
  `business-and-ip.md` becomes the lead.
- `mcp-weight` gains a paid surface (CI gate, team dashboard): it becomes the
  best-proven lead, with the caveat that type 1 monetization is hard.

## Sources

`shared-docs/CLAIMS-INDEX.md` (compiled 2026-11-12), the per-project summaries it
cites, `shared-docs/*/key-metrics.md`, `control-plane/project-registry.yaml`,
`control-plane/VISION.md`, `vkeys/.scratch/release/0.1-state.md`,
`kgp/README.md`, `code-health-mcp/README.md`, `mcp-weight/README.md`,
`eyewright` summary via the index, and `ai-security-layer/README.md`.
