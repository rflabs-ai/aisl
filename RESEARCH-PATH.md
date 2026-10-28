# RESEARCH PATH

Candidate research directions for someone who may take this up as a project
rather than a product. Each entry names the question, why it is genuinely open
*here* (grounded in this repo's own stated residuals, not a literature guess),
the first experiment that would show whether there is a paper, the artifact it
produces, and how hard it actually is.

The honest framing up front: ASL is a working enforcement plane with unusually
honest documentation of its own ceilings. That makes it a good *instrument* for
research — you have a real system to measure, and a list of limitations that
were written by someone trying to be accurate rather than persuasive. It is not
evidence of anything beyond itself.

---

## 1. Semantic exfiltration detection (from H7's named residual)

**Question.** Can you detect that a *meaning* crossed a boundary when no byte
pattern, encoding, or hash matches?

Everything shipped is syntactic: canaries, base64/hex/url variants, a byte cap.
ADR-037 says plainly that paraphrase and steganography are out of reach.

**Why it is open.** The evaluation problem is the real one, and it is why the
field has not settled: there is no ground truth for "this summary did or did not
convey the patient row". You cannot measure a detector without one.

**First experiment.** Build a *controlled* disclosure benchmark: take documents,
generate N summaries at graded levels of specificity (verbatim → paraphrase →
abstraction → allusion), and measure whether a detector ranks them monotonically.
Monotonic ranking is a weaker but measurable target than binary detection.

**Artifact.** A benchmark + a detector baseline (embedding similarity, entity
coverage, information-theoretic overlap). Publishable even if the detector is
mediocre, because the benchmark is the contribution.

**Difficulty.** Medium to build, hard to make convincing. Nearest neighbours:
membership inference, data extraction attacks on LLMs.

---

## 2. Completeness of capability attenuation (from H1's residual)

**Question.** Is the attenuation check *complete* — does it admit no escalation
path — or merely sound on the paths someone thought of?

ADR-023 replaced "the caller asserts its authority" with "the caller presents a
signed parent". The check is a six-dimension subset test. What is not proven is
that no composition of legal issuances yields authority the root never held.

**Why it is open.** It is a formal question about a real implementation, and
ADR-042 only bounded it (375 states, hand-chosen). Nobody has modelled the
*issuance* relation, only the decision.

**First experiment.** Model issuance in Alloy or TLA+ over the real six
dimensions; ask the solver for a counterexample where a chain grants more than
its root. If it finds one, that is a paper and a CVE-shaped bug. If it proves
none exists under stated assumptions, that is the paper.

**Artifact.** A machine-checked model + the modelling harness. This is the single
highest-value formal-methods project in this repo because the invariant is
load-bearing for the entire product claim.

**Difficulty.** High — needs formal methods competence, but the model is small.

---

## 3. Taint through model inference (from H4's residual)

**Question.** Can provenance survive the model, or is "the model is a black box"
a permanent wall?

H4 labels inputs. It cannot say that a request was *caused* by a document. Every
agent-security product on the market has this hole and mostly papers over it.

**Why it is open.** Interpretability is the bottleneck, not engineering. But
there is a tractable version: not "which token caused this", but "does the output
depend on the injected span at all" — an ablation question, answerable with
counterfactual re-runs.

**First experiment.** Take the malicious corpus, run the same task with and
without the injected sentence, and measure whether the *request set* changes. If
it does, you have a behavioural taint signal that needs no internals.

**Artifact.** An ablation-based influence metric + measurements across models.
Cheap to run, surprising if it works.

**Difficulty.** Medium. The measurement is easy; making it robust across models
is the work.

---

## 4. Adversarial synthesis against the enforcement plane (from H14)

**Question.** Can you *generate* attacks on a capability system faster than
humans write them — not prompt injections against the model, but policy and
capability forgery against the PDP?

H14's mutation lane mutates the *policy* and requires the goldens to notice. That
is one axis. The general problem is a differential fuzzer across policy engines
(ASL vs Cedar vs OPA) looking for decisions that disagree on the same input.

**Why it is open.** Differential testing of authorization engines is barely
done, and the engines are now commodity.

**First experiment.** Encode the same policy in ASL and Cedar, generate random
requests over a shared vocabulary, and diff decisions. Every disagreement is
either a bug in one engine or a semantic ambiguity in both.

**Artifact.** A cross-engine differential harness + a corpus of disagreements.
Very citable, and useful to the maintainers of both.

**Difficulty.** Medium-low. Highest ratio of result to effort on this list.

---

## 5. Verifiable audit without disclosure (from H11's residual)

**Question.** Can you prove a property of an audit log to a third party — "no
event of class X occurred in this window" — without revealing the events?

The log is a hash chain with external anchors. That proves *integrity*. It does
not prove a *statement* about content without handing over the content.

**Why it is open.** ZK proofs over long event sequences are expensive, and the
practical framing (what would a regulator actually accept?) is unexplored.

**First experiment.** Prove "no export of phi in window W" over a small log with
a succinct proof system; measure proof size and verification time against log
length.

**Artifact.** A prototype + cost curves. Strong paper if the constants are sane.

**Difficulty.** High. Needs cryptography depth.

---

## 6. Fail-closed availability under adversarial faults (from H15's residual)

**Question.** Fail-closed is correct and incompressible: one broken dependency
stops all work, and an adversary who can induce the fault gets a denial of
service for free. Can you bound that loss without widening authority?

**Why it is open.** H15 made the failure loud and measured. It did not make it
*cheap*. The trade is named and accepted, not solved.

**First experiment.** Pre-authorised degraded operation sets: capabilities that
are valid *only* while a named dependency is unhealthy, scoped to actions that
cannot leak. Then measure how much legitimate work survives a fault without any
decision widening.

**Artifact.** A degradation algebra + measurements. Practical, less glamorous,
and directly useful.

**Difficulty.** Medium.

---

## 7. Benchmarks for agent containment

**Question.** What does "secure agent runtime" even mean numerically, and can
independent teams compare?

There are security benchmarks for models (harm refusal) and none for runtime
*containment*. ASL ships measured SLOs and an adversarial harness; that shape,
generalised, could be the SPEC of this space.

**First experiment.** Define 8-10 containment properties (cross-tenant, egress,
capability forgery, taint laundering, artifact smuggling), each with a pass
criterion and a reference implementation, and show three systems' scores.

**Artifact.** A public benchmark suite. Highest community leverage, lowest
novelty — which is fine for a benchmark.

**Difficulty.** Medium, mostly coordination and maintenance.

---

## How to pick

- **Want a result in weeks:** #4 (differential policy fuzzing) or #3 (ablation
  taint).
- **Want a formal contribution:** #2. It is also the one that could find a real
  bug in shipped code.
- **Want to work on the hard problem everyone avoids:** #1 or #5.
- **Want something that outlives the paper:** #7.

The trap in all of them is evaluation. Every direction here has a cheap
measurement and an expensive one, and the expensive one is what makes it
publishable. Budget for the evaluation, not the prototype.

---

## What this repo gives you that a fresh project would not

- A real enforcement plane with 800+ tests to instrument.
- A written residual list in `SECURITY_CLAIMS.md` — a pre-surveyed problem set
  written by someone with an incentive to be accurate.
- A threat model set (`threat-models/`) and a corpus that already encodes what
  "attack" means here.
- Credibility: claims with stated ceilings are rare, and reviewers notice.
