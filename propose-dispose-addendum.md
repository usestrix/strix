# Addendum to the Propose–Dispose Proposal — Two Drop-In Sections

**For:** the proposal's author (strix program)
**From:** PM review, after reading both cited sources in full
**Re:** `propose-dispose-research-proposal.md` v0.1
**Status:** ready to merge into the proposal · both source citations independently verified as real and accurately characterized

> Two changes raise the odds this lands as a paper. (1) The closest prior art is not the two cited papers — it is the LLM-critic multi-agent systems (GPTLens, VulTrial, ConColl) that appear as baselines inside VulTriage's own Table 1. They already factorize proposal from judgment and still do not break the trap; the proposal must say *why strix is different from them*, not just from single-stage detectors. (2) The C-category targeting in §3/§4.3 is mis-aimed against the Semantic Trap's own FP/FN split; correcting it sharpens H3 and feeds the funnel-efficiency story.

---

## 1. New Related-Work / positioning paragraph

> Insert into §1 (end) and mirror in §9. Drop-in prose below; citations use the proposal's existing reference style.

**The factorization is not new — making the disposer non-generative is.** A line of multi-agent LLM systems already separates *proposing* a candidate from *judging* it. GPTLens (Hu et al., in VulTriage's Table 1) pairs an auditor agent that proposes candidate vulnerabilities with a critic agent that scores them. VulTrial (Widyasari et al., ICSE 2026) runs a four-role courtroom — security researcher, code author, moderator, review board — to a verdict by multi-round debate. ConColl (Tsai et al., EMNLP 2025) cascades a single agent, a RAG-augmented agent, and a multi-agent stage, gated by model-reported confidence. All three decouple proposal from disposition, and all three remain trapped: on the PrimeVul hard-pair test set they top out at ≈0.51–0.54 accuracy (GPTLens 0.518, VulTrial 0.536, ConColl 0.513), barely above the 0.50 floor, with VulTriage's best-in-class augmentation reaching only 0.636. The reason is structural: in every one of these systems **the disposer is itself a language model judging the same artifact the proposer judged.** Precision is still owned by a model reading code, so raising proposal aggressiveness still leaks into the final verdict — the precision/recall coupling survives the agent split.

Propose–dispose differs on exactly this axis. The disposer is **not a model and does not re-read the code**: it is a deterministic, evidence-producing harness that *observes runtime behavior* — an out-of-band callback correlated to a minted token, a differential across authenticated identities, a race interleaving, a reachability path. Confirmation requires `evidence_class ≠ none`, an artifact a model cannot fabricate by reasoning harder. Because precision is owned by the harness rather than by a second LLM, raising `R_prop` cannot leak into `Prec_gate` — the property the LLM-critic systems lack. We therefore position strix not as a better single-stage classifier, and not as another multi-agent judge, but as the rung the prior work gestures toward: **the cited static-analysis work (Semantic Trap, VulTriage) approximates behavior from static artifacts; the multi-agent work re-judges those artifacts with more LLMs; strix executes the target and gates on observed behavior.** This is the move that converts an architectural preference into a falsifiable break of the trade (H1).

**Positioning ladder (revise §9 to four rungs, prior art named):**

| Rung | Representative | Unit of analysis | Disposer | Trap broken? |
|---|---|---|---|---|
| Raw tokens | PrimeVul prompting | static source | model | No |
| + static structure | VulTriage (Tang et al.) | static AST/CFG/DFG | model | No (0.64 acc ceiling) |
| + distilled reasoning / CoT | Semantic Trap (Huang et al.) | static source + CoT | model (self) | No (floor-effect "escape") |
| + multi-agent factorization | **GPTLens / VulTrial / ConColl** | static source | **another LLM** | **No (≈0.51–0.54 acc)** |
| + observed runtime behavior w/ evidence | **strix (propose–dispose)** | **running deployment** | **deterministic harness** | **claim under test (H1)** |

> The added fourth rung is the load-bearing one. Without it, a reviewer asks "isn't this just GPTLens with extra steps?" and the contribution looks incremental. With it, the novelty is precise and single-sentence: *we replaced the LLM critic with a deterministic behavioral oracle.*

---

## 2. Revised §3 hypotheses + §4.3 intervention targeting

> The Semantic Trap's Finding 5 splits the C1–C8 taxonomy by failure direction: **C1 (control-flow) + C2 (API hallucination) drive false positives; C5 (CWE misapplication) + C6 (concurrency) drive false negatives; C5 is most frequent overall.** Proposal-stage interventions exist to raise **recall**, so they must target the **FN-drivers (C5, C6, and the FN-side of C3/C7)** — not C1. The current draft maps Control-Path → C1/C3, but C1 is an FP-driver; attacking it does not lift recall. Re-tag as follows.

### 2a. Corrected intervention → category map (replaces §4.3 list)

| Intervention | Targets (corrected) | Failure direction | Effect in propose–dispose |
|---|---|---|---|
| **Knowledge-Path priors** (per-endpoint-class CWE definitions/boundaries at proposal time) | **C5** (CWE misapplication — *most frequent FN-driver overall*) | False negative | **Raises `R_prop`** (recall) |
| **C1–C8 self-interrogation checklist** (force consideration of concurrency, trust boundaries, delegated checks before declining to propose) | **C6** (concurrency), **C7** (trust-boundary, FN side) | False negative | **Raises `R_prop`** (recall) |
| **Control-Path context** (verbalized route→handler→auth-mw→sink — the P4 reachability seam) | **C3** (scope/context isolation — caller guarantees, up/downstream validation) | FN side of C3 | **Raises `R_prop`** via reachability/context |
| *(same intervention, second-order effect)* | **C1** (control-flow misread — *FP-driver*) | False positive | **Funnel-efficiency gain** (fewer spurious proposals → fewer wasted harness runs), **not** recall |

**Key reframing:** Control-Path is doing two different jobs at once, and the proposal should not bill both as recall. Its recall contribution flows through **C3** (knowing the auth middleware and caller context prevents missing a genuinely reachable sink). Its **C1** contribution reduces false-positive proposals, which in a gated system is a **compute saving** measured by `funnel efficiency = harness_runs / |C|` (§4.1, §6) — a first-class result, not a footnote. This turns an apparent mis-targeting into evidence *for* the doctrine: the precision-side intervention shows up as cheaper funnels, the recall-side interventions show up as higher `R_prop`, and the two are cleanly separable because they live in different metrics.

### 2b. Revised hypothesis H3 (replaces the H3 row in §3)

| # | Hypothesis (revised) | Falsifier |
|---|---|---|
| **H3 — proposal interventions lift recall on their FN-target categories** | Knowledge-Path raises `R_prop` on **C5**-attributed misses; the C-checklist raises `R_prop` on **C6/C7**-attributed misses; Control-Path raises `R_prop` on **C3**-attributed (reachability/context) misses. Each shown by single-intervention ablation, measured as recall-over-known-labels on the targeted category. | An intervention shows no significant `R_prop` gain on its **FN-targeted** category. |
| **H3b — Control-Path's precision effect is a funnel-efficiency gain, not a recall gain** | Adding Control-Path lowers **C1-attributed** false-positive proposals, reducing `harness_runs / \|C\|` (better funnel efficiency) **without** materially changing `R_prop`. | Control-Path's only measurable effect is on `R_prop`, with no funnel-efficiency improvement (would mean C1 is not behaving as the FP-driver the source reports, or the gate is absorbing FPs for free). |

> Splitting H3 into H3 (recall) and H3b (efficiency) makes the per-category predictions falsifiable in the *right* direction and gives E3's ablation two distinct readouts instead of one muddled one.

### 2c. E3 ablation — what to report (replaces E3 cell in §5)

Run **Full vs. −Control vs. −Knowledge vs. −Checklist**, and for each report **two** numbers, not one:
- `R_prop` overall **and per targeted FN-category** (C5 for Knowledge, C6/C7 for checklist, C3 for Control-Path) — tests H3.
- `funnel efficiency = harness_runs / |C|`, with the C1-attributed false-positive-proposal rate broken out — tests H3b.

Expected signature if the doctrine holds: Knowledge and checklist move `R_prop` on their categories; Control-Path moves both `R_prop` (via C3) **and** funnel efficiency (via C1 FP-reduction). If Control-Path moves *only* recall or *only* efficiency, the source's FP/FN split does not transfer to the agentic regime — itself a publishable finding.

---

## 3. Carry-forward caution (one line for §6 Threats)

Both cited papers operate on **fine-tuned 7–8B classifiers over static C/C++ function pairs** (PrimeVul/DiverseVul/CVEFixes). Their specific magnitudes — FPR, Spearman ρ, F1 — establish the *shape* of the trap, not its coordinates in strix's frontier-agentic, live-target regime. Keep E1/M4's single-stage baseline self-measured; never imply the papers' numbers transfer. The C1–C8 taxonomy is itself an LLM-as-judge artifact (Semantic Trap §IV-D explicitly cautions it describes failure *descriptions*, not internal cognition), so treat "attacks C5" as "attacks the C5-described failure mode," with the same measurement softness.

---

### Verification trail (so the author can trust the above without re-reading)
- **Semantic Trap** = Huang, Sun, Zhang, Yang, Liu, Liu — arXiv 2601.22655v3. C1–C8 = Table V; FP/FN split + "C5 most frequent" = Finding 5; gap ρ 0.033–0.074, p<0.05 = Finding 4 / Table IV.
- **VulTriage** = Tang et al. — arXiv 2605.09461v2. Triple path = §3; 0.6356 Acc / 0.6907 F1 = Table 1; GPTLens/VulTrial/ConColl baselines + their accuracies = Table 1; GPTLens "auditor proposes / critic scores" wording = §4.1.
