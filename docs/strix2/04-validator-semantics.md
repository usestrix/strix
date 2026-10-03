# Phase 4 — Generalized Finding + PoC Validator Semantics

> **Status: ACCEPTED (2026-09-26) — all 8 ⟐ DECISIONs adopted at their recommended defaults.**
> Implementation is proceeding on this basis. The candidate (lead) tier — schema, store, tools, and
> run-time registration — has landed (see `01-design-log.md`, Phase 4); remaining work (network/cloud
> validated classes, the Leads section in the executive report, scope-coupled proof) follows in Phase
> 3/4. If any decision is revisited, this doc is updated first and the affected code revised.

Grounded in the current code (see `00-codebase-map.md` §5): `create_vulnerability_report`
(`strix/tools/reporting/tool.py`), `create_dependency_report`, and `ReportState`
(`strix/report/state.py`).

---

## 1. Why this is the whole ballgame

A fork that "runs nmap and prints ports" is worthless because it has no validation discipline. Strix's
value is that **every reported finding is a real, reproducible, demonstrated impact — never a scanner
guess.** Extending scope to network/cloud/API/infra is only worth doing if that discipline extends with
it. The failure mode to design against is *scanner-noise laundering*: a tool emits "S3 bucket may be
public / port 3306 open / CVE-2023-x present," and the agent files it as a finding. That must be
structurally impossible.

## 2. What already exists (build on it, don't reinvent)

- **The web gate is already the "validated" bar.** `create_vulnerability_report` hard-requires
  `poc_script_code` + `evidence` + a counterevidence/confidence/severity-change triad; CVSS is *computed*
  from an 8-metric vector; HTTP evidence (`http_exchange_ids`) is *verified against the live proxy* before
  storage. This is exactly "demonstrated impact with captured I/O." **Web semantics do not change.**
- **A reachability gradient already exists for supply-chain.** `create_dependency_report` carries
  `reachability ∈ {not_imported, imported, vulnerable_symbol_used, reachable_call_path, unknown}` plus a
  *contextual* CVSS rated to what the code actually does. This is the candidate→validated idea, already in
  the tree, for one domain. The two-tier model **generalizes this**, it doesn't replace it.
- **Upstream already has an "unconfirmed lead" channel**, but it's *ephemeral*: `agent_finish(open_items=…)`
  (narrative handoff to the parent) and `record_coverage` (what was tested). These are not durable, deduped,
  report-rendered records. The candidate tier makes leads first-class **without** discarding these.

## 3. The two-tier model

| | **Candidate (lead)** | **Validated (finding)** |
|---|---|---|
| Produced by | scanner/recon/static output, or reasoning | a demonstrated, captured, reproducible impact |
| Impact shown? | No — potential only | Yes — per §4 per-class bar |
| In the report? | separate **Leads** section, never in the finding count | the report's findings; counted, in the exec summary |
| Counts toward metrics? | No (tracked separately as recall/coverage) | Yes (precision denominator) |
| Storage | `ReportState` candidate list | `ReportState.vulnerability_reports` (today's store, unchanged) |
| Lifecycle | `open` → **promoted** to validated, or **dismissed** (ruled out, with reason) | filed → revised → withdrawn (today's flow, unchanged) |

**Core invariant (unchanged and now universal):** a record only enters the *validated* set when the
per-class impact bar in §4 is met, with the evidence bundle in §5 attached. Everything else is at most a
candidate. Default report output = validated only; candidates are available as leads on request / in a
separate section.

**Promotion** is the same gate as today: you call `create_vulnerability_report` (or its future
network/cloud siblings) with the proof; if a candidate id is referenced, the candidate is marked
`promoted` and linked. **Dismissal** mirrors `delete_vulnerability_report`: a candidate ruled out is
closed with a stated reason (kept for the coverage/recall record, not shown as a finding).

⟐ **DECISION 3a — Do candidates dedupe against validated findings?**
*Recommended default:* yes — reuse `report/dedupe.py`; a candidate whose root cause matches an existing
validated finding is auto-linked, not shown twice.

⟐ **DECISION 3b — Are candidates persisted to disk by default (a `candidates.json` beside
`vulnerabilities.json`, and a Leads section in the report), or in-memory only unless `--emit-candidates`?**
*Recommended default:* persist to `candidates.json`; render a collapsed "Leads (unvalidated)" section.
Rationale: recall is a Phase 6 metric and leads are the honest audit trail of what was seen-but-not-proven.

## 4. Per-class definition of "demonstrated impact"

For every class: a **candidate** is the tool/recon output; a **validated finding** requires the stated
interaction + captured I/O. "Captured I/O" means the raw request/response or command transcript is stored
as evidence, not paraphrased.

### 4.1 Web / App — **UNCHANGED**
Keep upstream's model exactly. The existing gate is the reference definition of validated. Web candidates
are *permitted* (e.g. a reflected parameter not yet proven to execute) but web behavior is otherwise
untouched, satisfying the brief's "keep upstream's model unchanged."

### 4.2 Network
- **Candidate:** an open port; a service/version banner; a Nuclei/CVE *template match* or version-based
  CVE inference with no interaction; a default-credential pair not yet tried.
- **Validated:** a **live service interaction that demonstrates a security consequence**, with the
  request/response or session transcript captured — e.g. an authentication bypass, unauthenticated access
  to data or functionality, or a working exploit/CVE check whose captured I/O shows the vulnerable
  behavior actually occurring.
- **Never validated on its own:** an open port, a banner, or a version string. Reachability and missing
  auth affect *exploitability*, not impact (this mirrors the existing CVSS guidance in
  `create_vulnerability_report`).

⟐ **DECISION 4.2a — Version-only CVE matches.** When a service's version definitively matches a CVE but a
non-destructive exploit is unsafe/unavailable in the lab, is that ever more than a candidate?
*Recommended default:* **no** — it stays a candidate ("version-inferred CVE, not exercised") unless a
safe, deterministic behavioral probe confirms the vulnerable code path. This keeps the no-false-positive
promise; the lead is still surfaced.

### 4.3 Cloud (AWS first)
- **Candidate:** a config that *looks* public or over-permissive — a bucket whose ACL/policy reads public,
  an IAM policy granting `*`, a prowler/ScoutSuite check hit, a security group open to `0.0.0.0/0`.
- **Validated:** an **API call from the attacker's actual principal** (the least-privilege / in-scope
  credentials) that produces **unauthorized impact** — e.g. listing/reading an object or secret that
  policy should deny — with **request + response captured**, and recording the exact principal
  (ARN/account), the action, and the policy that *should* have denied it. A config that merely looks wrong
  is a candidate until the impact is reproduced with the attacker's credentials.
- **Read-only proof is strongly preferred** (read the object, enumerate the secret name, assume-role and
  observe access). Any state-changing proof (write/delete/attach-policy) is an intrusive action → gated by
  `--allow-intrusive` (Phase 1 scope) and logged. Default lab runs prove impact read-only.

⟐ **DECISION 4.3a — "Attacker principal."** In a lab we may hold admin creds. Do we require validation to
run under an explicitly-declared *least-privilege* principal (e.g. an `attacker`/`anonymous` profile named
in `scope.yaml`), and refuse to validate using ambient admin creds?
*Recommended default:* **yes** — the finding must name the principal it was proven with, and validating a
"should-be-denied" access using admin creds is itself a false positive. Anonymous/unauthenticated access
counts as a principal (`anonymous`).

⟐ **DECISION 4.3b — Exfiltration limit.** Brief says "no exfiltration beyond the minimum for a PoC." Fix
the concrete limit.
*Recommended default:* capture only object **metadata + a bounded head** (e.g. first ≤1 KiB or a hash) as
proof of read; never store full object contents in the report.

### 4.4 Infra / IaC / Container
- **Candidate:** any static scanner hit — Trivy/Checkov/Nuclei-template/Semgrep — a Dockerfile or IaC
  misconfiguration, an image CVE.
- **Validated:** a **runtime demonstration or a concrete reachable-exploit path** — the misconfig
  exploited in a running container, the vulnerable symbol reached at runtime, or a corroborated reachable
  call path (reuse the dependency `reachability` ladder: `reachable_call_path`/`vulnerable_symbol_used` =
  validated-eligible; `imported`/`unknown` = candidate).

### 4.5 Dependency / supply-chain — reconcile with existing
`create_dependency_report` stays. Position it explicitly in the two-tier model:

⟐ **DECISION 4.5a — Where do dependency findings sit?**
*Recommended default:* a dependency finding with `reachability ∈ {vulnerable_symbol_used,
reachable_call_path}` is a **validated finding** (as today); `imported`/`unknown` renders under **Leads**.
This preserves current behavior for the strong cases and stops "present in lockfile" CVEs from padding the
finding count.

## 5. The evidence bundle for a validated finding

Every validated finding ships (brief §5): **(1) reproduction steps, (2) the captured evidence, (3) the
exact credentials/scope used, (4) a re-run script where safe.** Concretely, per class:

| Class | Captured evidence (raw I/O) | Credentials / scope recorded | Re-run artifact |
|---|---|---|---|
| Web/API | proxy `http_exchange_ids` (verified) | auth context / role | request(s) as script (today) |
| Network | command + full request/response or session transcript | source position, any creds used | the exact command/script |
| Cloud | API request + response (SDK/CLI), denying policy doc | principal ARN/account, region | `aws … ` re-run script (read-only) |
| Infra/IaC | runtime transcript or reachable-path trace | runtime context | repro command / manifest ref |

⟐ **DECISION 5a — Auto re-run scripts for network/cloud.** Generate and store them by default (they
re-execute the *read-only* proof), or gate behind a flag because re-running touches the target again?
*Recommended default:* generate for read-only proofs; for intrusive proofs, store the script but do not
auto-execute, and mark it intrusive.

## 6. Classification schema additions

Keep CVSS v3.1 + CWE (unchanged, still computed). Add **optional** fields to the finding schema (additive,
no change to existing validation):
- `mitre_attack: list[str]` — technique IDs, e.g. `T1530` (cloud data), `T1078` (valid accounts). Weighted
  to the ATT&CK cloud matrix for cloud findings.
- `cis_benchmark: list[str]` — CIS control IDs (e.g. CIS AWS Foundations `2.1.5`) for cloud/infra.

⟐ **DECISION 6a — Required or optional per class?** *Recommended default:* optional everywhere, but
prompt for `mitre_attack` on cloud findings and `cis_benchmark` on cloud/infra findings. Never let a
missing framework tag block a validated finding — CVSS+CWE remain the required rating.

## 7. Data model & implementation sketch (for review, not yet built)

Additive, rebase-safe — mirrors how `create_dependency_report` was added as a sibling class:

- **`finding_class`** gains candidate handling. Validated classes stay `dynamic` / `dependency_cve` and
  add `network` / `cloud` / `infra` as the domain siblings land (Phase 3/4).
- **New tools** (registered via `register_agent_tools`, no core edit):
  - `create_candidate(...)` — files a lead (title, target, source tool, why-it-might-matter, class). Low
    bar, no PoC required. Deduped. Never counts as a finding.
  - `promote_candidate(candidate_id, …)` / or the existing `create_*_report` referencing a `candidate_id`
    — attaches the proof and moves it to validated.
  - `dismiss_candidate(candidate_id, reason)` — rules a lead out (kept for recall/coverage).
- **`ReportState`** gains a parallel `candidates` list + `candidates.json` writer and found/updated
  callbacks (mirroring the vuln callbacks), so the viewer can render a Leads panel.
- **Report writer** gains a "Leads (unvalidated)" section; the executive summary + counts stay
  validated-only.
- **Scope coupling (depends on Phase 1):** the validator's impact-proving call runs through
  `ScopePolicy.evaluate(target, intrusive=…)`. Read-only proof within scope is allowed; state-changing
  proof requires `allow_intrusive`. The principal/scope used is written into the finding.

## 8. Acceptance-criterion walk-through (brief §5)

*Lab: a deliberately-public S3 object + an open-but-unexploitable port.*
- **Port 8080 open, service present, no exploitable behavior** → `create_candidate` files a network lead
  ("open port / banner, no demonstrated impact"). It is **not** promoted: no interaction demonstrated a
  security consequence (§4.2). Appears under Leads, not in the finding count. ✅ discriminates.
- **Public S3 object** → recon files a candidate ("bucket policy reads public"). The cloud agent then, as
  the declared `anonymous`/least-priv principal (§4.3a), performs an unauthenticated `GetObject`, captures
  request + response + the denying-should-be policy + principal, keeps a bounded head as proof (§4.3b),
  and promotes it to a **validated** cloud finding with a read-only re-run script. ✅ validated with
  captured unauthorized read.

This is exactly the discrimination the brief demands: the S3 issue validates, the port stays a lead.

## 9. Consolidated decisions — ACCEPTED (defaults adopted 2026-09-26)
- **3a** ✅ candidate↔validated dedup — structural dedup implemented in `CandidateStore.add`; semantic
  (LLM) dedup via `dedupe.py` is a follow-up.
- **3b** ✅ persist candidates (`candidates.json`) — implemented; Leads section in the executive report is
  a follow-up (needs a small, logged `report/writer.py` edit).
- **4.2a** ✅ version-only CVE stays a candidate.
- **4.3a** ✅ require a named least-priv/`anonymous` principal; refuse validating with ambient admin creds.
- **4.3b** ✅ cloud exfil limit = metadata + ≤1 KiB head/hash.
- **4.5a** ✅ dependency reachability → validated vs Leads split.
- **5a** ✅ auto re-run scripts for read-only proofs only.
- **6a** ✅ ATT&CK/CIS optional, prompted per class; never blocks a finding.

Landed so far: the candidate data model (`strix/candidates/`), the `create_candidate` / `list_candidates`
/ `promote_candidate` / `dismiss_candidate` tools (`strix/tools/candidates/`), and run-time registration
(`strix/strix2_ext.py`, one-line hook in `core/runner.py`). Not yet: network/cloud validated finding
classes and their evidence channels, the Leads section in the report, and scope-coupled proof (depends on
Phase 1 scope enforcement).
