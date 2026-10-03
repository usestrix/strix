---
name: bounty_hunting
description: Run a scoped bug-bounty engagement against a HackerOne/Bugcrowd program — read the program scope + rules of engagement, dedupe against disclosed reports, then validate novel issues into submission-ready findings with evidence
---

# Bug-bounty hunting (Strix 2 — scoped, deduped, submission-ready)

Hunt a single authorized bug-bounty program for **novel, validated** issues worth submitting. A bug-bounty
authorization is **conditional on the program's rules** — scope and rules of engagement are the contract, not
suggestions. Stay inside them and every finding is authorized testing; step outside and it is not.

## 1. Read the engagement first (`bounty_scope_status`)
Start every run by calling `bounty_scope_status`. It gives you:
- **Scope** — the in-scope web/api/network/cloud assets and the **exclusions** (assets carved out of a broad
  wildcard). Scope is enforced at the tool boundaries; an out-of-scope action is refused. Use
  `check_scope("<target>")` before touching anything you have not already confirmed.
- **Unmapped in-scope assets** — mobile apps, source bundles, binaries the scope engine cannot gate. They are
  in scope per the program; test them deliberately, not by firing network tools at them.
- **Rules of engagement (hard constraints)** — the rate limit, prohibited techniques, ineligible bug classes,
  and the intrusive posture. Obey every one. `active_tools_allowed: false` means **recon-only** (see §4).
- **`allow_intrusive`** — follows the program: a state-changing proof is permitted only when it is true.

## 2. Dedupe before you commit (`check_duplicate`)
Payouts go to the first valid report, so a known issue is wasted effort. Before you treat anything as
submittable, call `check_duplicate(title, asset, vuln_type)`. It ranks the program's disclosed reports and
returns a `likely_duplicate` / `possible_duplicate` / `novel` verdict. The verdict is **guidance**: open the
matched reports and judge for yourself. A `novel` result when nothing was loaded only means nothing was
loaded — still reason about whether the issue is already known.

## 3. Two-tier discipline (candidate → validated finding)
- A scanner/recon signal — a reflected parameter, an enumerable id, an open redirect candidate, a version
  guess — is a **candidate** (`create_candidate`), never a finding.
- It becomes a **validated finding** only when you demonstrate the security impact with **captured request/
  response I/O**, file `create_vulnerability_report`, then `promote_candidate`. Reconcile candidates vs.
  findings before you finish; unproven leads stay candidates.

## 4. Recon-only mode
When `active_tools_allowed` is false (the program prohibits automated scanning and the run chose recon-only),
do **not** fire active scanners or exploitation. Map the attack surface from public information, dedupe
against disclosed reports, and produce a prioritized **manual test plan** the operator can execute by hand.

## 5. Submission-ready evidence (per validated finding)
Each finding you would submit needs: a clear **title**; the **in-scope asset**; **CWE** and a **CVSS** vector
+ severity; **numbered reproduction steps**; the **raw request/response or transcript** (not paraphrased); a
one-paragraph **impact** statement in the program's terms; and a **dedupe note** — the `check_duplicate`
verdict and why this is not one of the matched reports. Prefer a **non-intrusive** proof (show access, do not
exfiltrate real data or change state) unless `allow_intrusive` is true and the proof genuinely needs it.

## Rules that keep this honest
- Out of scope = stop. Exclusions and the rate limit are not negotiable; prohibited techniques (DoS, social
  engineering, physical, testing third-party services) are never performed.
- A banner, a version, a reflected value, or a scanner hit never validates on its own — demonstrate impact.
- Do not submit known-ineligible issue types, and do not re-report a known/disclosed issue.
- You are testing on the program's authorization; if a rule and a lead conflict, the rule wins.

## Further reference (external, Apache-2.0)
The `mukul975/Anthropic-Cybersecurity-Skills` collection (recorded in `THIRD_PARTY.md`) has technique guides
you may consult — e.g. `conducting-api-security-testing`, `exploiting-idor-vulnerabilities`,
`web-application-penetration-testing`. Adapt their techniques to Strix's tools, this scope, and this evidence bar.
