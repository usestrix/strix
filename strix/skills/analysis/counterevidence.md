---
name: counterevidence
description: Closure discipline for security findings — what counts as proof of safety, what does not, and how to record an unresolved candidate instead of silently dropping it
---

# Counterevidence and Closure Discipline

Proving a bug is real is only half the job. The other half is proving a
candidate is *not* real — and that half is where both false positives and
false negatives come from.

This skill governs how you close a candidate. It applies to every
candidate you open, whether it came from a scanner, a code read, a crawl,
or a hunch.

## Three Closure States

Every candidate you open ends in exactly one of these. There is no fourth
state, and "I moved on" is not one of them.

**1. `confirmed`** — you have a working PoC or, in white-box, a complete
source → control → sink → impact trace plus evidence the path is
reachable. File it with `create_vulnerability_report`.

**2. `ruled_out`** — you can name the **specific control** that makes the
code safe, at a specific location, and you have checked that the control
actually runs on the attacker's path. "Named control" means you can
complete this sentence with concrete detail: *"This is safe because
`<control>` at `<file:line or observed behavior>` `<does what>` before
`<sink>`, on every path an attacker can reach."* If you cannot complete
that sentence, you are not in `ruled_out`.

**3. `open_proof_gap`** — the candidate is plausible, you could not
confirm it, and you also could not name a control that rules it out. This
is a legitimate, expected outcome. Record it with
`record_coverage(outcome="needs_follow_up")`, carry it up in
`agent_finish(open_items=[...])`, and reflect it in `counterevidence` /
`confidence_rationale` if you file a related report. Do **not** convert
it to `ruled_out` to tidy up your worklist.

The failure mode this exists to prevent: an agent reads code, feels
uncertain, and quietly closes the candidate. That is an
`open_proof_gap` being mislabelled as `ruled_out`, and it is how real
vulnerabilities get missed.

## What Does NOT Rule Out a Candidate

Each of these is a common, plausible-sounding reason to drop a candidate.
None of them is sufficient on its own.

**Generic trust in a library or helper.** "It uses a well-known
sanitizer / the framework escapes this / the ORM handles it" is not
counterevidence. You must confirm *that* call, with *those* arguments, in
*that* context. Escaping helpers are context-specific: an HTML escaper
does nothing in a JS or attribute context, a SQL identifier quoter is not
a value quoter, and a path joiner is not a containment check.

**A control that runs on a different path.** Middleware, a decorator, or
a guard that protects the common route does not protect a sibling route,
an internal caller, a batch/async job, or an admin alias that reaches the
same sink. Check the specific path.

**A control that runs at the wrong time.** Validation *before* a
redirect, canonicalization *after* a path is already materialized, a
containment check *after* extraction, or an ownership check *after* the
object was already fetched and returned — these are ordering bugs, not
controls. Establish that the control runs before the dangerous effect.

**A control that can fail open.** Hardening flags set inside a
`try`/`except` that swallows failures, a parser feature that a caller can
override, a factory or config object supplied by the caller, or a
allow-list that is empty by default — all leave the candidate alive.

**A safe sibling.** If one call site is correctly guarded, that says
nothing about the other call sites of the same helper. Never let a safe
instance close a vulnerable one, and never collapse multiple instances
into one candidate just because they share a root cause — each reachable
instance stands or falls on its own.

**Missing information.** "I could not find a caller", "I could not tell
if this is deployed", "I could not determine whether this route is
exposed", "I could not stand up the service" — every one of these is an
`open_proof_gap`, not proof of safety. Missing evidence is missing
evidence; it is not evidence of absence.

**Difficulty.** "The build failed", "it needs credentials I don't have",
"the service mesh isn't available" are reasons to record a proof gap and
move on to the next candidate — not reasons to mark it clean. Do not let
one hard environment setup consume the budget you need for sibling
candidates.

**Operator configurability.** "An operator *could* configure a filter",
"this is a documented feature", "it's off by default" are not controls.
What ships and what is reachable is what matters.

**Being internal.** Internal-only, admin-only, or authenticated-only
reduces severity — it does not make the finding unreal. Downgrade it;
do not delete it.

## Recording Closure

Closure is only useful if it is written down. Every surface you assess
gets a `record_coverage` entry:

- `confirmed` → outcome `reported`, once the report is filed.
- `ruled_out` → outcome `ruled_out`, with the named control in
  `evidence`. If you cannot name it, this is not `ruled_out`.
- `open_proof_gap` → outcome `needs_follow_up`, with the specific gap in
  `evidence`.
- Tested thoroughly with nothing to show for it → `no_issue_found`.
- The risk cannot apply to this surface at all → `not_applicable`, with
  the reason.

A scan that records only findings cannot tell the reader what was
reviewed and cleared, which makes every clean area indistinguishable
from an unvisited one.

Closure is not permanent. The ledger is shared across every agent, and
a surface someone left at `needs_follow_up` is an invitation: if you
had the credentials, the running service, or the reachability proof
they lacked, move their entry with `update_coverage` rather than
recording a parallel one. This runs both ways — a `ruled_out` whose
named control does not cover the path you just found goes back to
`reported` or `needs_follow_up`, with what changed in `evidence`. The
previous state is kept as history, so correcting the record costs
nothing and leaving it wrong costs a finding.

## What DOES Rule Out a Candidate

- You executed the attack and it demonstrably failed, and you understand
  *why* it failed (not just that the response was a 403).
- You can point at the control, at a location, and show it runs on every
  attacker-reachable path to the sink, before the effect, without a
  fail-open branch.
- The sink is not actually dangerous in this context, and you can say
  what makes it inert.
- The input is not actually attacker-controlled, and you traced it to a
  trusted origin rather than assuming it.

Negative controls make a `ruled_out` much stronger: send the payload that
*should* work if the bug were real, and show it is blocked, while a
benign variant succeeds. That distinguishes "the control works" from "the
endpoint is broken/unreachable for unrelated reasons".

## Before You File a Report

Run this pass on every finding before calling
`create_vulnerability_report`:

1. **Argue the other side.** Spend real effort building the strongest
   case that this is *not* exploitable, or not as severe as you think.
   Look for the guard you might have missed, the deployment context that
   constrains it, the precondition you assumed.
2. **Record what you found** in `counterevidence`. If you found a real
   constraint, say what it is and why it does not neutralize the finding.
   If you genuinely found nothing, say what you checked — "no input
   validation, WAF, or authorization check was found on this path; tested
   both authenticated and unauthenticated" — not just "none".
3. **Set `confidence` honestly.** A working PoC against a live target is
   `high`. A complete static trace you could not execute is at best
   `medium`, and `confidence_rationale` must name the gap. Do not inflate
   confidence to make a finding look better; an accurate `medium` is far
   more useful to the reader than a `high` that does not survive triage.
4. **State what would move the severity** in `severity_change_conditions`
   — the one concrete piece of evidence that would raise or lower it
   (e.g. "confirmation that this route is exposed to unauthenticated
   internet traffic would raise this to critical").

## Reporting an Unconfirmed Candidate

Dynamic proof is the standard. But when you have a complete
source → control → sink → impact trace and runtime reproduction is
genuinely out of reach (no credentials, unavailable internal services, a
build that cannot run in the sandbox), a static-only finding is still
reportable — at `confidence: medium` or `low`, with the missing runtime
proof named explicitly in `confidence_rationale`.

What is **not** acceptable is a scanner hit with no trace, a "this
pattern is usually dangerous" claim, or a finding where you never
identified the attacker-controlled input. Those are not proof gaps, they
are non-findings.

If you are unsure whether a candidate clears this bar: it clears it if
you can name the input, the path, the missing or broken control, and the
effect. It does not if any one of those is a guess.
