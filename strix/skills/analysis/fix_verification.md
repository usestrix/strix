---
name: fix_verification
description: How to verify a proposed code fix before shipping it — the ordered gates, what disqualifies a fix, and when to withhold the suggestion instead
---

# Fix Verification

When you attach `fix_before` / `fix_after` to a code location, you are not
writing advice. You are writing a suggestion block that a reviewer can
apply with one click, straight into their codebase. An unverified fix is
worse than no fix: it converts your uncertainty into their merged commit.

This skill covers what you must establish before that happens.

## Judge in This Order

1. The current state is correctly classified — vulnerable, already safe,
   or unproven.
2. The fix completely closes the broken security boundary.
3. Legitimate behavior and compatibility are preserved.
4. The relevant repository checks pass.
5. The change follows the repository's own conventions.
6. The patch contains only what properties 1–5 require.

**Never trade an earlier property for a later one.** A smaller, tidier,
more idiomatic patch that leaves the boundary open is a failure. Minimal
means *the smallest repository-native change that satisfies everything
above it* — not the fewest lines.

## Before You Edit

Establish these from the code, not from assumption:

- The source → sink path or the specific broken control.
- The attacker-controlled input and the preconditions it needs.
- **The security invariant** — state it in one sentence. "Only the owning
  tenant may read this record." "The extracted path must stay inside the
  destination directory." If you cannot state the invariant, you cannot
  tell whether your patch enforces it.
- The narrowest place that invariant can be enforced.
- The legitimate behavior, public APIs, and error semantics that must
  survive the change.
- The repository's existing helpers and precedents for this kind of
  control. Reach for the codebase's own validator before inventing one.

## The Verification Gates

Run these **in order**. A failure at any gate disqualifies the fix —
revise the patch or withhold it. Do not compensate for a failed gate by
making the diff smaller or the write-up longer.

**1. Applicability.** Read the final diff. Confirm it contains nothing
unrelated, that `fix_before` still matches the file character-for-
character, and that `start_line`/`end_line` still cover exactly those
lines. Run the narrowest syntax / import / type check available.

**2. Security closure.** Re-run the original PoC against the patched
code. If you cannot execute it, re-trace source → control → sink through
the *patched* source and state precisely which step now fails and why.
"The fix adds validation" is not closure; "the fix rejects `../` before
the path reaches `open()`, and `open()` is the only sink on this path" is.

**3. Bypass review.** Re-read the finding and the diff *without* leaning
on the reasoning that produced the patch — you are looking for what that
reasoning missed. Trace the changed branches from their direct callers.
Check equivalent sinks and sibling call sites of the same helper. Try at
least one alternate malicious input class: different encoding, different
content type, a null byte, a unicode homoglyph, a nested/doubled
payload, a different HTTP verb. A control that catches your one payload
and nothing else has not closed the boundary.

**4. Preserved behavior.** Exercise the legitimate case through the same
boundary. Confirm the APIs, error semantics, and compatibility
constraints you recorded still hold. A fix that breaks the feature will
be reverted, which means the vulnerability comes back.

**5. Repository checks.** Run the focused tests covering the changed
lines, then the owning package's tests, then the applicable formatter,
linter, and type checker. Use the repository's own commands.

Where practical, confirm the check would **fail if the security change
were removed**. A test that passes both with and without the patch is
proving nothing.

## What Disqualifies a Fix

- It closes your specific payload but not the input class.
- It sanitizes at the wrong layer — after the value was already used, or
  in a helper that other callers bypass.
- It relies on a caller passing the right flag, or on a config the
  operator has to set.
- It fails open: the new check sits inside a `try`/`except` that swallows
  the failure, or returns "allowed" on error.
- It weakens authentication, authorization, tenant isolation, input
  validation, sandboxing, or logging to make something else pass. Never
  do this.
- It silently accepts, truncates, or reinterprets unsafe state instead of
  rejecting it.
- It drags in unrelated refactors, sibling findings, or architectural
  redesign.

## Withholding the Fix

If you cannot pass the gates, that is a legitimate outcome — say so
rather than shipping a guess. Drop `fix_after` from the location, leave
it informational, and put the remediation in prose in
`remediation_steps` instead. State in `fix_verification` exactly which
gate you could not clear and what was missing: the command that failed,
the service you could not start, the decision that needs a human.

Withhold and explain when:

- The complete fix depends on an unresolved product or public-API
  compatibility decision.
- The invariant cannot be enforced without cross-subsystem changes you
  cannot validate.
- You could not establish that the vulnerable path is real in the
  current checkout. Do not patch an adjacent weakness as a consolation
  prize, and do not add speculative defense-in-depth to a path you never
  proved was reachable.

## Recording It

Everything above goes in `fix_verification`, which is required whenever
any location carries a `fix_after`. Write the actual commands and their
results, grouped by gate, and mark every gate you could only reason
about — rather than execute — as an explicit gap. Do not hide proof
gaps; a reviewer who knows gate 5 was skipped can run it themselves, but
one who was told it passed cannot.
