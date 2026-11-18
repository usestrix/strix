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

## Coverage Inventory

Before the gates, write down every route, handler, resolver, mutation, job
and sink the finding names, and every sibling in the same file or router
that has the same shape: loads the same resource, calls the same use case,
sits on the same mount. This list is the contract the patch has to meet.

For each entry, after the patch, quote the line (`file:line`) that enforces
the control for that entry. Two things do not count as an enforcing line:

- A route guard that only authenticates. An `adminOnly()` guard on the
  mount says who may call; it does not say which tenant's record they may
  act on.
- A shared helper the handler calls. "The export handler goes through the
  same `loadDocument` use case" is only coverage if you quote the line in
  `loadDocument` that reads the caller's identity and compares it to the
  resource. If the helper never looks at the caller, the sibling is open.

An entry you cannot quote an enforcing line for gets its own
`code_locations` entry with its own `fix_before` / `fix_after`, or the
finding says in `fix_verification` that it is left unfixed and why. The
reviewer builds this list again without seeing yours; a sibling you
skipped comes straight back as a rejection.

The same search applies to the other shapes a finding takes:

- **A leaked secret or personal data.** Find every other place the same
  value is logged, returned, cached or sent to telemetry, including the
  error handler and the metrics call next to the line you fixed.
- **A race, replay or double spend.** Find every other path that writes
  the same balance, counter or state (refunds, recovery paths, retries,
  hooks that run before a unique index rejects the write). The check and
  the write must be one atomic operation, or sit under a lock that cannot
  expire while the operation is still running.
- **A missing limit.** Find every other route that verifies the same
  secret or code.

## Who Uses This Code Today

A fix that closes the hole and locks out the people who use the feature
is an outage with a security label. Before you write the patch, find
every legitimate caller of the code you are about to change and write
down what each one sends today.

Look for them in the repository: client and device code, scripts that
provision or configure devices, API schemas and validators for each
surface, existing tests and their fixtures, webhook senders and
receivers, scheduled jobs, staff and support tools, allowlists of
origins or hosts, e-mail and message templates that carry links, and
comments that describe a rollout. A route whose callers are not in the
repository (hardware in the field, a released mobile or desktop client, a
partner's server, a link already delivered) still has callers. You
simply cannot see what they are able to send.

For each kind of caller, answer one question: after the patch, does the
exact request it sends today get the answer it gets today?

## What the Fix Asks of Others

Classify the change from that list. The class, not your confidence,
decides whether a patch is filed.

- **Refuses only the attacker.** Every legitimate caller sends what it
  sends today and gets what it gets today. Only the attack changes. This
  is a patch you can file.
- **Needs a step from the operator.** Legitimate requests are untouched,
  but the patch needs something done once: a configuration value set, a
  new migration or backfill run, a credential rotated. File the patch,
  and make the step the first line of `fix_pr_body` with exactly what
  happens while it has not been done. If legitimate requests are refused
  until the step is done, this is the next class, not this one.
- **A legitimate caller must change.** Some caller has to send something
  it does not send today (a credential, header, field, token or
  signature), has to call a different endpoint, or loses access it has
  today. You cannot ship the other side of that change and you cannot
  know when it is deployed. Do not file a patch for it. Putting it behind
  a switch does not help: off, the finding is still open; on, every
  caller that was not updated stops working.

When a legitimate caller would have to change:

1. Look for the part of the fix that refuses only the attacker and file
   that part alone. There usually is one: scope a write to the records
   that belong to the identity the request already carries, stop
   returning data the caller has no claim to, reject an identifier that
   was never issued.
2. Say in the first line of `fix_pr_body` and in `fix_verification` that
   the patch closes that part only and name what stays open.
3. Put the rest in `remediation_steps` as a plan the owner can act on:
   what each caller would have to send, the order in which the two sides
   must be deployed, and the questions only the owner can answer (which
   devices or client versions are in use, what credentials they are able
   to send, who is meant to call this).
4. If no part of the fix refuses only the attacker, withhold the patch.

If you cannot tell which class a change is in, treat it as "a legitimate
caller must change". A requirement placed on a caller whose code you
cannot read is always in that class.

## Facts From Outside the Repository

A sentence about what something outside the repository does or is able
to do is a claim, not knowledge: a device's firmware, a released client,
a partner's API, a browser, a proxy or CDN header, a cloud service. It
needs a source the reader can open: a `file:line` in the repository, or
the vendor's published documentation, which you read during this run and
quote with its address.

Without a source it is a question. Write it as an open question for the
owner and do not build the patch on the answer you would like. "The
device can send this header", "works without any change on the client"
and "the proxy always sets this" are never written from memory. A patch
whose safety depends on such a sentence is in the class "a legitimate
caller must change" until the owner confirms it.

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
Walk the coverage inventory again: for every entry, is the enforcing line
you quoted still the one the request hits? Check equivalent sinks and
sibling call sites of the same helper. Try at least one alternate malicious
input class: different encoding, different
content type, a null byte, a unicode homoglyph, a nested/doubled
payload, a different HTTP verb. A control that catches your one payload
and nothing else has not closed the boundary.

**4. Preserved behavior.** Exercise the legitimate case through the same
boundary. Grep for every symbol the patch removes or renames (an import, a
middleware, a helper) and account for each remaining reference; a patch
that drops `required` from the import list while another route still uses
it does not compile. Say what status and error body a denied caller now
gets, and make `fix_pr_body` say the same thing. Confirm the APIs, error semantics, and compatibility
constraints you recorded still hold. A fix that breaks the feature will
be reverted, which means the vulnerability comes back.

**5. Repository checks.** Run them; do not reason about them. See "Run
It" below. A fix whose `fix_verification` has no executed command in it
has not passed this gate.

## Run It

You have a shell and the repository. A patch you have only read is a
guess, and most rejected fix PRs fail on something a single command would
have shown: an unused import, a formatting rule, a type error, an existing
test that asserted the old behavior.

**Work on a scratch copy.** Copy the repository to a directory outside the
workspace, apply your `fix_after` edits there, and run everything in the
copy. The workspace checkout stays exactly as it was, so `fix_before`
keeps matching it.

**Find the repository's own commands.** Read its manifest and CI
configuration (package scripts, Makefile, task runner, workflow files) and
use the formatter, linter, type checker and test runner it already uses,
with its own configuration. Do not substitute your preferred tool.

**Get the tools without touching the owner's systems.** Never send a
request to the repository owner's package registry, artifact store,
deployed services, or any host that belongs to them, even when the
repository's configuration points there. Install from the public registry
only: in the scratch copy, point the package manager at the public
registry and drop the dependencies that only exist privately. Many checks
need far less than a full install; a formatter or linter usually runs on
the touched files with only itself installed. When a check cannot run
without private packages or a service you cannot start, say so and move to
the next check; never invent stand-ins for missing packages to make a
suite pass.

**Run, narrowest first, on the files you touched:**

1. Formatter and linter. Fix everything they report on your lines,
   including imports your patch left unused.
2. Type checker or compiler, where it starts.
3. The existing tests nearest the changed code. A test that fails because
   it asserted the vulnerable behavior is part of your patch: update it in
   its own `code_locations` entry. A test that fails because you broke a
   legitimate caller means the patch is wrong.

**Write the test for the attack.** Add a regression test, in the existing
test file nearest the changed code and in its style, that performs the
attack from the finding and asserts it is refused, plus one assertion that
the legitimate caller still succeeds. Add one case per entry in the
coverage inventory, not only the route in the title. Where the suite can
run, show the test fails on the unpatched copy and passes on the patched
one. Ship the test as a `code_locations` entry of its own: `fix_before` is
the last lines of the existing test block, `fix_after` is those same lines
followed by the new test. Ship it even when you could not execute it, and
say that it was not executed.

**Feed the results back into the patch.** Every failure a check reports on
your change is fixed in `fix_after` before you file, and the checks are
run again. File only when what ran is clean.

## The Fix Is Its Own Job

A fix written as an afterthought while filing a report is the fix that
misses the sibling route. Once a finding is validated, the work of fixing
it belongs to one agent that does nothing else: a fix agent, started for
this finding, whose task is the patch, its test and the report that
carries them. If you are that agent, do not look for other
vulnerabilities and do not re-validate the finding; spend your turns on
the code around the bug.

Rules that hold for every fix:

- Do every remediation step the finding calls for, or name in
  `fix_verification` and `fix_pr_body` exactly what you left out and why.
- Change only what closing the finding requires. No refactors, no
  reformatting of neighbours, no dependency upgrades, no regenerated
  lockfile unless the fix adds a dependency, no new CI pipeline files, no
  notes about the exploit in the owner's documentation.
- Never edit a migration that has already shipped. A schema change goes
  in a new migration.
- Prefer the repository's existing helper or the platform's standard
  facility over code you write yourself. A hand-written replacement for a
  standard client or parser is a new attack surface.
- A limit, lockout or stricter rule that ordinary users can hit is a
  behaviour change. Name it for the owner.

## Independent Review Before You File

"The reviewer" here always means a separate agent that you start with
`create_agent`. Nothing else counts: not your own second read and not a
review you expect to happen later. If no agent you started has answered
`APPROVE` for the exact patch you are about to file, you are not allowed
to file it with `fix_after`. A patch filed without that verdict is the single failure
this procedure exists to prevent.

The unpatched workspace stays unpatched from start to finish. The
reviewer needs it to see the attack test fail, and the report's
`fix_before` lines are matched against it. All edits go in the scratch
copy; if you edited the workspace by mistake, restore it before anything
else.

Begin `fix_verification` with one line the reader can audit:
`Independent review: APPROVE by agent <id>, patch sha256 <checksum>`, or
`Independent review: REJECTED twice, no patch attached`.

You do not approve your own fix. When the patch is ready in the scratch
copy and your checks are clean:

1. Write the patch to a file next to the scratch copy
   (`git diff` against the unpatched tree) and note its checksum.
2. Write the words you intend to file to a second file next to it: the
   proposed `fix_pr_body`, the `remediation_steps`, your list of
   legitimate callers and the class of the change, every outside fact
   the patch depends on with its source, and what you left out or left
   open and why. State these plainly. Do not argue for the patch.
3. Start a reviewer with `create_agent`: name it "Fix Reviewer", give it
   the `fix_review` skill, and set `inherit_context` to false so it does
   not see your reasoning. Its task carries only: the finding as written,
   the path of the unpatched workspace, the path of your scratch copy,
   the path and checksum of the patch file, the path of the file with
   your intended words, and the commands you ran with their results.
4. Wait for its verdict. Do not file while it is working.
5. On `APPROVE` for the checksum you sent: file the report with exactly
   that patch and the words the reviewer read. If you changed the patch
   or those words after the review, it is not what was approved; send it
   back.
6. On `REJECT`: fix every blocking problem it lists, re-run your checks,
   and send the new patch to a fresh reviewer once. You get one retry.
7. Rejected twice: file the finding without `fix_after`, put the
   remediation in prose, and record the reviewer's unresolved problems in
   `fix_verification`. No fix is better than one that was rejected.

Record the reviewer's verdict, what it executed and the checksum in
`fix_verification`.

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
- The check reads a value the caller controls or one that is not what it
  seems at the moment the check runs: an identifier from the request
  where the stored record's own value is the one that matters, an
  identity that is regenerated on every request, a body field that an
  earlier middleware has not parsed yet, a header a direct caller can
  set, text that compares differently in another case or encoding, a
  cache that remembers the answer for a different argument.
- The refusal itself leaks. A different status or body for "exists but
  is not yours" and "does not exist" lets the caller enumerate records.
  Deny the way the neighbouring handlers deny, with their status code
  and error body.
- It drops a metric, log line or audit event the changed code emitted.
  The owner uses those to see the attack and the clients that still need
  to migrate.

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
- A legitimate caller would have to change and no part of the fix
  refuses only the attacker (see "What the Fix Asks of Others").
- The fix is only safe if a statement about a system outside the
  repository is true and you have no source for it.

A withheld fix still owes the owner an explanation. Say in
`remediation_steps` what you would change, why you did not attach it,
and what the owner has to decide or confirm before anyone writes it.
- You could not establish that the vulnerable path is real in the
  current checkout. Do not patch an adjacent weakness as a consolation
  prize, and do not add speculative defense-in-depth to a path you never
  proved was reachable.

## Guards You Rely On

A fix that calls an existing guard is only as strong as that guard today.
Open the definition of every middleware, policy or helper your patch uses
to enforce the control and read it to the end. If it enforces only when a
feature flag, rollout gate, shadow or report-only mode, environment value
or configuration is on, it is not a control you can rely on: check the
subject directly in your patch (the loaded record's owner or tenant against
the caller), and say in `fix_verification` which guard you did not trust
and why.

Then attack your own patch with one more request: change the state the
check reads through another route the caller may use, send the value as a
nested or dotted key, an array or an operator object, reach the same data
through an aliased, cached or batched path. A check that one extra request
defeats has not closed the boundary.

## What the Operator Must Do

A fix PR is merged by someone who was not in the room. Start `fix_pr_body`
with a short "Before you merge" list whenever any of these apply, and omit
the list when none do:

- **New configuration.** Every environment variable, secret or setting the
  patch reads that did not exist before: its name, what value it needs,
  and exactly what happens when it is not set (requests rejected, feature
  silently off, alerts stop).
- **Credential rotation.** For a secret found in source, the first item is
  "rotate this credential". Removing it from the newest commit does not
  revoke it; it stays valid in the git history until it is rotated. Name
  each credential and where it is issued.
- **Decisions you had to make.** When the right behavior is a product
  choice the code does not settle (may the record's owner still call this route,
  which permission is required, what the limit is, which status code a
  refusal uses), first look for the repository's own precedent: the
  limit, permission name or status the neighbouring handlers use. Follow
  it and cite it. Where there is none, choose the strictest option that
  keeps the callers you can see in the repository working, and state the
  choice and the alternative in one line so the owner can confirm it.
- **Answers that change.** Any caller that receives a different status
  or body after the patch, and what it now receives. This list is for
  refusals and error shapes only. A legitimate caller that has to send
  something new is not a line in a PR; that part of the fix is not
  filed.
- **What stays open.** When the patch closes only part of the finding,
  say which part and where the plan for the rest is.

The PR text must describe the diff as it is. Do not write "removes",
"adds a test" or "rate limits" unless a hunk does it.

## Recording It

Everything above goes in `fix_verification`, which is required whenever
any location carries a `fix_after`. Start with the coverage inventory
(entry, then `file:line` of its enforcing line after the patch), then the
callers you found and the class of the change, then every outside fact
the patch depends on with its source, then the gates. Write the actual commands and their results, grouped by gate, and mark every gate you could only reason
about — rather than execute — as an explicit gap. End with a "Checks"
list, one line per check: the command, then `passed`, `failed` (with what
you changed), or `not run` (with the reason). Repeat the `not run` lines
in `fix_pr_body` so the person merging knows what their CI still has to
prove. Do not hide proof
gaps; a reviewer who knows gate 5 was skipped can run it themselves, but
one who was told it passed cannot.
