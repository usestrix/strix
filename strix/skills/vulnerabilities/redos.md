---
name: redos
description: Regular expression denial of service (ReDoS, CWE-1333) in backtracking regex engines, covering exponential and polynomial patterns, recheck-assisted detection, growth-curve confirmation, and severity calibration
---

# ReDoS (Regular Expression Denial of Service)

A backtracking regex engine can take exponential or polynomial time on a crafted input that almost matches. When attacker-controlled text reaches such a pattern, one request or one document can pin a CPU core for seconds to hours. Tracked as CWE-1333 (Inefficient Regular Expression Complexity).

The textbook shape, nested quantifiers like `(a+)+`, is the rarest one in real code. Most real ReDoS is polynomial: two adjacent pieces that can match the same characters, or an unanchored pattern that fails slowly at every start position. Do not rule a pattern out because it has no nested quantifier.

## Engines

Backtracking (vulnerable): Python `re` and `regex`, JavaScript (V8, JavaScriptCore, SpiderMonkey), Java `java.util.regex`, .NET (default mode), PCRE/PHP, Perl, Ruby before 3.2.

Linear-time (not vulnerable to ReDoS): Go `regexp`, Rust `regex`, RE2 and its bindings (`google-re2`, `re2j`), .NET `RegexOptions.NonBacktracking`. Ruby 3.2+ memoizes most patterns and has `Regexp.timeout`; treat it as lower risk, not immune.

PHP is special: when `pcre.backtrack_limit` is hit, `preg_match` returns `false` instead of hanging. That turns ReDoS into a logic bypass when the caller treats `false` as "no match", e.g. a validator or WAF rule that silently passes.

## Vulnerable Shapes

**Nested quantifiers (exponential)**: `^(a+)+$`, `^(a*)*$`, `^(\w+\s?)+$`. About 30 matching characters plus one that fails the anchor can hang.

**Overlapping alternation inside a repeat (exponential)**: `^(a|a)*$`, `^(\w|\d)+$`, `^(.*,)*$`.

**Adjacent overlapping quantifiers (polynomial)**: two consecutive pieces that can both match the same character, followed by something that fails. The engine tries every way to split the run between them.

~~~text
\d+\d+x          a run of digits split between two \d+, with no x after it (cubic: also retried at every start)
^`{3,}[^\n]*\n   a run of backticks split between the fence and [^\n]*, with no newline after it
~~~

**Unanchored pattern that fails slowly at every start (polynomial)**: `<[^>]+>` on `<<<<…` with no `>`, or `\s+$` on a long run of spaces followed by one non-space character. Each start position scans to the end, and `sub`/`findall`/`search` retry at every position.

**Lazy scan with an absent terminator inside a loop**: `.*?END` or `[\s\S]*?` applied repeatedly to text that never contains `END`.

**Backreferences**: `^(a+)\1$` is quadratic: the engine tries every split of the run between the group and its repeat.

## Where to Look

- Validators: email, URL, hostname, semver, UUID, phone, password rules
- Parsers and sanitizers: markdown, MDX, HTML stripping, template engines, log and CSV parsers, user-agent parsing
- Routing and matching: route patterns, CORS origin checks, WAF and content-filter rules, glob-to-regex conversions
- Patterns built from input: `re.compile(user_value)`, search filters, MongoDB `$regex`, Elasticsearch `regexp` queries (these are regex injection, the attacker supplies the pattern itself)
- Document and RAG loaders that clean uploaded or fetched files: one large file per request is an easy delivery path

Find candidate patterns in source:

```bash
rg -n --type py "re\.(compile|match|search|fullmatch|sub|subn|findall|finditer|split)\(" .
rg -n --type js --type ts "new RegExp\(|/[^/\n]+/[dgimsuyv]*\.(test|exec)|\.(match|matchAll|replace|replaceAll|search|split)\(/" .
```

## Detect with recheck

[recheck](https://github.com/makenowjust-labs/recheck) combines static analysis and fuzzing, reports the complexity class (linear, polynomial with degree, exponential), and produces an attack string. It catches polynomial cases that nested-quantifier heuristics and some tools miss. Install a pinned version at scan time:

```bash
mkdir -p /tmp/recheck && cd /tmp/recheck && npm install --silent recheck@4.5.0
```

Put the patterns in a JSON file, one `[source, flags]` pair per entry, so no shell escaping is involved:

```js
// /tmp/recheck/run.mjs   usage: node run.mjs patterns.json
import { check } from "recheck";
import { readFileSync } from "node:fs";
for (const [source, flags] of JSON.parse(readFileSync(process.argv[2], "utf8"))) {
  const r = await check(source, flags, { timeout: 30000 });
  console.log(JSON.stringify({ source, status: r.status, complexity: r.complexity?.summary, attack: r.attack?.pattern }));
}
```

recheck understands JavaScript syntax only. Translate other dialects first:

| Python | JavaScript |
|--------|-----------|
| `(?P<name>…)` | `(?<name>…)` |
| `(?P=name)` | `\k<name>` |
| `\Z` | `$(?![\s\S])` |
| `\A` | `^` without the `m` flag |
| inline `(?m)`, `(?s)`, `(?i)` | `m`, `s`, `i` in the flags string |
| `(?>…)`, `a*+` (3.11+) | no equivalent; recheck will over-report, so confirm in Python |

Treat recheck's verdict as a lead and its attack string as a hint. The attack string can rely on JavaScript-only behavior and run fast in the target language: with the `m` flag, JavaScript `^` also matches after `\r`, ` `, and ` `, while Python `^` only matches after `\n`. Rebuild the attack for the real engine. If `npm install` fails (no network), reason from the shapes above and go straight to timing.

## Confirm in the Target Language

One timing proves nothing. Measure growth: double or 10x the input and compare times. Linear grows about 10x per 10x, quadratic about 100x, cubic about 1000x, exponential explodes after a few dozen characters.

```python
import re, time
pattern = re.compile(r"(?ms)^(?P<fence>`{3,}|~{3,})[^\n]*\n.*?(?:^(?P=fence)[ \t]*$|\Z)")
for n in (1_000, 10_000, 100_000):
    payload = "`" * n   # the repeated character, with the required terminator missing
    t = time.perf_counter(); pattern.sub("", payload); print(n, f"{time.perf_counter() - t:.3f}s")
```

Build the payload as: a prefix that reaches the vulnerable piece, then many copies of the character both quantifiers accept, then a suffix that makes the overall match fail (or no suffix, when the failing piece needs a character that never arrives). Run the confirmation against the function the attacker reaches, not just the bare regex, so input caps and preprocessing are included.

## Severity Calibration

Report the time at a realistic input size, not the asymptotic class alone. Ask:

- Can the attacker supply the text, and how large can it be? Body size limits, field length validation, and upload caps decide whether 100 KB (seconds for quadratic) is reachable.
- What does one slow match block? A Node.js event loop or a single-threaded worker stalls every user (higher). A per-request thread with a timeout affects one request (lower).
- Is the work repeatable without authentication or rate limits?
- Diff or PR review: compare against the base code. A new slow pattern next to an existing pattern with the same complexity on the same input does not add an attack; say so and calibrate down instead of reporting a new HIGH.

Exponential on short unauthenticated input in a shared event loop is high. Quadratic needing megabytes behind authentication is usually low or informational.

## False Positives

- Linear-time engine (Go, Rust, RE2, .NET NonBacktracking)
- Input length capped well below where the curve hurts
- recheck flagged a construct the target dialect handles atomically (possessive quantifiers, atomic groups)
- Only the developer controls the input (build scripts, static config)

## Remediation

- Make overlapping pieces unambiguous: atomic groups (`` (?>`{3,}) ``; Python 3.11+, Java, PCRE, .NET) or possessive quantifiers (`a++`; Python 3.11+, Java, PCRE), or rewrite so adjacent pieces cannot match the same character
- Anchor patterns and bound repeats (`{1,256}`) where the format allows
- Cap input length before matching
- Switch to a linear-time engine (`google-re2`, Rust/Go regex) for untrusted input
- Use engine timeouts where available: .NET `matchTimeout`, Ruby `Regexp.timeout`, Python `regex` module `timeout=`

## Summary

Look for adjacent pieces that can match the same character, not just nested quantifiers. Use recheck to flag candidates and get a starting attack string, then rebuild and time the attack in the target language at 1k, 10k, and 100k characters. Calibrate severity by reachable input size, what a stalled match blocks, and, in a PR, whether the base code was already as slow.
