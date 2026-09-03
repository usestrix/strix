---
name: hypothesis
description: Property-based local differential testing with Hypothesis for parsers, canonicalizers, serializers, validators, routers, and other pure functions, emphasizing explicit invariants, shrinking, reproducibility, and bounded resource use
---

# Hypothesis Differential Testing

Use [Hypothesis](https://hypothesis.readthedocs.io/) when a security property can be expressed over local code and failures are likely to hide in combinations of encoding, normalization, structure, or parser recovery. It is especially useful for comparing two implementations or checking that validation and consumption preserve the same meaning.

Do not point unrestricted generators at a live service. Hypothesis is safest and most useful against pure local adapters with no network, subprocess, filesystem, or persistent-state side effects.

## Install

Use an isolated virtual environment and install a reviewed pinned version:

```bash
python -m pip install 'hypothesis==<reviewed-version>'
```

Official project: [Hypothesis](https://github.com/HypothesisWorks/hypothesis)

## Start From an Invariant

Write the security relationship before writing strategies. Examples:

```text
allowlist(raw) implies sink(canonicalize(raw)) remains inside the allowed origin/path
validator(raw) accepts implies consumer(raw) assigns the same media type/structure
parse_A(raw) and parse_B(raw) agree on message boundaries and authoritative fields
serialize(parse(raw)) cannot introduce a delimiter, wildcard, traversal, or new field
```

A test that only checks “does not crash” can find robustness bugs but does not establish a security differential.

## Minimal Differential Harness

```python
from hypothesis import given, settings, strategies as st


def outcome(parser, raw):
    try:
        return ("accept", parser(raw))
    except ExpectedParseError as exc:
        return ("reject", type(exc).__name__)


@settings(max_examples=250, deadline=500)
@given(st.text(max_size=128))
def test_security_boundary(raw: str) -> None:
    checked = outcome(security_parser, raw)
    consumed = outcome(sink_parser, raw)
    assert equivalent_security_meaning(checked, consumed)
```

- Bound string/list/binary sizes, recursion, examples, and deadline.
- Build structured inputs from relevant tokens rather than generating unrestricted noise.
- Normalize expected accept/reject/error outcomes explicitly so ordinary parser rejection is not mistaken for a property-test failure.
- Use `st.one_of`, `st.sampled_from`, `st.lists`, `st.binary`, `st.text`, and composite strategies to represent the actual grammar.
- Add explicit edge seeds with `@example` for known delimiters and regressions.
- Let Hypothesis shrink failures; the minimal counterexample is often the clearest explanation of the parser disagreement.

## High-Value Strategy Axes

- percent and double encoding, malformed escapes, mixed separators
- Unicode normalization, replacement characters, surrogates, case folding, IDNA
- dot segments, slash/backslash, absolute/relative paths, sibling-prefix collisions
- duplicate, empty, first/last, comma-joined, or differently cased fields
- declared length versus actual bytes, truncation, padding, and terminators
- nested objects, parser depth, ordering, unknown keys, and error recovery
- serialize/deserialize round trips and version-to-version behavior

Generate only axes supported by the target's transformation graph. Cartesian payload spraying obscures causality.

## Reproducibility

- Keep the minimized failing example as a normal regression test.
- Preserve code revision, dependency lock, locale, platform, and parser/library versions.
- Keep Hypothesis's example database in a task-specific artifact directory when replay across runs matters.
- For CI, rely on stored explicit regressions for critical cases; randomized discovery supplements them.
- Classify nondeterminism before suppressing health checks. Timing, global state, environment, and shared caches can create flaky false differentials.

## Safety and Resource Controls

- Adapt target functions so tests cannot reach the network or execute commands.
- Use temporary directories and non-secret corpora for parsers that require files.
- Put native parsers in a disposable, networkless process/container with CPU, memory, file-size, and process ceilings.
- Do not disable deadlines globally to hide hangs; isolate and bound intentionally slow examples.
- A crash, timeout, or excessive allocation is a robustness result. Prove a security boundary or exploitability separately.
- Never reuse captured credentials, customer content, or production requests as generative corpora without sanitization.

## Validation Deliverable

1. stated invariant and why it protects a security boundary
2. adapters and exact component/version pair compared
3. bounded strategies and resource settings
4. minimized counterexample and both interpretations
5. stable explicit regression test
6. impact trace from disagreement to privileged consumer
7. fixed-version or corrected-invariant result
