"""Deterministic source-to-sink data-flow analysis over the CSPT fixtures.

The structural check in ``test_cspt_skill.py`` only asserts that a source string
and a sink string both appear in a fixture; a page with an *unrelated* source
and sink would pass it. This module closes that gap with a small, deterministic
taint tracker that verifies the source value actually **flows into** the request
sink's path argument.

It is intentionally not a general JS engine — it models the assignment- and
concatenation-based flow the fixtures use (the same shape real CSPT bugs take):

* seed taint at ``const X = <source-expression>`` and inside a ``postMessage``
  handler's ``event.data`` access;
* propagate taint across ``const Y = <expr referencing a tainted identifier>``
  (covers ``.replace(...)``, ``decodeURIComponent(...)``, wrapper vars);
* mark a flow **broken** when a tainted value is gated by an allowlist guard
  (``/.../.test(id)``) before any sink, or is only ever passed to
  ``searchParams.set`` / used as a query value on a constant path;
* report a **hit** when a tainted identifier appears in the path argument of a
  request sink (``fetch(...)``, ``xhr.open(...)``, an ``axios``-style
  ``baseURL + path`` join).

Because it requires a *connected* path, it fails closed: break the flow in a
fixture (rename the tainted var at the sink, drop the concatenation, add a real
guard) and the corresponding assertion flips. That is the regression the issue
asks for.
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest


FIXTURES = Path(__file__).parent / "fixtures" / "cspt"

POSITIVE_FIXTURES = [
    "positive_direct.html",
    "positive_encoded.html",
    "positive_normalized.html",
    "positive_postmessage.html",
    "positive_storage.html",
]
NEGATIVE_FIXTURES = [
    "negative_validated.html",
    "negative_safe_construction.html",
]

# Expressions that introduce attacker-controlled taint.
_SOURCE_EXPR = re.compile(
    r"""
    location\.hash
    | location\.search
    | location\.pathname
    | document\.referrer
    | new\s+URLSearchParams\b
    | localStorage\.getItem
    | sessionStorage\.getItem
    | event\.data
    | window\.name
    """,
    re.VERBOSE,
)

# A request sink call. Each alternative captures the sink name; the balancer
# starts at the ``(`` that immediately follows the match. ``.open`` is the XHR
# method-then-URL form, handled by picking the 2nd argument below.
_SINK_CALL = re.compile(
    r"""
    (?P<open>\.open)\s*\(
    | (?P<fetch>\bfetch)\s*\(
    | (?P<beacon>sendBeacon)\s*\(
    | (?P<es>new\s+EventSource)\s*\(
    | (?P<ws>new\s+WebSocket)\s*\(
    """,
    re.VERBOSE,
)

_JS_IDENT = re.compile(r"[A-Za-z_$][\w$]*")

# A same-endpoint allowlist guard: an anchored character-class regex literal used
# anywhere, plus a ``.test(<ident>)`` gate. The literal and the call need not be
# adjacent (the fixture stores the regex in a const, then calls VALID_ID.test).
_ALLOWLIST_REGEX_LITERAL = re.compile(r"/\^\[[^\]]+\][^/]*\$?/")
_TEST_GUARD = re.compile(r"\.test\s*\(\s*([A-Za-z_$][\w$]*)\s*\)")


def _script_body(html: str) -> str:
    return "\n".join(re.findall(r"<script>(.*?)</script>", html, re.DOTALL))


def _balanced_args(src: str, open_paren_idx: int) -> str:
    """Return the full argument-list text between an opening paren and its
    matching close paren (exclusive)."""
    depth = 0
    out: list[str] = []
    i = open_paren_idx
    while i < len(src):
        ch = src[i]
        if ch == "(":
            depth += 1
            if depth == 1:
                i += 1
                continue
        elif ch == ")":
            depth -= 1
            if depth == 0:
                break
        out.append(ch)
        i += 1
    return "".join(out)


def _split_top_level_args(arglist: str) -> list[str]:
    """Split an argument-list string on top-level commas (ignoring commas nested
    in (), [], {}, or string/template literals)."""
    args: list[str] = []
    depth = 0
    quote: str | None = None
    buf: list[str] = []
    for ch in arglist:
        if quote:
            buf.append(ch)
            if ch == quote:
                quote = None
            continue
        if ch in "\"'`":
            quote = ch
            buf.append(ch)
            continue
        if ch in "([{":
            depth += 1
        elif ch in ")]}":
            depth -= 1
        if ch == "," and depth == 0:
            args.append("".join(buf))
            buf = []
            continue
        buf.append(ch)
    if buf:
        args.append("".join(buf))
    return args


def _tainted_vars(script: str) -> set[str]:
    """Fixed-point propagation of taint through ``const/let/var X = <expr>``.

    Seeds on source expressions, then repeatedly taints any assignment whose
    right-hand side references an already-tainted identifier. ``event.data``
    accesses inside a message handler seed the handler's derived var too.
    """
    assign_re = re.compile(
        r"\b(?:const|let|var)\s+([A-Za-z_$][\w$]*)\s*=\s*(.+?);",
        re.DOTALL,
    )
    assignments = [(m.group(1), m.group(2)) for m in assign_re.finditer(script)]

    tainted: set[str] = set()
    # Seed: direct source expression on the RHS.
    for name, rhs in assignments:
        if _SOURCE_EXPR.search(rhs):
            tainted.add(name)

    # Propagate to a fixed point: RHS references a tainted identifier.
    changed = True
    while changed:
        changed = False
        for name, rhs in assignments:
            if name in tainted:
                continue
            idents = set(_JS_IDENT.findall(rhs))
            if idents & tainted:
                tainted.add(name)
                changed = True
    return tainted


def _guarded_idents(script: str) -> set[str]:
    """Identifiers gated by an allowlist ``.test(ident)`` guard before a sink."""
    guarded: set[str] = set()
    if _ALLOWLIST_REGEX_LITERAL.search(script):
        for m in _TEST_GUARD.finditer(script):
            guarded.add(m.group(1))
    return guarded


def _sink_path_args(script: str) -> list[str]:
    """The URL/path argument text of every request sink call in the script.

    The URL is the 1st argument for ``fetch``/``sendBeacon``/``EventSource``/
    ``WebSocket`` and the 2nd for ``xhr.open(method, url)``.
    """
    args: list[str] = []
    for m in _SINK_CALL.finditer(script):
        open_idx = script.index("(", m.end() - 1)
        arglist = _balanced_args(script, open_idx)
        parts = _split_top_level_args(arglist)
        if not parts:
            continue
        url_arg = parts[1] if m.group("open") and len(parts) > 1 else parts[0]
        args.append(url_arg)
    return args


def _tainted_flows_into_sink_path(script: str) -> bool:
    """True iff a tainted identifier is concatenated into a sink's path arg.

    Requires an actual join into the path (``+`` concatenation or a template
    literal) so that a tainted value used *only* as a query parameter (e.g.
    ``searchParams.set(k, tainted)`` on a constant-path URL) does not count.
    """
    tainted = _tainted_vars(script)
    guarded = _guarded_idents(script)
    live = tainted - guarded
    if not live:
        return False

    # An axios-style wrapper joins ``baseURL + path``; the tainted value reaches
    # the sink transitively through the wrapper argument. Treat a call to such a
    # wrapper method (``.get("/x/" + tainted)``) as a path-join sink too.
    wrapper_join = re.compile(r"\.get\s*\(")

    candidate_args = list(_sink_path_args(script))
    for m in wrapper_join.finditer(script):
        open_idx = script.find("(", m.end() - 1)
        if open_idx != -1:
            parts = _split_top_level_args(_balanced_args(script, open_idx))
            if parts:
                candidate_args.append(parts[0])

    for arg in candidate_args:
        joins_path = "+" in arg or "${" in arg or "`" in arg
        if not joins_path:
            continue
        if set(_JS_IDENT.findall(arg)) & live:
            return True
    return False


# --------------------------------------------------------------------------- #
# Tests
# --------------------------------------------------------------------------- #


@pytest.mark.parametrize("name", POSITIVE_FIXTURES)
def test_positive_fixture_source_flows_into_sink_path(name: str) -> None:
    script = _script_body((FIXTURES / name).read_text(encoding="utf-8"))
    assert _tainted_flows_into_sink_path(script), (
        f"{name}: no data flow from a client source into a request sink's path — "
        "source and sink present but not connected"
    )


@pytest.mark.parametrize("name", NEGATIVE_FIXTURES)
def test_negative_fixture_flow_is_broken(name: str) -> None:
    script = _script_body((FIXTURES / name).read_text(encoding="utf-8"))
    assert not _tainted_flows_into_sink_path(script), (
        f"{name}: a tainted value reaches a request sink's path — negative fixture "
        "is not actually neutralized"
    )


def test_analyzer_detects_a_disconnected_source_and_sink() -> None:
    # Meta-test: the analyzer must NOT flag a page where the source and sink are
    # both present but unrelated (the exact gap the structural check misses).
    disconnected = """
        const tainted = location.hash.slice(1);
        console.log(tainted);            // taint goes nowhere
        fetch("/api/orders/12345/detail", { credentials: "include" });
    """
    assert not _tainted_flows_into_sink_path(disconnected)


def test_analyzer_flags_a_connected_source_and_sink() -> None:
    # ...and it MUST flag the connected version, so the negative above is real.
    connected = """
        const tainted = location.hash.slice(1);
        fetch("/api/orders/" + tainted + "/detail", { credentials: "include" });
    """
    assert _tainted_flows_into_sink_path(connected)
