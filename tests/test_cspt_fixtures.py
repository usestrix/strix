"""Deterministic, browser-free regression over the CSPT fixtures.

This checks one thing only: whether an attacker-controlled client source reaches
a request sink's path **unguarded** — the CSPT *primitive*. It deliberately does
NOT decide exploitability: a reached sink is not yet a finding. Whether the
redirected request has security impact (a state change, a rendered response, an
internal fetch, an authz bypass) is proven separately, per the exploitability bar
in the `client_side_path_traversal` skill. So a passing test here means "the
primitive is present/absent as labelled", not "exploitable".

It is a fixture/pattern regression, not a static taint tracker, kept honest by a
convention: the attacker value that reaches a sink is named ``userPath``.
"""

from __future__ import annotations

from pathlib import Path


_FIXTURES = Path(__file__).parent / "fixtures" / "cspt"

#: Browser-controlled input sources an attacker influences.
_SOURCES = (
    "location.search",
    "URLSearchParams",
    "location.hash",
    "document.referrer",
    "postMessage",
    "localStorage",
)
#: Request sinks whose path, if attacker-shaped, carries the traversal.
_SINKS = ("fetch(", "XMLHttpRequest", "axios", "EventSource", "WebSocket")
#: Markers of a guard that neutralises the flow before the sink.
_MITIGATIONS = ("/^", ".test(", "allowlist", "hardcoded")


def _reaches_sink_unguarded(text: str) -> bool:
    """True when the attacker value (``userPath``) reaches a sink-call line."""
    return any(
        any(sink in line for sink in _SINKS) and "userPath" in line
        for line in text.splitlines()
    )


def _detect_primitive(text: str) -> str:
    """"reaches_sink" when an unguarded attacker source reaches a sink path.

    This is the CSPT primitive, not an exploitability verdict — impact is a
    separate, out-of-band step the skill describes.
    """
    has_source = any(token in text for token in _SOURCES)
    has_sink = any(token in text for token in _SINKS)
    guarded = any(token in text for token in _MITIGATIONS)
    if has_source and has_sink and _reaches_sink_unguarded(text) and not guarded:
        return "reaches_sink"
    return "no_unguarded_sink"


def test_cspt_fixtures_match_their_labelled_primitive() -> None:
    fixtures = sorted(_FIXTURES.glob("*.html"))
    assert fixtures, "no CSPT fixtures found"

    positives = [f for f in fixtures if f.name.startswith("positive_")]
    negatives = [f for f in fixtures if f.name.startswith("negative_")]
    assert len(positives) >= 2, "need at least two primitive-present fixtures"
    assert len(negatives) >= 2, "need at least two guarded / no-flow controls"

    for fixture in fixtures:
        # positive_* = the unguarded source-to-sink primitive is present
        # (exploitability is proven separately); negative_* = guarded or no flow.
        expected = "reaches_sink" if fixture.name.startswith("positive_") else "no_unguarded_sink"
        actual = _detect_primitive(fixture.read_text(encoding="utf-8"))
        assert actual == expected, f"{fixture.name}: expected {expected}, matched {actual}"
