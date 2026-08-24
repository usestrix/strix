"""Guard against the Python and Go protocol constants drifting apart.

The wire protocol is declared twice — ``strix/interface/tui/backend/protocol.py``
for the backend and ``strix/interface/tui/internal/protocol/protocol.go`` for the
sidecar. This test parses the Go source shipped in the tree and checks the two
declarations agree, so a version or capability change in one language cannot
land silently without the other.
"""

from __future__ import annotations

import re
from pathlib import Path

from strix.interface.tui.backend.protocol import PROTOCOL_CAPABILITIES, PROTOCOL_VERSION


GO_PROTOCOL_SOURCE = (
    Path(__file__).resolve().parents[1]
    / "strix"
    / "interface"
    / "tui"
    / "internal"
    / "protocol"
    / "protocol.go"
)


def test_go_protocol_source_is_present() -> None:
    assert GO_PROTOCOL_SOURCE.is_file()


def test_protocol_version_matches_go() -> None:
    source = GO_PROTOCOL_SOURCE.read_text(encoding="utf-8")
    match = re.search(r"^const Version = (\d+)$", source, flags=re.MULTILINE)
    assert match is not None, "const Version not found in protocol.go"
    assert int(match.group(1)) == PROTOCOL_VERSION


def test_protocol_capabilities_match_go() -> None:
    source = GO_PROTOCOL_SOURCE.read_text(encoding="utf-8")
    match = re.search(
        r"^var Capabilities = \[\]string\{\n(?P<body>(?:\t\"[^\"]+\",\n)+)\}",
        source,
        flags=re.MULTILINE,
    )
    assert match is not None, "var Capabilities not found in protocol.go"
    go_capabilities = re.findall(r"\"([^\"]+)\"", match.group("body"))
    assert tuple(go_capabilities) == PROTOCOL_CAPABILITIES
