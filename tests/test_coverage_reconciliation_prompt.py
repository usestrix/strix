"""The root agent must follow up open coverage rows before finishing."""

from __future__ import annotations

import pytest

from strix.agents.prompt import render_system_prompt


_FOLLOW_UP = 'calls `list_coverage(outcome="needs_follow_up")` and follows up every row it returns'
_KEEP_GENUINE_GAPS = "stays `needs_follow_up` only when it is genuinely blocked"


@pytest.mark.parametrize("scan_mode", ["quick", "standard", "deep"])
@pytest.mark.parametrize("is_whitebox", [False, True])
@pytest.mark.parametrize("is_root", [False, True])
def test_prompt_follows_up_open_coverage(scan_mode: str, is_whitebox: bool, is_root: bool) -> None:
    prompt = render_system_prompt(scan_mode=scan_mode, is_whitebox=is_whitebox, is_root=is_root)

    assert prompt
    assert _FOLLOW_UP in prompt
    assert _KEEP_GENUINE_GAPS in prompt
