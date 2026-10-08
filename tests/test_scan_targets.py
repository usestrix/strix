"""Which scans count as source-aware (white-box)."""

from __future__ import annotations

from typing import Any

import pytest

from strix.core.targets import is_whitebox_scan


def _web() -> dict[str, Any]:
    return {"type": "web_application", "details": {"target_url": "https://app.example"}}


def _local() -> dict[str, Any]:
    return {"type": "local_code", "details": {"target_path": "/src/app"}}


def _repo(*, cloned: bool = True) -> dict[str, Any]:
    details: dict[str, Any] = {"target_repo": "https://github.com/org/repo"}
    if cloned:
        details["cloned_repo_path"] = "/work/clones/repo"
    return {"type": "repository", "details": details}


@pytest.mark.parametrize(
    ("targets", "expected"),
    [
        pytest.param([], False, id="no-targets"),
        pytest.param(None, False, id="targets-missing"),
        pytest.param([_web()], False, id="web-only"),
        pytest.param([_local()], True, id="local-directory"),
        pytest.param([_repo()], True, id="cloned-repository"),
        pytest.param([_repo(cloned=False)], False, id="repository-that-was-not-cloned"),
        pytest.param([_repo(), _web()], True, id="repository-beside-a-domain"),
        pytest.param([_web(), _repo()], True, id="domain-before-repository"),
    ],
)
def test_source_in_front_of_the_agent_makes_the_scan_whitebox(
    targets: list[dict[str, Any]] | None, *, expected: bool
) -> None:
    assert is_whitebox_scan(targets) is expected


def test_a_target_without_details_does_not_break_the_check() -> None:
    assert is_whitebox_scan([{"type": "repository"}]) is False
