"""The dependency path of ``check_duplicate`` decides without asking the model."""

from __future__ import annotations

import asyncio
from typing import TYPE_CHECKING, Any

from strix.report import dedupe


if TYPE_CHECKING:
    import pytest


def _dependency(
    report_id: str,
    *,
    cve: str | None = "CVE-2024-1",
    package: str = "left-pad",
    ecosystem: str = "npm",
    manifest: str | None = "package.json",
) -> dict[str, Any]:
    metadata: dict[str, str] = {"package_name": package, "package_ecosystem": ecosystem}
    if manifest is not None:
        metadata["manifest_path"] = manifest
    report: dict[str, Any] = {"id": report_id, "dependency_metadata": metadata}
    if cve is not None:
        report["cve"] = cve
    return report


def test_the_same_dependency_is_a_duplicate_without_asking_the_model(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Case and spelling differences are identity, not a new finding."""

    def model_is_forbidden(*_args: object, **_kwargs: object) -> None:
        raise AssertionError("the deterministic dependency path consulted the model")

    monkeypatch.setattr(dedupe, "resolve_dedupe_model", model_is_forbidden)

    result = asyncio.run(
        dedupe.check_duplicate(
            _dependency(
                "vuln-2",
                cve="cve-2024-1",
                package="Left-Pad",
                ecosystem="NPM",
                manifest="./package.json",
            ),
            [_dependency("vuln-1")],
        )
    )

    assert result["is_duplicate"] is True
    assert result["duplicate_id"] == "vuln-1"


def test_the_same_dependency_in_another_manifest_stays_a_second_finding() -> None:
    decision = dedupe._check_dependency_duplicate(
        _dependency("vuln-2", manifest="b/package.json"),
        [_dependency("vuln-1", manifest="a/package.json")],
    )

    assert decision is not None
    assert decision["is_duplicate"] is False


def test_a_report_without_a_cve_is_left_to_the_model() -> None:
    """Identity needs a CVE: without one the deterministic path declines to decide."""
    assert (
        dedupe._check_dependency_duplicate(_dependency("vuln-2", cve=None), [_dependency("vuln-1")])
        is None
    )
