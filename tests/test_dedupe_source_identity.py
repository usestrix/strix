from __future__ import annotations

from types import SimpleNamespace
from typing import Any

from strix.report import dedupe


def _dependency_report(
    *,
    report_id: str,
    target: str,
    manifest_path: str = "package-lock.json",
) -> dict[str, Any]:
    return {
        "id": report_id,
        "target": target,
        "cve": "CVE-2024-0001",
        "dependency_metadata": {
            "package_name": "fixture-package",
            "package_ecosystem": "npm",
            "manifest_path": manifest_path,
        },
    }


def test_dependency_dedupe_separates_matching_manifests_across_sources(
    monkeypatch: Any, tmp_path: Any
) -> None:
    repo_a = tmp_path / "repo-a"
    repo_b = tmp_path / "repo-b"
    state = SimpleNamespace(
        scan_config={
            "local_sources": [
                {"source_path": str(repo_a), "workspace_subdir": "repo-a"},
                {"source_path": str(repo_b), "workspace_subdir": "repo-b"},
            ]
        }
    )
    monkeypatch.setattr(dedupe, "get_global_report_state", lambda: state)

    result = dedupe._check_dependency_duplicate(
        _dependency_report(report_id="vuln-0002", target=str(repo_b)),
        [_dependency_report(report_id="vuln-0001", target=str(repo_a))],
    )

    assert result is not None
    assert result["is_duplicate"] is False


def test_dependency_dedupe_still_collapses_same_source_manifest(
    monkeypatch: Any, tmp_path: Any
) -> None:
    repo = tmp_path / "repo"
    state = SimpleNamespace(
        scan_config={"local_sources": [{"source_path": str(repo), "workspace_subdir": "repo"}]}
    )
    monkeypatch.setattr(dedupe, "get_global_report_state", lambda: state)

    result = dedupe._check_dependency_duplicate(
        _dependency_report(report_id="vuln-0002", target=str(repo)),
        [_dependency_report(report_id="vuln-0001", target=str(repo))],
    )

    assert result == {
        "is_duplicate": True,
        "duplicate_id": "vuln-0001",
        "confidence": 1.0,
        "reason": "Same dependency CVE/package identity",
    }


def test_dependency_dedupe_keeps_distinct_manifests_in_one_source(
    monkeypatch: Any, tmp_path: Any
) -> None:
    repo = tmp_path / "repo"
    state = SimpleNamespace(
        scan_config={"local_sources": [{"source_path": str(repo), "workspace_subdir": "repo"}]}
    )
    monkeypatch.setattr(dedupe, "get_global_report_state", lambda: state)

    result = dedupe._check_dependency_duplicate(
        _dependency_report(report_id="vuln-0002", target=str(repo), manifest_path="requirements.txt"),
        [_dependency_report(report_id="vuln-0001", target=str(repo))],
    )

    assert result is not None
    assert result["is_duplicate"] is False
