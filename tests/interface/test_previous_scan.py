from pathlib import Path

import pytest

from strix.interface.previous_scan import build_previous_scan_context, resolve_previous_scan_dir


def test_resolve_previous_scan_dir_accepts_run_name(tmp_path: Path) -> None:
    run_dir = tmp_path / "strix_runs" / "scan-123"
    run_dir.mkdir(parents=True)

    assert resolve_previous_scan_dir("scan-123", tmp_path) == run_dir.resolve()


def test_resolve_previous_scan_dir_accepts_relative_path(tmp_path: Path) -> None:
    run_dir = tmp_path / "custom-run"
    run_dir.mkdir()

    assert resolve_previous_scan_dir("custom-run", tmp_path) == run_dir.resolve()


def test_resolve_previous_scan_dir_raises_for_missing_run(tmp_path: Path) -> None:
    with pytest.raises(ValueError, match="Previous scan 'missing' was not found"):
        resolve_previous_scan_dir("missing", tmp_path)


def test_build_previous_scan_context_reads_report_vulns_and_wiki(tmp_path: Path) -> None:
    run_dir = tmp_path / "strix_runs" / "scan-abc"
    vulns_dir = run_dir / "vulnerabilities"
    wiki_dir = run_dir / "wiki"
    vulns_dir.mkdir(parents=True)
    wiki_dir.mkdir()

    (run_dir / "penetration_test_report.md").write_text(
        "# Security Penetration Test Report\n\nAuth review complete.",
        encoding="utf-8",
    )
    (vulns_dir / "vuln-0001.md").write_text(
        "# SQL injection\n\nConfirmed in /login.",
        encoding="utf-8",
    )
    (wiki_dir / "repo.md").write_text(
        "# Repo Wiki\n\nInteresting admin routes: /admin.",
        encoding="utf-8",
    )

    context = build_previous_scan_context("scan-abc", tmp_path)

    assert "<previous_scan_context>" in context
    assert "Auth review complete." in context
    assert "Confirmed in /login." in context
    assert "Interesting admin routes" in context
    assert str(run_dir.resolve()) in context


def test_build_previous_scan_context_truncates_large_context(tmp_path: Path) -> None:
    run_dir = tmp_path / "strix_runs" / "scan-large"
    run_dir.mkdir(parents=True)
    (run_dir / "penetration_test_report.md").write_text("A" * 200, encoding="utf-8")

    context = build_previous_scan_context("scan-large", tmp_path, max_chars=50)

    assert "[previous scan context truncated]" in context
