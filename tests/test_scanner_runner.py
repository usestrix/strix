"""Deterministic tests for the scanner_runner tool."""

from __future__ import annotations

import json
import subprocess
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

import pytest

from strix.tools.scanner_runner.tool import (
    ScannerNotFoundError,
    ScannerTimeoutError,
    _parse_findings,
    run_scanner,
)


_GITLEAKS_LINE = json.dumps(
    {
        "RuleID": "aws-access-key",
        "Description": "AWS Access Key",
        "File": "src/config.py",
        "StartLine": 12,
        "EndLine": 12,
        "Fingerprint": "abc123",
    }
)

_TRUFFLEHOG_LINE = json.dumps(
    {
        "DetectorName": "AWS",
        "Verified": True,
        "Raw": "AKIA...",
        "SourceMetadata": {
            "Data": {
                "Filesystem": {
                    "file": "src/secrets.py",
                    "line": 7,
                }
            }
        },
    }
)

_TRIVY_OUTPUT = json.dumps(
    {
        "Results": [
            {
                "Target": "requirements.txt",
                "Vulnerabilities": [
                    {
                        "VulnerabilityID": "CVE-2024-1",
                        "Title": "Bad lib",
                        "Severity": "HIGH",
                        "PkgName": "badlib",
                        "InstalledVersion": "1.0.0",
                        "FixedVersion": "1.0.1",
                    }
                ],
            }
        ]
    }
)


def test_run_scanner_tool_not_found() -> None:
    """A missing scanner produces a structured ScannerNotFoundError."""
    with (
        patch("shutil.which", return_value=None),
        pytest.raises(ScannerNotFoundError, match="Scanner not found on PATH: gitleaks"),
    ):
        run_scanner("gitleaks", ".")


def test_run_scanner_unsupported_tool() -> None:
    """An unsupported tool name raises ScannerNotFoundError."""
    with pytest.raises(ScannerNotFoundError, match="Unsupported scanner: nmap"):
        run_scanner("nmap", ".")


def test_run_scanner_timeout() -> None:
    """A subprocess timeout is surfaced as ScannerTimeoutError."""
    with (
        patch("shutil.which", return_value="/usr/bin/gitleaks"),
        patch(
            "subprocess.run",
            side_effect=subprocess.TimeoutExpired(cmd=["gitleaks"], timeout=300),
        ),
        pytest.raises(ScannerTimeoutError, match="Scanner gitleaks timed out"),
    ):
        run_scanner("gitleaks", ".")


def test_run_scanner_gitleaks_success(tmp_path: Path) -> None:
    """Gitleaks output is parsed into a stably sorted finding list."""
    raw = f"{_GITLEAKS_LINE}\n{_GITLEAKS_LINE.replace('src/config.py', 'src/other.py')}\n"
    with (
        patch("shutil.which", return_value="/usr/bin/gitleaks"),
        patch(
            "subprocess.run",
            side_effect=[
                _fake_completed("gitleaks 8.30.1", 0),
                _fake_completed(raw, 0),
            ],
        ),
    ):
        result = run_scanner("gitleaks", "src/", output_dir=tmp_path)

    assert result["tool"] == "gitleaks"
    assert result["version"] == "gitleaks 8.30.1"
    assert result["target"] == "src/"
    assert result["returncode"] == 0
    assert len(result["findings"]) == 2
    assert result["findings"][0]["file"] == "src/config.py"
    assert result["findings"][1]["file"] == "src/other.py"
    assert Path(result["raw_output_ref"]).exists()


def test_run_scanner_trufflehog_success() -> None:
    """Trufflehog output is parsed and findings are sorted."""
    raw = f"{_TRUFFLEHOG_LINE}\n"
    with (
        patch("shutil.which", return_value="/usr/bin/trufflehog"),
        patch(
            "subprocess.run",
            side_effect=[
                _fake_completed("3.95.5", 0),
                _fake_completed(raw, 0),
            ],
        ),
    ):
        result = run_scanner("trufflehog", "git+https://example.com/repo")

    assert result["tool"] == "trufflehog"
    assert result["version"] == "3.95.5"
    assert result["findings"][0]["detector_name"] == "AWS"
    assert result["findings"][0]["verified"] is True


def test_run_scanner_trivy_success() -> None:
    """Trivy JSON output is parsed into a sorted finding list."""
    with (
        patch("shutil.which", return_value="/usr/bin/trivy"),
        patch(
            "subprocess.run",
            side_effect=[
                _fake_completed("0.71.0", 0),
                _fake_completed(_TRIVY_OUTPUT, 1),
            ],
        ),
    ):
        result = run_scanner("trivy", "fs", extra_args=["--scanners", "vuln"])

    assert result["tool"] == "trivy"
    assert result["version"] == "0.71.0"
    assert result["returncode"] == 1
    assert result["findings"][0]["vulnerability_id"] == "CVE-2024-1"


def test_parse_findings_empty_for_unknown_tool() -> None:
    """Unknown tools return an empty finding list without crashing."""
    assert _parse_findings("unknown", "some output") == []


def _fake_completed(stdout: str, returncode: int) -> SimpleNamespace:
    """Return a minimal CompletedProcess-like object."""
    return SimpleNamespace(stdout=stdout, stderr="", returncode=returncode)
