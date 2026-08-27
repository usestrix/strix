from __future__ import annotations

import os
import sys
from typing import TYPE_CHECKING

import pytest

from strix.config import loader
from strix.interface.cli_args import parse_arguments


if TYPE_CHECKING:
    from pathlib import Path


@pytest.fixture(autouse=True)
def _isolated_settings(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(loader, "_cached", None)
    monkeypatch.setattr(loader, "_override", tmp_path / "missing-config.json")
    monkeypatch.delenv("STRIX_VERIFY_FINDINGS", raising=False)


def test_verify_findings_flag_enables_process_setting(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        sys,
        "argv",
        ["strix", "--target", "https://example.com", "--verify-findings"],
    )

    args = parse_arguments()

    assert args.verify_findings is True
    assert loader.load_settings().verification.enabled is True
    assert "STRIX_VERIFY_FINDINGS" not in os.environ


def test_verify_findings_appears_in_help(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    monkeypatch.setattr(sys, "argv", ["strix", "--help"])

    with pytest.raises(SystemExit) as exc_info:
        parse_arguments()

    assert exc_info.value.code == 0
    assert "--verify-findings" in capsys.readouterr().out
