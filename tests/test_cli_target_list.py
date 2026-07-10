"""Tests for CLI target-list argument parsing."""

from __future__ import annotations

import importlib
import json
import sys
from types import SimpleNamespace
from typing import TYPE_CHECKING, Any

import pytest


if TYPE_CHECKING:
    from pathlib import Path


cli_main: Any = importlib.import_module("strix.interface.main")


def _stub_settings(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        cli_main,
        "load_settings",
        lambda: SimpleNamespace(runtime=SimpleNamespace(max_local_copy_mb=1024)),
    )


def test_parse_arguments_accepts_target_list_file(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    target_list = tmp_path / "targets.txt"
    target_list.write_text(
        "https://test1.com/\n"
        "\n"
        "http://test2.com:5789/\n",
        encoding="utf-8",
    )
    _stub_settings(monkeypatch)
    monkeypatch.setattr(sys, "argv", ["strix", "--target-list", str(target_list), "-n"])

    args = cli_main.parse_arguments()

    assert [target["original"] for target in args.targets_info] == [
        "https://test1.com/",
        "http://test2.com:5789/",
    ]
    assert [target["type"] for target in args.targets_info] == [
        "web_application",
        "web_application",
    ]


def test_parse_arguments_combines_target_and_target_list(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    target_list = tmp_path / "targets.txt"
    target_list.write_text("http://test2.com:5789/\n", encoding="utf-8")
    _stub_settings(monkeypatch)
    monkeypatch.setattr(
        sys,
        "argv",
        ["strix", "-t", "https://test1.com/", "--target-list", str(target_list)],
    )

    args = cli_main.parse_arguments()

    assert [target["original"] for target in args.targets_info] == [
        "https://test1.com/",
        "http://test2.com:5789/",
    ]


def test_parse_arguments_rejects_resume_with_target_list(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    target_list = tmp_path / "targets.txt"
    target_list.write_text("https://test1.com/\n", encoding="utf-8")
    monkeypatch.setattr(
        sys,
        "argv",
        ["strix", "--resume", "old-run", "--target-list", str(target_list)],
    )

    with pytest.raises(SystemExit):
        cli_main.parse_arguments()

    assert (
        "Cannot combine --resume with --target/--target-list/--mount"
        in capsys.readouterr().err
    )


@pytest.mark.parametrize(
    ("extra_args", "expected"),
    [([], False), (["--completion-nudge"], True)],
)
def test_parse_arguments_completion_nudge_flag(
    extra_args: list[str],
    expected: bool,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _stub_settings(monkeypatch)
    monkeypatch.setattr(
        sys,
        "argv",
        ["strix", "--target", "https://test.example", *extra_args],
    )

    args = cli_main.parse_arguments()

    assert args.completion_nudge is expected


@pytest.mark.parametrize(
    ("persisted", "extra_args"),
    [(True, []), (False, ["--completion-nudge"])],
)
def test_parse_arguments_resume_enables_completion_nudge(
    tmp_path: Path,
    persisted: bool,
    extra_args: list[str],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    (tmp_path / "run.json").write_text(
        json.dumps(
            {
                "targets_info": [
                    {
                        "type": "web_application",
                        "details": {"target": "https://test.example"},
                        "original": "https://test.example",
                    }
                ],
                "completion_nudge": persisted,
            }
        ),
        encoding="utf-8",
    )
    (tmp_path / "agents.json").write_text("{}", encoding="utf-8")
    monkeypatch.setattr(cli_main, "run_dir_for", lambda _run_name: tmp_path)
    monkeypatch.setattr(cli_main, "runtime_state_dir", lambda _run_dir: tmp_path)
    monkeypatch.setattr(
        sys,
        "argv",
        ["strix", "--resume", "existing-run", *extra_args],
    )

    args = cli_main.parse_arguments()

    assert args.completion_nudge is True
