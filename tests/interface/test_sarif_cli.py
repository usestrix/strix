import importlib
import sys
from argparse import Namespace
from pathlib import Path
from typing import Any

from strix.interface.main import parse_arguments, write_requested_sarif_output


main_module = importlib.import_module("strix.interface.main")


def test_parse_arguments_accepts_sarif_flags(monkeypatch) -> None:
    monkeypatch.setattr(
        sys,
        "argv",
        [
            "strix",
            "--target",
            "./",
            "--non-interactive",
            "--sarif",
            "--sarif-output",
            "results.sarif",
        ],
    )

    args = parse_arguments()

    assert args.sarif is True
    assert args.sarif_output == "results.sarif"


def test_write_requested_sarif_output_writes_before_non_interactive_exit(
    monkeypatch,
    tmp_path: Path,
) -> None:
    output_path = tmp_path / "results.sarif"
    args = Namespace(sarif=False, sarif_output=str(output_path))

    class FakeTracer:
        def __init__(self) -> None:
            self.vulnerability_reports: list[dict[str, Any]] = [
                {
                    "id": "vuln-0001",
                    "title": "Unsafe eval",
                    "severity": "high",
                    "code_locations": [{"file": "src/app.py", "start_line": 10, "end_line": 10}],
                }
            ]

    def get_fake_tracer() -> FakeTracer:
        return FakeTracer()

    monkeypatch.setattr(main_module, "get_global_tracer", get_fake_tracer)

    written_path = write_requested_sarif_output(args, tmp_path / "strix_runs" / "demo")

    assert written_path == output_path
    assert output_path.exists()


def test_write_requested_sarif_output_reports_write_errors(
    monkeypatch,
    capsys,
    tmp_path: Path,
) -> None:
    args = Namespace(sarif=True, sarif_output=str(tmp_path / "results.sarif"))

    def raise_write_error(*_args: Any, **_kwargs: Any) -> None:
        raise OSError("disk full")

    monkeypatch.setattr(main_module, "write_sarif_report", raise_write_error)

    written_path = write_requested_sarif_output(args, tmp_path / "strix_runs" / "demo")

    assert written_path is None
    assert "Failed to write SARIF" in capsys.readouterr().out
