"""Request-body validation must precede source uploads and remote mutations."""

from __future__ import annotations

import json
from typing import TYPE_CHECKING, Any
from unittest.mock import Mock

import pytest
import requests

from strix.interface import cloud
from strix.interface.cloud import source_scan


if TYPE_CHECKING:
    from pathlib import Path


@pytest.fixture
def source_service(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> tuple[Path, list[Any], Mock]:
    """Keep Requests preparation real; replace only its network transport."""
    source = tmp_path / "source"
    source.mkdir()
    (source / "main.py").write_text("print(1)\n", encoding="utf-8")
    sent: list[Any] = []

    def send(_session: Any, request: requests.PreparedRequest, **_kwargs: Any) -> requests.Response:
        sent.append(request)
        payloads = {
            "/api/v1/uploads/request": {
                "upload_id": "upload-fixture",
                "token": "upload-token",
                "signed_url": "https://app.example.test/storage/v1/fixture",
            },
            "/api/v1/uploads/complete": {"id": "upload-fixture"},
            "/api/v1/scans": {"id": "scan-fixture"},
        }
        response = requests.Response()
        response.status_code = 200
        response.headers["content-type"] = "application/json"
        response._content = json.dumps(payloads.get(request.path_url, {})).encode()
        response._content_consumed = True
        response.request = request
        return response

    monkeypatch.setattr(requests.sessions.Session, "send", send)
    monkeypatch.setattr("strix.interface.cloud.runner.time.sleep", lambda _seconds: None)
    prepare = Mock(wraps=source_scan.prepare_source)
    monkeypatch.setattr(source_scan, "prepare_source", prepare)
    return source, sent, prepare


def _arguments(source: Path) -> list[str]:
    return [
        "scans",
        "start",
        "--source",
        str(source),
        "--yes",
        "--json",
        "--token",
        "fixture",
        "--app-url",
        "https://app.example.test",
    ]


@pytest.mark.parametrize("dry_run", [False, True])
@pytest.mark.parametrize(
    "extra",
    [
        ["--max-budget-usd", "nan"],
        ["--max-budget-usd", "inf"],
        ["--max-budget-usd=-inf"],
        ["--max-budget-usd", "1e309"],
        ["--data", '{"max_budget_usd":NaN}'],
        ["--data", '{"nested":{"values":[1,Infinity]}}'],
        ["--headers", '[{"name":"X-Test","value":-Infinity}]'],
    ],
)
def test_nonfinite_body_is_rejected_before_source_or_network(
    source_service: tuple[Path, list[Any], Mock], extra: list[str], dry_run: bool, capsys: Any
) -> None:
    source, sent, prepare = source_service
    argv = [*_arguments(source), *extra, *(["--dry-run"] if dry_run else [])]

    assert cloud.run_cloud(argv) == 2

    payload = json.loads(capsys.readouterr().out)
    assert "finite" in payload["error"]
    assert "launch_outcome_unknown" not in payload
    assert "upload_retained" not in payload
    assert sent == []
    prepare.assert_not_called()


def test_nonfinite_data_file_is_rejected_before_source_or_network(
    source_service: tuple[Path, list[Any], Mock], tmp_path: Path, capsys: Any
) -> None:
    source, sent, prepare = source_service
    data = tmp_path / "request.json"
    data.write_text('{"max_budget_usd":1e309}', encoding="utf-8")

    assert cloud.run_cloud([*_arguments(source), "--data", f"@{data}"]) == 2

    assert "finite" in json.loads(capsys.readouterr().out)["error"]
    assert sent == []
    prepare.assert_not_called()


@pytest.mark.parametrize("dry_run", [False, True])
@pytest.mark.parametrize("budget", ["0", "0.125", "10"])
def test_finite_body_preserves_upload_and_dry_run_behavior(
    source_service: tuple[Path, list[Any], Mock], budget: str, dry_run: bool, capsys: Any
) -> None:
    source, sent, prepare = source_service
    extra = {"nested": {"values": [0, 1.25, "NaN", None, False]}}
    argv = [
        *_arguments(source),
        "--max-budget-usd",
        budget,
        "--data",
        json.dumps(extra),
        *(["--dry-run"] if dry_run else []),
    ]

    assert cloud.run_cloud(argv) == 0

    payload = json.loads(capsys.readouterr().out)
    assert payload["source"]["file_count"] == 1
    prepare.assert_called_once()
    if dry_run:
        assert sent == []
    else:
        assert [(request.method, request.path_url) for request in sent] == [
            ("POST", "/api/v1/uploads/request"),
            ("PUT", "/storage/v1/fixture"),
            ("POST", "/api/v1/uploads/complete"),
            ("POST", "/api/v1/scans"),
        ]
        body = json.loads(sent[-1].body)
        assert body["max_budget_usd"] == float(budget)
        assert body["nested"] == extra["nested"]
        assert payload["scan"]["id"] == "scan-fixture"
