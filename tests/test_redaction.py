"""Secrets named by STRIX_REDACT_ENV are masked in every run artifact."""

from __future__ import annotations

import asyncio
import json
import sqlite3
from typing import TYPE_CHECKING, Any, cast

import pytest
from agents.memory import SQLiteSession

from strix.config import loader
from strix.core.paths import runtime_state_dir
from strix.report.redaction import (
    build_replacements,
    parse_env_names,
    redact_run_dir,
    redact_text,
    secrets_from_env,
)
from strix.report.state import ReportState


if TYPE_CHECKING:
    from pathlib import Path


# Quote, backslash, space, "@" and a non-ASCII letter: each one is written
# differently by JSON escaping, double JSON escaping and percent-encoding.
PASSWORD = 'Hunter "2" \\ p@ss é'  # noqa: S105
MARKER = "[REDACTED:PRINCIPAL_A_PASSWORD]"
SECRETS = {"PRINCIPAL_A_PASSWORD": PASSWORD}


def _forms_on_disk(value: str) -> list[bytes]:
    once = json.dumps(value)[1:-1]
    once_utf8 = json.dumps(value, ensure_ascii=False)[1:-1]
    return [
        value.encode(),
        once.encode(),
        once_utf8.encode(),
        json.dumps(once)[1:-1].encode(),
        json.dumps(once_utf8, ensure_ascii=False)[1:-1].encode(),
    ]


def _assert_no_secret_under(directory: Path) -> None:
    for path in directory.rglob("*"):
        if path.is_file():
            data = path.read_bytes()
            for form in _forms_on_disk(PASSWORD):
                assert form not in data, f"secret left in {path}"


def test_parse_env_names_accepts_commas_and_spaces() -> None:
    assert parse_env_names(" A, B  C,,A ") == ["A", "B", "C"]
    assert parse_env_names("") == []
    assert parse_env_names(None) == []


def test_secrets_from_env_skips_unset_empty_and_short_values() -> None:
    environ = {"LONG": "long-enough", "EMPTY": "", "SHORT": "abc"}
    assert secrets_from_env(["LONG", "EMPTY", "SHORT", "UNSET"], environ) == {"LONG": "long-enough"}


def test_redact_text_covers_raw_json_and_percent_encoded_forms() -> None:
    replacements = build_replacements(SECRETS)
    text = " | ".join(
        [
            PASSWORD,
            json.dumps({"password": PASSWORD}),
            json.dumps({"arguments": json.dumps({"password": PASSWORD})}),
            "password=" + "Hunter%20%222%22%20%5C%20p%40ss%20%C3%A9",
        ]
    )
    redacted = redact_text(text, replacements)
    assert redacted.count(MARKER) == 4
    for form in _forms_on_disk(PASSWORD):
        assert form.decode() not in redacted


def test_redact_run_dir_masks_json_text_and_sqlite_artifacts(tmp_path: Path) -> None:
    run_dir = tmp_path / "run"
    state_dir = runtime_state_dir(run_dir)
    state_dir.mkdir(parents=True)
    (run_dir / "run.json").write_text(
        json.dumps({"scan_config": {"instruction": f"Log in with {PASSWORD}"}}, indent=2),
        encoding="utf-8",
    )
    (state_dir / "notes.json").write_text(
        json.dumps([{"content": PASSWORD}], ensure_ascii=False), encoding="utf-8"
    )
    (run_dir / "strix.log").write_text(f"login ok for {PASSWORD}\n", encoding="utf-8")
    (run_dir / "strix.log").chmod(0o640)

    # The SDK's own session store, in WAL mode, with the secret inside a
    # tool call's JSON-encoded arguments.
    session = SQLiteSession(session_id="agent-1", db_path=state_dir / "agents.db")
    asyncio.run(
        session.add_items(
            [
                {"role": "user", "content": f"Credentials: {PASSWORD}"},
                {
                    "type": "function_call",
                    "call_id": "c1",
                    "name": "terminal",
                    "arguments": json.dumps({"command": f"login --password '{PASSWORD}'"}),
                },
            ]
        )
    )
    session.close()

    summary = redact_run_dir(run_dir, SECRETS)

    assert summary.errors == []
    assert {p.name for p in summary.files_changed} == {
        "run.json",
        "notes.json",
        "strix.log",
        "agents.db",
    }
    _assert_no_secret_under(run_dir)
    assert MARKER in json.loads((run_dir / "run.json").read_text())["scan_config"]["instruction"]
    assert (run_dir / "strix.log").stat().st_mode & 0o777 == 0o640

    reopened = SQLiteSession(session_id="agent-1", db_path=state_dir / "agents.db")
    items = [cast("dict[str, Any]", i) for i in asyncio.run(reopened.get_items())]
    reopened.close()
    assert items[0]["content"] == f"Credentials: {MARKER}"
    arguments = json.loads(items[1]["arguments"])
    assert arguments == {"command": f"login --password '{MARKER}'"}
    with sqlite3.connect(state_dir / "agents.db") as connection:
        assert connection.execute("PRAGMA integrity_check").fetchone() == ("ok",)


def test_redact_run_dir_is_idempotent_and_leaves_clean_files_alone(tmp_path: Path) -> None:
    (tmp_path / "clean.md").write_text("nothing to see", encoding="utf-8")
    (tmp_path / "dirty.md").write_text(PASSWORD, encoding="utf-8")

    first = redact_run_dir(tmp_path, SECRETS)
    second = redact_run_dir(tmp_path, SECRETS)

    assert [p.name for p in first.files_changed] == ["dirty.md"]
    assert second.files_changed == []
    assert (tmp_path / "dirty.md").read_text() == MARKER


def test_redact_run_dir_without_secrets_changes_nothing(tmp_path: Path) -> None:
    (tmp_path / "run.json").write_text(PASSWORD, encoding="utf-8")
    assert redact_run_dir(tmp_path, {}).files_changed == []
    assert (tmp_path / "run.json").read_text() == PASSWORD


@pytest.fixture
def _fresh_settings(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    monkeypatch.setattr(loader, "_cached", None)
    monkeypatch.setattr(loader, "_override", tmp_path / "no-config.json")


@pytest.mark.usefixtures("_fresh_settings")
def test_report_state_cleanup_redacts_the_instruction_in_run_json(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv("PRINCIPAL_A_PASSWORD", PASSWORD)
    monkeypatch.setenv("STRIX_REDACT_ENV", "PRINCIPAL_A_PASSWORD")
    state = ReportState(run_name="redact-run")
    state.set_scan_config({"user_instructions": f"Log in as a@example.com / {PASSWORD}"})

    state.cleanup()

    run_dir = state.get_run_dir()
    _assert_no_secret_under(run_dir)
    record = json.loads((run_dir / "run.json").read_text())
    assert record["instruction"] == f"Log in as a@example.com / {MARKER}"


@pytest.mark.usefixtures("_fresh_settings")
def test_report_state_cleanup_keeps_secrets_when_redaction_is_not_configured(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.chdir(tmp_path)
    monkeypatch.delenv("STRIX_REDACT_ENV", raising=False)
    state = ReportState(run_name="plain-run")
    state.set_scan_config({"user_instructions": PASSWORD})

    state.cleanup()

    record = json.loads((state.get_run_dir() / "run.json").read_text())
    assert record["instruction"] == PASSWORD
