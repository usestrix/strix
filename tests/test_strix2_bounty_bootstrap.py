"""Tests for bounty-mode wiring: bootstrap, env rehydration, and artifact writing."""

from __future__ import annotations

import json
import os
from pathlib import Path
from typing import TYPE_CHECKING

import pytest

from strix.bounty import bootstrap, compile_to_scope, evaluate_roe
from strix.bounty.bootstrap import (
    activate_bounty_from_env,
    bootstrap_bounty,
)
from strix.bounty.dedupe import KnownReport, reset_known_reports
from strix.bounty.loaders.fromfile import load_program_file
from strix.bounty.report import write_bounty_artifacts
from strix.bounty.runtime import BountyContext, get_bounty_context, set_bounty_context
from strix.scope.loader import load_scope_policy


if TYPE_CHECKING:
    from collections.abc import Iterator

_FIXTURES = Path(__file__).parent / "fixtures" / "bounty"
_ENV_KEYS = (
    "STRIX_SCOPE_CONFIG",
    "STRIX_ALLOW_INTRUSIVE",
    bootstrap.ENV_PROGRAM,
    bootstrap.ENV_KNOWN_REPORTS,
    bootstrap.ENV_AUTOMATED_POLICY,
    bootstrap.ENV_INTRUSIVE_POLICY,
)


@pytest.fixture(autouse=True)
def _isolate_bounty_state(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Iterator[None]:
    saved = {k: os.environ.get(k) for k in _ENV_KEYS}
    # Keep every generated artifact inside the test's tmp dir.
    monkeypatch.setattr(bootstrap, "_bounty_dir", lambda program: tmp_path / program.slug)
    yield
    for key, value in saved.items():
        if value is None:
            os.environ.pop(key, None)
        else:
            os.environ[key] = value
    set_bounty_context(None)
    reset_known_reports(None)


def _write_program(tmp_path: Path, **roe: object) -> Path:
    data = {
        "platform": "hackerone",
        "handle": "acme",
        "in_scope": [{"identifier": "*.acme.com", "asset_type": "wildcard"}],
        "roe": roe,
    }
    path = tmp_path / "program.json"
    path.write_text(json.dumps(data), encoding="utf-8")
    return path


# --- bootstrap ---------------------------------------------------------------


def test_bootstrap_writes_artifacts_and_wires_env() -> None:
    result = bootstrap_bounty(str(_FIXTURES / "program_fromfile.yaml"))
    assert result.proceed is True
    assert (result.bounty_dir / "scope.yaml").is_file()
    assert (result.bounty_dir / "program.json").is_file()
    assert (result.bounty_dir / "dedupe.md").is_file()
    assert os.environ["STRIX_SCOPE_CONFIG"] == str(result.bounty_dir / "scope.yaml")
    assert os.environ[bootstrap.ENV_PROGRAM] == str(result.bounty_dir / "program.json")

    # The generated scope.yaml is a valid, enforcing policy.
    policy = load_scope_policy(result.bounty_dir / "scope.yaml")
    assert policy is not None
    assert policy.evaluate("https://api.acme.com/v2/x").allowed
    assert not policy.evaluate("https://acme.com/corporate/page").allowed


def test_bootstrap_refuses_prohibited_program_by_default(tmp_path: Path) -> None:
    program_path = _write_program(tmp_path, automated_testing_allowed=False)
    result = bootstrap_bounty(str(program_path))
    assert result.proceed is False
    assert any("PROHIBITS" in w for w in result.warnings)


def test_bootstrap_warn_and_proceed_overrides_prohibition(tmp_path: Path) -> None:
    program_path = _write_program(tmp_path, automated_testing_allowed=False)
    result = bootstrap_bounty(str(program_path), automated_policy="warn_and_proceed")
    assert result.proceed is True
    assert result.gate.mode == "warn_and_proceed"


def test_bootstrap_auto_intrusive_sets_env(tmp_path: Path) -> None:
    program_path = _write_program(
        tmp_path, automated_testing_allowed=True, state_changing_poc_allowed=True
    )
    result = bootstrap_bounty(str(program_path), intrusive_policy="auto")
    assert result.compiled.policy.allow_intrusive is True
    assert os.environ.get("STRIX_ALLOW_INTRUSIVE") == "1"


# --- env rehydration ---------------------------------------------------------


def test_activate_from_env_binds_context() -> None:
    bootstrap_bounty(str(_FIXTURES / "program_fromfile.yaml"))
    set_bounty_context(None)  # simulate a fresh process
    assert activate_bounty_from_env() is True
    context = get_bounty_context()
    assert context is not None
    assert context.program.handle == "acme"


def test_activate_from_env_noop_without_env() -> None:
    os.environ.pop(bootstrap.ENV_PROGRAM, None)
    set_bounty_context(None)
    assert activate_bounty_from_env() is False
    assert get_bounty_context() is None


# --- artifact writing --------------------------------------------------------


def _bind_context() -> None:
    program = load_program_file(_FIXTURES / "program_fromfile.yaml")
    set_bounty_context(
        BountyContext(
            program=program,
            gate=evaluate_roe(program),
            compiled=compile_to_scope(program),
        )
    )


def test_write_bounty_artifacts(tmp_path: Path) -> None:
    _bind_context()
    reset_known_reports([KnownReport(title="SQL injection in search", asset="shop.acme.com")])
    vulns = [
        {
            "id": "vuln-0001",
            "title": "SQLi in product search",
            "severity": "high",
            "cwe": "CWE-89",
            "endpoint": "https://shop.acme.com/search",
            "description": "Boolean-based SQL injection.",
            "poc_description": "Send ' OR 1=1 --",
            "impact": "Read arbitrary rows.",
            "evidence": "HTTP 200 with dumped rows.",
        }
    ]
    assert write_bounty_artifacts(tmp_path, vulns) is True
    submission = (tmp_path / "bounty" / "submissions" / "vuln-0001.md").read_text(encoding="utf-8")
    assert "SQLi in product search" in submission
    assert "Duplicate check" in submission
    assert "likely_duplicate" in submission  # matches the known SQLi report
    assert (tmp_path / "bounty" / "program.json").is_file()
    assert (tmp_path / "bounty" / "README.md").is_file()
    assert (tmp_path / "bounty" / "submissions" / "INDEX.md").is_file()


def test_write_bounty_artifacts_noop_without_context(tmp_path: Path) -> None:
    set_bounty_context(None)
    assert write_bounty_artifacts(tmp_path, []) is False
    assert not (tmp_path / "bounty").exists()
