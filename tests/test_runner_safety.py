from __future__ import annotations

import json
from typing import TYPE_CHECKING

import pytest

from strix.core.runner import _safety_mode, _validate_resume_safety_mode


if TYPE_CHECKING:
    from pathlib import Path


def _record(run_dir: Path, mode: str | None) -> None:
    run_dir.mkdir(exist_ok=True)
    data = {} if mode is None else {"safety_mode": mode}
    (run_dir / "run.json").write_text(json.dumps(data), encoding="utf-8")


def test_programmatic_runs_default_to_guarded() -> None:
    assert _safety_mode({}) == "guarded"


@pytest.mark.parametrize("mode", ["guarded", "off"])
def test_resume_accepts_unchanged_safety_mode(tmp_path: Path, mode: str) -> None:
    _record(tmp_path, mode)

    _validate_resume_safety_mode(tmp_path, mode)  # type: ignore[arg-type]


def test_legacy_resume_defaults_to_off(tmp_path: Path) -> None:
    _record(tmp_path, None)

    _validate_resume_safety_mode(tmp_path, "off")


@pytest.mark.parametrize(
    ("persisted", "requested"),
    [("guarded", "off"), ("off", "guarded"), (None, "guarded")],
)
def test_resume_rejects_safety_mode_changes(
    tmp_path: Path,
    persisted: str | None,
    requested: str,
) -> None:
    _record(tmp_path, persisted)

    with pytest.raises(ValueError, match="Cannot change safety mode"):
        _validate_resume_safety_mode(tmp_path, requested)  # type: ignore[arg-type]


def test_resume_rejects_removed_observe_mode(tmp_path: Path) -> None:
    _record(tmp_path, "observe")

    with pytest.raises(ValueError, match="observe mode was removed"):
        _validate_resume_safety_mode(tmp_path, "guarded")


@pytest.mark.parametrize("malformed", [None, "", False, 0])
def test_resume_rejects_present_malformed_safety_mode(
    tmp_path: Path,
    malformed: object,
) -> None:
    (tmp_path / "run.json").write_text(
        json.dumps({"safety_mode": malformed}),
        encoding="utf-8",
    )

    with pytest.raises(ValueError, match="invalid safety mode"):
        _validate_resume_safety_mode(tmp_path, "off")
