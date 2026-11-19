"""Tests for the --skills and --skills-dir CLI flags and STRIX_SKILLS_DIR."""

from __future__ import annotations

import importlib
import json
import os
import sys
from types import SimpleNamespace
from typing import TYPE_CHECKING, Any

import pytest

from strix import skills as skills_pkg
from strix.report.state import ReportState


if TYPE_CHECKING:
    from pathlib import Path


cli_main: Any = importlib.import_module("strix.interface.main")

ARGV = ["strix", "-t", "https://test.com/", "-n"]


def _stub_settings(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        cli_main,
        "load_settings",
        lambda: SimpleNamespace(runtime=SimpleNamespace(max_local_copy_mb=1024)),
    )


def _write_skill(root: Path, rel: str, description: str) -> Path:
    path = root / rel
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        f"---\ndescription: {description}\n---\n# {rel}\n{description}\n", encoding="utf-8"
    )
    return path


@pytest.fixture(autouse=True)
def _isolate(monkeypatch: pytest.MonkeyPatch) -> None:
    # setenv (not delenv) so the value the parser writes is restored afterwards.
    monkeypatch.setenv(skills_pkg.SKILLS_DIR_ENV, "")
    monkeypatch.setattr(skills_pkg, "_EXTRA_SKILL_DIRS", [])


def test_skills_flag_parses_names_into_list(monkeypatch: pytest.MonkeyPatch) -> None:
    _stub_settings(monkeypatch)
    monkeypatch.setattr(
        sys, "argv", [*ARGV, "--skills", "idor, vulnerabilities/mass_assignment,idor,"]
    )

    args = cli_main.parse_arguments()

    assert args.skills == ["idor", "vulnerabilities/mass_assignment"]


def test_skills_flag_defaults_to_empty_list(monkeypatch: pytest.MonkeyPatch) -> None:
    _stub_settings(monkeypatch)
    monkeypatch.setattr(sys, "argv", ARGV)

    assert cli_main.parse_arguments().skills == []


def test_skills_flag_rejects_unknown_name(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    _stub_settings(monkeypatch)
    monkeypatch.setattr(sys, "argv", [*ARGV, "--skills", "idor,no_such_skill"])

    with pytest.raises(SystemExit):
        cli_main.parse_arguments()

    err = capsys.readouterr().err
    assert "--skills:" in err
    assert "no_such_skill" in err


def test_skills_flag_has_no_count_limit(monkeypatch: pytest.MonkeyPatch) -> None:
    _stub_settings(monkeypatch)
    names = [s["name"] for s in skills_pkg.get_available_skills()["vulnerabilities"]][:7]
    assert len(names) == 7
    monkeypatch.setattr(sys, "argv", [*ARGV, "--skills", ",".join(names)])

    assert cli_main.parse_arguments().skills == names


def test_skills_dir_flag_registers_custom_root(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _write_skill(tmp_path, "custom/my_method.md", "Our methodology")
    _stub_settings(monkeypatch)
    monkeypatch.setattr(
        sys, "argv", [*ARGV, "--skills-dir", str(tmp_path), "--skills", "custom/my_method"]
    )

    args = cli_main.parse_arguments()

    assert args.skills == ["custom/my_method"]
    assert os.environ[skills_pkg.SKILLS_DIR_ENV] == str(tmp_path)
    assert skills_pkg.skill_search_dirs()[0] == tmp_path
    assert "my_method" in skills_pkg.load_skills(["custom/my_method"])


def test_skills_dir_flag_is_repeatable_and_prepends_to_env(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    first, second, from_env = tmp_path / "a", tmp_path / "b", tmp_path / "env"
    for d in (first, second, from_env):
        d.mkdir()
    monkeypatch.setenv(skills_pkg.SKILLS_DIR_ENV, str(from_env))
    _stub_settings(monkeypatch)
    monkeypatch.setattr(
        sys, "argv", [*ARGV, "--skills-dir", str(first), "--skills-dir", str(second)]
    )

    cli_main.parse_arguments()

    assert os.environ[skills_pkg.SKILLS_DIR_ENV].split(os.pathsep) == [
        str(first),
        str(second),
        str(from_env),
    ]


def test_skills_dir_flag_rejects_missing_directory(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    _stub_settings(monkeypatch)
    monkeypatch.setattr(sys, "argv", [*ARGV, "--skills-dir", str(tmp_path / "nope")])

    with pytest.raises(SystemExit):
        cli_main.parse_arguments()

    assert "--skills-dir directory not found" in capsys.readouterr().err


def test_env_skill_dir_is_searched_and_shadows_builtin(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _write_skill(tmp_path, "vulnerabilities/idor.md", "Our IDOR playbook")
    _write_skill(tmp_path, "custom/gap_assessment.md", "Web/API gap assessment")
    monkeypatch.setenv(skills_pkg.SKILLS_DIR_ENV, os.pathsep.join([str(tmp_path), " "]))

    assert skills_pkg.env_skill_dirs() == (tmp_path,)
    assert skills_pkg.skill_search_dirs()[0] == tmp_path
    catalog = skills_pkg.get_available_skills()
    assert {"name": "gap_assessment", "description": "Web/API gap assessment"} in catalog["custom"]
    idor = [s for s in catalog["vulnerabilities"] if s["name"] == "idor"]
    assert idor == [{"name": "idor", "description": "Our IDOR playbook"}]
    assert "Our IDOR playbook" in skills_pkg.load_skills(["idor"])["idor"]


def test_registered_dir_wins_over_env_dir(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    env_dir, reg_dir = tmp_path / "env", tmp_path / "reg"
    _write_skill(env_dir, "custom/x.md", "from env")
    _write_skill(reg_dir, "custom/x.md", "from registered")
    monkeypatch.setenv(skills_pkg.SKILLS_DIR_ENV, str(env_dir))
    skills_pkg.register_skill_dir(reg_dir)

    assert skills_pkg.skill_search_dirs()[:2] == (reg_dir, env_dir)
    assert "from registered" in skills_pkg.load_skills(["custom/x"])["x"]


def test_scan_config_and_run_record_carry_skills(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _stub_settings(monkeypatch)
    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr(sys, "argv", [*ARGV, "--skills", "idor,business_logic"])
    args = cli_main.parse_arguments()

    state = ReportState(args.run_name)
    state.set_scan_config({"targets": args.targets_info, "skills": args.skills})

    assert state.run_record["skills"] == ["idor", "business_logic"]


def _write_resumable_run(runs_dir: Path, run_name: str, record: dict[str, Any]) -> None:
    run_dir = runs_dir / run_name
    run_dir.mkdir(parents=True, exist_ok=True)
    (run_dir / "run.json").write_text(json.dumps(record), encoding="utf-8")
    state_dir = run_dir / ".state"
    state_dir.mkdir(exist_ok=True)
    (state_dir / "agents.json").write_text("{}", encoding="utf-8")


def _resumable_record(skills: list[str]) -> dict[str, Any]:
    return {
        "run_name": "pentest_abcd",
        "targets_info": [{"type": "web_application", "details": {"original": "https://t.com/"}}],
        "local_sources": [],
        "instruction": "",
        "scan_mode": "deep",
        "skills": skills,
    }


def test_resume_restores_persisted_skills(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    _stub_settings(monkeypatch)
    monkeypatch.chdir(tmp_path)
    _write_resumable_run(tmp_path / "strix_runs", "pentest_abcd", _resumable_record(["idor"]))
    monkeypatch.setattr(sys, "argv", ["strix", "--resume", "pentest_abcd"])

    assert cli_main.parse_arguments().skills == ["idor"]


def test_resume_explicit_skills_flag_wins(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    _stub_settings(monkeypatch)
    monkeypatch.chdir(tmp_path)
    _write_resumable_run(tmp_path / "strix_runs", "pentest_abcd", _resumable_record(["idor"]))
    monkeypatch.setattr(
        sys, "argv", ["strix", "--resume", "pentest_abcd", "--skills", "business_logic"]
    )

    assert cli_main.parse_arguments().skills == ["business_logic"]
