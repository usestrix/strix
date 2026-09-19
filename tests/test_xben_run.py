"""Tests for the XBEN benchmark runner (benchmarks/xben/run.py).

This module drives a real ``strix`` subprocess against a live Docker + LLM
environment, neither of which is available here. Every test below mocks
``subprocess.run`` (via ``run.run_strix_subprocess``) and the filesystem
artifacts a real run would produce, so only the argument-parsing and
run-record-construction logic is exercised -- never a real scan.
"""

from __future__ import annotations

import json
import subprocess
from datetime import UTC, datetime
from typing import TYPE_CHECKING, Any
from unittest.mock import MagicMock

import pytest

from benchmarks.xben import run


if TYPE_CHECKING:
    from pathlib import Path


def _manifest_entry(**overrides: Any) -> dict[str, Any]:
    base: dict[str, Any] = {
        "challenge_id": "XBEN-001-24",
        "challenge_name": "Test Challenge",
        "difficulty": "easy",
        "target": "https://target.example.com",
        "flag": "FLAG{test}",
    }
    base.update(overrides)
    return base


class TestChallengeFromDict:
    def test_valid_entry(self) -> None:
        spec = run._challenge_from_dict(_manifest_entry(), default_id=None, source="test")
        assert spec.challenge_id == "XBEN-001-24"
        assert spec.difficulty == "easy"
        assert spec.target == "https://target.example.com"
        assert spec.flag == "FLAG{test}"

    def test_default_id_used_when_missing(self) -> None:
        entry = _manifest_entry()
        del entry["challenge_id"]
        spec = run._challenge_from_dict(entry, default_id="dir-name", source="test")
        assert spec.challenge_id == "dir-name"

    def test_missing_id_raises(self) -> None:
        entry = _manifest_entry()
        del entry["challenge_id"]
        with pytest.raises(run.ChallengeSpecError, match="challenge_id"):
            run._challenge_from_dict(entry, default_id=None, source="test")

    def test_invalid_difficulty_raises(self) -> None:
        with pytest.raises(run.ChallengeSpecError, match="difficulty"):
            run._challenge_from_dict(
                _manifest_entry(difficulty="impossible"), default_id=None, source="test"
            )

    def test_missing_target_raises(self) -> None:
        entry = _manifest_entry()
        del entry["target"]
        with pytest.raises(run.ChallengeSpecError, match="target"):
            run._challenge_from_dict(entry, default_id=None, source="test")

    def test_missing_flag_is_allowed(self) -> None:
        entry = _manifest_entry()
        del entry["flag"]
        spec = run._challenge_from_dict(entry, default_id=None, source="test")
        assert spec.flag is None


class TestLoadManifest:
    def test_loads_list_of_entries(self, tmp_path: Path) -> None:
        manifest = tmp_path / "manifest.json"
        manifest.write_text(json.dumps([_manifest_entry(), _manifest_entry(challenge_id="B")]))
        specs = run.load_manifest(manifest)
        assert [s.challenge_id for s in specs] == ["XBEN-001-24", "B"]

    def test_non_list_manifest_raises(self, tmp_path: Path) -> None:
        manifest = tmp_path / "manifest.json"
        manifest.write_text(json.dumps({"not": "a list"}))
        with pytest.raises(run.ChallengeSpecError, match="must be a JSON array"):
            run.load_manifest(manifest)


class TestDiscoverChallenges:
    def test_discovers_challenge_json_per_subdirectory(self, tmp_path: Path) -> None:
        chal_dir = tmp_path / "chal-1"
        chal_dir.mkdir()
        entry = _manifest_entry()
        del entry["challenge_id"]
        (chal_dir / "challenge.json").write_text(json.dumps(entry))

        specs = run.discover_challenges(tmp_path)
        assert len(specs) == 1
        assert specs[0].challenge_id == "chal-1"

    def test_missing_directory_raises(self, tmp_path: Path) -> None:
        with pytest.raises(FileNotFoundError):
            run.discover_challenges(tmp_path / "missing")

    def test_no_challenges_found_raises(self, tmp_path: Path) -> None:
        with pytest.raises(run.ChallengeSpecError, match=r"no challenge\.json"):
            run.discover_challenges(tmp_path)


class TestBuildStrixCommand:
    def test_basic_command_shape(self) -> None:
        command = run.build_strix_command(
            strix_bin="strix",
            target="https://target.example.com",
            run_name="xben-run-1",
            max_budget_usd=None,
            max_turns=None,
        )
        assert command == [
            "strix",
            "--target",
            "https://target.example.com",
            "--non-interactive",
            "--run-name",
            "xben-run-1",
        ]

    def test_includes_optional_budget_and_turns(self) -> None:
        command = run.build_strix_command(
            strix_bin="strix",
            target="https://target.example.com",
            run_name="xben-run-1",
            max_budget_usd=5.0,
            max_turns=100,
        )
        assert "--max-budget" in command
        assert command[command.index("--max-budget") + 1] == "5.0"
        assert "--max-turns" in command
        assert command[command.index("--max-turns") + 1] == "100"


class TestFlagWasMatched:
    def test_no_flag_means_not_matched(self, tmp_path: Path) -> None:
        assert run.flag_was_matched(tmp_path, None) is False

    def test_flag_found_in_vulnerabilities_json(self, tmp_path: Path) -> None:
        (tmp_path / "vulnerabilities.json").write_text('[{"evidence": "FLAG{found-it}"}]')
        assert run.flag_was_matched(tmp_path, "FLAG{found-it}") is True

    def test_flag_found_in_report_markdown(self, tmp_path: Path) -> None:
        (tmp_path / "penetration_test_report.md").write_text("We recovered FLAG{in-report}.")
        assert run.flag_was_matched(tmp_path, "FLAG{in-report}") is True

    def test_flag_not_present_anywhere(self, tmp_path: Path) -> None:
        (tmp_path / "vulnerabilities.json").write_text("[]")
        assert run.flag_was_matched(tmp_path, "FLAG{missing}") is False


class TestBuildRunRecord:
    def test_builds_conformant_record_from_run_json(self, tmp_path: Path) -> None:
        run_dir = tmp_path / "strix_runs" / "xben-run-1"
        run_dir.mkdir(parents=True)
        (run_dir / "run.json").write_text(
            json.dumps(
                {
                    "status": "completed",
                    "llm_usage": {"cost": 2.5, "input_tokens": 1000, "output_tokens": 200},
                },
            ),
        )
        (run_dir / "vulnerabilities.json").write_text('[{"evidence": "FLAG{yes}"}]')

        challenge = run.ChallengeSpec(
            challenge_id="XBEN-001-24",
            challenge_name="Test",
            difficulty="easy",
            target="https://target.example.com",
            flag="FLAG{yes}",
        )
        started = datetime(2026, 1, 1, tzinfo=UTC)
        finished = datetime(2026, 1, 1, 0, 5, tzinfo=UTC)

        record = run.build_run_record(
            challenge=challenge,
            run_dir=run_dir,
            run_id="xben-run-1",
            model="anthropic/claude-sonnet-4-5",
            mode="black-box",
            started_at=started,
            finished_at=finished,
        )

        assert record["challenge_id"] == "XBEN-001-24"
        assert record["difficulty"] == "easy"
        assert record["model"] == "anthropic/claude-sonnet-4-5"
        assert record["mode"] == "black-box"
        assert record["flag_matched"] is True
        assert record["solved"] is True
        assert record["duration_seconds"] == pytest.approx(300.0)
        assert record["total_cost_usd"] == pytest.approx(2.5)
        assert record["input_tokens"] == 1000
        assert record["output_tokens"] == 200
        assert record["run_id"] == "xben-run-1"

    def test_missing_run_json_raises(self, tmp_path: Path) -> None:
        challenge = run.ChallengeSpec(
            challenge_id="X",
            challenge_name="X",
            difficulty="easy",
            target="https://target.example.com",
        )
        with pytest.raises(FileNotFoundError):
            run.build_run_record(
                challenge=challenge,
                run_dir=tmp_path,
                run_id="run-1",
                model="m",
                mode="black-box",
                started_at=datetime.now(tz=UTC),
                finished_at=datetime.now(tz=UTC),
            )

    def test_unsolved_without_flag_uses_status(self, tmp_path: Path) -> None:
        run_dir = tmp_path
        (run_dir / "run.json").write_text(json.dumps({"status": "completed", "llm_usage": {}}))
        challenge = run.ChallengeSpec(
            challenge_id="X",
            challenge_name="X",
            difficulty="easy",
            target="https://target.example.com",
            flag=None,
        )
        record = run.build_run_record(
            challenge=challenge,
            run_dir=run_dir,
            run_id="run-1",
            model="m",
            mode="black-box",
            started_at=datetime.now(tz=UTC),
            finished_at=datetime.now(tz=UTC),
        )
        assert record["flag_matched"] is False
        assert record["solved"] is True  # falls back to run status when there's no flag to check


class TestRunOneChallengeWithMockedSubprocess:
    def test_invokes_subprocess_and_builds_record(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        challenge = run.ChallengeSpec(
            challenge_id="XBEN-001-24",
            challenge_name="Test",
            difficulty="easy",
            target="https://target.example.com",
            flag="FLAG{yes}",
        )

        fake_result = subprocess.CompletedProcess(
            args=["strix"], returncode=0, stdout="", stderr=""
        )
        mock_run = MagicMock(return_value=fake_result)
        monkeypatch.setattr(run, "run_strix_subprocess", mock_run)

        def fake_run_dir_for(run_name: str) -> Path:
            run_dir = tmp_path / run_name
            run_dir.mkdir(parents=True, exist_ok=True)
            (run_dir / "run.json").write_text(
                json.dumps({"status": "completed", "llm_usage": {"cost": 1.0}}),
            )
            (run_dir / "vulnerabilities.json").write_text('[{"evidence": "FLAG{yes}"}]')
            return run_dir

        args = run.build_parser().parse_args(
            ["--manifest", "unused.json", "--model", "test-model"],
        )

        record = run.run_one_challenge(
            challenge,
            args=args,
            env={},
            run_dir_for_name=fake_run_dir_for,
        )

        mock_run.assert_called_once()
        called_command = mock_run.call_args.args[0]
        assert called_command[:3] == ["strix", "--target", "https://target.example.com"]
        assert record["challenge_id"] == "XBEN-001-24"
        assert record["flag_matched"] is True


class TestMainDryRun:
    def test_dry_run_prints_commands_without_running_strix(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
    ) -> None:
        manifest = tmp_path / "manifest.json"
        manifest.write_text(json.dumps([_manifest_entry()]))

        mock_run = MagicMock()
        monkeypatch.setattr(run, "run_strix_subprocess", mock_run)

        exit_code = run.main(["--manifest", str(manifest), "--model", "test-model", "--dry-run"])

        assert exit_code == 0
        mock_run.assert_not_called()
        captured = capsys.readouterr()
        assert "XBEN-001-24" in captured.out
        assert "--target" in captured.out

    def test_unknown_challenge_id_filter_errors(
        self, tmp_path: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        manifest = tmp_path / "manifest.json"
        manifest.write_text(json.dumps([_manifest_entry()]))

        exit_code = run.main(
            [
                "--manifest",
                str(manifest),
                "--model",
                "test-model",
                "--challenge-id",
                "does-not-exist",
                "--dry-run",
            ],
        )
        assert exit_code == 1
        captured = capsys.readouterr()
        assert "does-not-exist" in captured.err
