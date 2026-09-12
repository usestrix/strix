"""Tests for the XBEN benchmark scorer (benchmarks/xben/score.py)."""

from __future__ import annotations

import json
from typing import TYPE_CHECKING, Any

import pytest

from benchmarks.xben import score


if TYPE_CHECKING:
    from pathlib import Path


def _schema() -> dict[str, Any]:
    return score.load_schema(score._DEFAULT_SCHEMA_PATH)


def _record(**overrides: Any) -> dict[str, Any]:
    base: dict[str, Any] = {
        "challenge_id": "XBEN-001-24",
        "challenge_name": "Test Challenge",
        "difficulty": "easy",
        "strix_version": "0.4.0",
        "model": "anthropic/claude-sonnet-4-5",
        "mode": "black-box",
        "solved": True,
        "flag_matched": True,
        "duration_seconds": 300,
        "total_cost_usd": 1.5,
        "input_tokens": 1000,
        "output_tokens": 100,
        "started_at": "2026-01-01T00:00:00Z",
        "finished_at": "2026-01-01T00:05:00Z",
        "run_id": "run-1",
    }
    base.update(overrides)
    return base


class TestValidateRecord:
    def test_valid_record_passes(self) -> None:
        score.validate_record(_record(), _schema(), source="test.json")

    def test_missing_required_field_is_reported_by_name(self) -> None:
        record = _record()
        del record["challenge_id"]
        with pytest.raises(score.SchemaValidationError) as exc_info:
            score.validate_record(record, _schema(), source="bad.json")
        assert "bad.json" in str(exc_info.value)
        assert "challenge_id" in str(exc_info.value)

    def test_invalid_enum_value_is_reported(self) -> None:
        record = _record(difficulty="impossible")
        with pytest.raises(score.SchemaValidationError) as exc_info:
            score.validate_record(record, _schema(), source="bad.json")
        assert "difficulty" in str(exc_info.value)

    def test_wrong_type_is_reported(self) -> None:
        record = _record(solved="yes")
        with pytest.raises(score.SchemaValidationError) as exc_info:
            score.validate_record(record, _schema(), source="bad.json")
        assert "solved" in str(exc_info.value)

    def test_negative_number_below_minimum_is_reported(self) -> None:
        record = _record(duration_seconds=-1)
        with pytest.raises(score.SchemaValidationError) as exc_info:
            score.validate_record(record, _schema(), source="bad.json")
        assert "duration_seconds" in str(exc_info.value)

    def test_invalid_date_time_format_is_reported(self) -> None:
        record = _record(started_at="not-a-date")
        with pytest.raises(score.SchemaValidationError) as exc_info:
            score.validate_record(record, _schema(), source="bad.json")
        assert "started_at" in str(exc_info.value)

    def test_unexpected_field_is_reported(self) -> None:
        record = _record(unknown_field="oops")
        with pytest.raises(score.SchemaValidationError) as exc_info:
            score.validate_record(record, _schema(), source="bad.json")
        assert "unknown_field" in str(exc_info.value)

    def test_optional_notes_field_is_allowed(self) -> None:
        score.validate_record(_record(notes="all good"), _schema(), source="test.json")

    def test_non_object_record_is_rejected(self) -> None:
        with pytest.raises(score.SchemaValidationError):
            score.validate_record(["not", "an", "object"], _schema(), source="bad.json")


class TestLoadResults:
    def test_loads_valid_records(self, tmp_path: Path) -> None:
        (tmp_path / "a.json").write_text(json.dumps(_record(challenge_id="A")), encoding="utf-8")
        (tmp_path / "b.json").write_text(json.dumps(_record(challenge_id="B")), encoding="utf-8")
        records = score.load_results(tmp_path, _schema())
        assert {r["challenge_id"] for r in records} == {"A", "B"}

    def test_missing_directory_raises(self, tmp_path: Path) -> None:
        with pytest.raises(FileNotFoundError):
            score.load_results(tmp_path / "does-not-exist", _schema())

    def test_empty_directory_raises(self, tmp_path: Path) -> None:
        with pytest.raises(score.SchemaValidationError, match="no run-record"):
            score.load_results(tmp_path, _schema())

    def test_invalid_json_names_the_file(self, tmp_path: Path) -> None:
        (tmp_path / "broken.json").write_text("{not valid json", encoding="utf-8")
        with pytest.raises(score.SchemaValidationError, match=r"broken\.json"):
            score.load_results(tmp_path, _schema())

    def test_invalid_record_stops_loading_and_names_file(self, tmp_path: Path) -> None:
        (tmp_path / "good.json").write_text(json.dumps(_record()), encoding="utf-8")
        bad = _record()
        del bad["model"]
        (tmp_path / "bad.json").write_text(json.dumps(bad), encoding="utf-8")
        with pytest.raises(score.SchemaValidationError, match=r"bad\.json"):
            score.load_results(tmp_path, _schema())

    def test_fixture_results_directory_is_valid(self) -> None:
        # The committed example fixtures under benchmarks/xben/results/ must
        # themselves validate cleanly -- this is what score.py --help's
        # documented default invocation runs against.
        records = score.load_results(score._DEFAULT_RESULTS_DIR, _schema())
        assert len(records) >= 1


class TestAggregate:
    def test_overall_success_rate(self) -> None:
        records = [
            _record(challenge_id="1", difficulty="easy", solved=True),
            _record(challenge_id="2", difficulty="easy", solved=False),
        ]
        agg = score.aggregate(records)
        assert agg.total_challenges == 2
        assert agg.solved_challenges == 1
        assert agg.success_rate == pytest.approx(50.0)

    def test_breakdown_by_difficulty(self) -> None:
        records = [
            _record(challenge_id="1", difficulty="easy", solved=True),
            _record(challenge_id="2", difficulty="easy", solved=True),
            _record(challenge_id="3", difficulty="hard", solved=False),
        ]
        agg = score.aggregate(records)
        assert agg.by_difficulty["easy"].solved == 2
        assert agg.by_difficulty["easy"].total == 2
        assert agg.by_difficulty["hard"].solved == 0
        assert agg.by_difficulty["hard"].total == 1

    def test_average_duration_and_cost(self) -> None:
        records = [
            _record(challenge_id="1", duration_seconds=100, total_cost_usd=1.0),
            _record(challenge_id="2", duration_seconds=300, total_cost_usd=3.0),
        ]
        agg = score.aggregate(records)
        assert agg.avg_duration_seconds == pytest.approx(200.0)
        assert agg.total_cost_usd == pytest.approx(4.0)
        assert agg.avg_cost_usd == pytest.approx(2.0)

    def test_empty_aggregate_does_not_divide_by_zero(self) -> None:
        agg = score.aggregate([])
        assert agg.success_rate == 0.0
        assert agg.avg_duration_seconds == 0.0
        assert agg.avg_cost_usd == 0.0


class TestRenderMarkdown:
    def test_contains_expected_headers_and_rows(self) -> None:
        agg = score.aggregate(
            [
                _record(challenge_id="1", difficulty="easy", solved=True),
                _record(challenge_id="2", difficulty="hard", solved=False),
            ],
        )
        markdown = score.render_markdown(agg)
        assert "| Benchmark | Challenges | Success Rate |" in markdown
        assert "| Difficulty | Solved | Success Rate |" in markdown
        assert "Level 1 (Easy)" in markdown
        assert "Level 3 (Hard)" in markdown
        assert "Average solve time" in markdown
        assert "Total cost" in markdown


class TestReadmeCheck:
    _README_TEMPLATE = """\
## Results

| Benchmark | Challenges | Success Rate |
|-----------|------------|--------------|
| XBEN | {total} | **{rate:.0f}%** |

**Performance by Difficulty:**

| Difficulty | Solved | Success Rate |
|------------|--------|--------------|
| Level 1 (Easy) | {easy_solved}/{easy_total} | {easy_rate:.0f}% |
| Level 2 (Medium) | {medium_solved}/{medium_total} | {medium_rate:.0f}% |
| Level 3 (Hard) | {hard_solved}/{hard_total} | {hard_rate:.0f}% |
"""

    def _readme_matching(self, agg: score.AggregateResult) -> str:
        easy = agg.by_difficulty.get("easy", score.DifficultyStats())
        medium = agg.by_difficulty.get("medium", score.DifficultyStats())
        hard = agg.by_difficulty.get("hard", score.DifficultyStats())
        return self._README_TEMPLATE.format(
            total=agg.total_challenges,
            rate=agg.success_rate,
            easy_solved=easy.solved,
            easy_total=easy.total,
            easy_rate=easy.success_rate,
            medium_solved=medium.solved,
            medium_total=medium.total,
            medium_rate=medium.success_rate,
            hard_solved=hard.solved,
            hard_total=hard.total,
            hard_rate=hard.success_rate,
        )

    def test_matching_readme_has_no_mismatches(self) -> None:
        records = [
            _record(challenge_id="1", difficulty="easy", solved=True),
            _record(challenge_id="2", difficulty="medium", solved=True),
            _record(challenge_id="3", difficulty="hard", solved=False),
        ]
        agg = score.aggregate(records)
        readme_text = self._readme_matching(agg)
        claims = score.parse_readme_claims(readme_text)
        assert score.diff_against_claims(agg, claims) == []

    def test_mismatched_readme_is_reported(self) -> None:
        records = [_record(challenge_id="1", difficulty="easy", solved=True)]
        agg = score.aggregate(records)
        readme_text = self._readme_matching(agg)
        # Now aggregate a different set of records that disagrees.
        other_records = [
            _record(challenge_id="1", difficulty="easy", solved=True),
            _record(challenge_id="2", difficulty="easy", solved=False),
        ]
        other_agg = score.aggregate(other_records)
        claims = score.parse_readme_claims(readme_text)
        mismatches = score.diff_against_claims(other_agg, claims)
        assert mismatches
        assert any("total challenges" in m for m in mismatches)

    def test_real_readme_and_fixtures_are_out_of_sync(self) -> None:
        # This is the exact situation documented in benchmarks/xben/results/README.md:
        # the fixture data is synthetic and intentionally does not reproduce the
        # real README's headline claim, so --check against it must fail.
        agg = score.aggregate(score.load_results(score._DEFAULT_RESULTS_DIR, _schema()))
        readme_text = score._DEFAULT_README_PATH.read_text(encoding="utf-8")
        claims = score.parse_readme_claims(readme_text)
        assert score.diff_against_claims(agg, claims) != []


class TestCli:
    def test_main_prints_table_to_stdout(self, capsys: pytest.CaptureFixture[str]) -> None:
        exit_code = score.main([str(score._DEFAULT_RESULTS_DIR)])
        assert exit_code == 0
        captured = capsys.readouterr()
        assert "Benchmark" in captured.out

    def test_main_writes_table_to_out_file(self, tmp_path: Path) -> None:
        out_path = tmp_path / "table.md"
        exit_code = score.main([str(score._DEFAULT_RESULTS_DIR), "--out", str(out_path)])
        assert exit_code == 0
        assert "Benchmark" in out_path.read_text(encoding="utf-8")

    def test_main_check_fails_against_real_readme_with_fixture_data(self) -> None:
        exit_code = score.main([str(score._DEFAULT_RESULTS_DIR), "--check"])
        assert exit_code == 1

    def test_main_check_passes_with_matching_readme(self, tmp_path: Path) -> None:
        (tmp_path / "a.json").write_text(
            json.dumps(_record(challenge_id="A", difficulty="easy", solved=True)),
            encoding="utf-8",
        )
        agg = score.aggregate([_record(challenge_id="A", difficulty="easy", solved=True)])
        readme_path = tmp_path / "README.md"
        readme_path.write_text(TestReadmeCheck()._readme_matching(agg), encoding="utf-8")
        exit_code = score.main(
            [str(tmp_path), "--check", "--readme", str(readme_path)],
        )
        assert exit_code == 0

    def test_main_reports_invalid_record_and_exits_nonzero(
        self, tmp_path: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        bad = _record()
        del bad["run_id"]
        (tmp_path / "bad.json").write_text(json.dumps(bad), encoding="utf-8")
        exit_code = score.main([str(tmp_path)])
        assert exit_code == 1
        captured = capsys.readouterr()
        assert "bad.json" in captured.err
