#!/usr/bin/env python3
"""Aggregate and score committed XBEN run records.

Reads a directory of run-record JSON files (see
``benchmarks/xben/schema/run_record.schema.json``), validates each one, and
computes the same headline numbers hand-typed into ``benchmarks/README.md``:
overall success rate, a breakdown by difficulty, average solve time, and
total/average cost.

This is the "reproducible from committed data" half of closing out GitHub
issues #1263 ("Make published XBEN metrics reproducible from committed
data") and #1264 ("Record enough provenance to reproduce XBEN runs") on
usestrix/strix: instead of a hand-typed table with no backing data, the
table is regenerated mechanically from JSON files committed under
``benchmarks/xben/results/``.

Usage:
    python3 benchmarks/xben/score.py [RESULTS_DIR] [--out PATH] [--check]

See ``benchmarks/xben/README.md`` for the full walkthrough.
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Any

from rich.console import Console


_DEFAULT_RESULTS_DIR = Path(__file__).parent / "results"
_DEFAULT_SCHEMA_PATH = Path(__file__).parent / "schema" / "run_record.schema.json"
_DEFAULT_README_PATH = Path(__file__).parent.parent / "README.md"

_DIFFICULTY_LABELS: dict[str, str] = {
    "easy": "Level 1 (Easy)",
    "medium": "Level 2 (Medium)",
    "hard": "Level 3 (Hard)",
}
_DIFFICULTY_ORDER: tuple[str, ...] = ("easy", "medium", "hard")

console = Console()
error_console = Console(stderr=True)


class SchemaValidationError(Exception):
    """A run-record JSON file failed validation against the XBEN schema."""


# ---------------------------------------------------------------------------
# Minimal JSON Schema validation.
#
# ``jsonschema`` is not a declared dependency of strix-agent (it only ever
# shows up transitively via other packages' requirements), so rather than
# depend on an undeclared package we implement just the subset of JSON
# Schema (Draft 2020-12) that benchmarks/xben/schema/run_record.schema.json
# actually uses: object/type/required/properties/additionalProperties,
# enum, minimum, and the "date-time" format.
# ---------------------------------------------------------------------------

_TYPE_MAP: dict[str, tuple[type, ...]] = {
    "object": (dict,),
    "string": (str,),
    "boolean": (bool,),
    "number": (int, float),
    "integer": (int,),
}


def _check_type(value: Any, expected: str, path: str, errors: list[str]) -> None:
    python_types = _TYPE_MAP.get(expected)
    if python_types is None:
        return
    # bool is a subclass of int in Python; JSON Schema treats them as distinct.
    if expected in {"number", "integer"} and isinstance(value, bool):
        errors.append(f"{path}: expected {expected}, got boolean")
        return
    if not isinstance(value, python_types):
        errors.append(f"{path}: expected {expected}, got {type(value).__name__}")


def _check_format(value: str, fmt: str, path: str, errors: list[str]) -> None:
    if fmt != "date-time":
        return
    try:
        datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        errors.append(f"{path}: '{value}' is not a valid ISO 8601 date-time")


def _validate_property(
    value: Any, prop_schema: dict[str, Any], path: str, errors: list[str]
) -> None:
    expected_type = prop_schema.get("type")
    if isinstance(expected_type, str):
        _check_type(value, expected_type, path, errors)

    enum = prop_schema.get("enum")
    if enum is not None and value not in enum:
        errors.append(f"{path}: {value!r} is not one of {enum!r}")

    minimum = prop_schema.get("minimum")
    if minimum is not None and isinstance(value, int | float) and value < minimum:
        errors.append(f"{path}: {value} is less than the minimum {minimum}")

    min_length = prop_schema.get("minLength")
    if min_length is not None and isinstance(value, str) and len(value) < min_length:
        errors.append(f"{path}: string is shorter than minLength {min_length}")

    fmt = prop_schema.get("format")
    if fmt is not None and isinstance(value, str):
        _check_format(value, fmt, path, errors)


def validate_record(record: Any, schema: dict[str, Any], *, source: str) -> None:
    """Validate ``record`` against ``schema``, raising with file+field context on failure."""
    errors: list[str] = []

    if not isinstance(record, dict):
        raise SchemaValidationError(f"{source}: top-level value must be a JSON object")

    required = schema.get("required", [])
    errors.extend(
        f"missing required field '{field_name}'"
        for field_name in required
        if field_name not in record
    )

    properties: dict[str, Any] = schema.get("properties", {})
    for key, value in record.items():
        if key not in properties:
            if schema.get("additionalProperties") is False:
                errors.append(f"unexpected field '{key}' (not in schema)")
            continue
        _validate_property(value, properties[key], key, errors)

    if errors:
        formatted = "; ".join(errors)
        raise SchemaValidationError(f"{source}: {formatted}")


# ---------------------------------------------------------------------------
# Loading and aggregation.
# ---------------------------------------------------------------------------


def load_schema(schema_path: Path) -> dict[str, Any]:
    data: Any = json.loads(schema_path.read_text(encoding="utf-8"))
    if not isinstance(data, dict):
        raise SchemaValidationError(f"{schema_path}: schema file is not a JSON object")
    return data


def load_results(results_dir: Path, schema: dict[str, Any]) -> list[dict[str, Any]]:
    """Load and validate every ``*.json`` run record under ``results_dir``.

    Raises ``SchemaValidationError`` naming the offending file and field on the
    first invalid record — validation failures are meant to be loud, not
    silently skipped.
    """
    if not results_dir.is_dir():
        raise FileNotFoundError(f"results directory not found: {results_dir}")

    records: list[dict[str, Any]] = []
    for path in sorted(results_dir.glob("*.json")):
        try:
            raw: Any = json.loads(path.read_text(encoding="utf-8"))
        except json.JSONDecodeError as exc:
            raise SchemaValidationError(f"{path.name}: invalid JSON ({exc})") from exc
        validate_record(raw, schema, source=path.name)
        records.append(raw)

    if not records:
        raise SchemaValidationError(f"no run-record *.json files found under {results_dir}")

    return records


@dataclass
class DifficultyStats:
    solved: int = 0
    total: int = 0

    @property
    def success_rate(self) -> float:
        return (self.solved / self.total * 100) if self.total else 0.0


@dataclass
class AggregateResult:
    total_challenges: int = 0
    solved_challenges: int = 0
    total_duration_seconds: float = 0.0
    total_cost_usd: float = 0.0
    by_difficulty: dict[str, DifficultyStats] = field(default_factory=dict)

    @property
    def success_rate(self) -> float:
        return (
            (self.solved_challenges / self.total_challenges * 100) if self.total_challenges else 0.0
        )

    @property
    def avg_duration_seconds(self) -> float:
        return self.total_duration_seconds / self.total_challenges if self.total_challenges else 0.0

    @property
    def avg_cost_usd(self) -> float:
        return self.total_cost_usd / self.total_challenges if self.total_challenges else 0.0


def aggregate(records: list[dict[str, Any]]) -> AggregateResult:
    result = AggregateResult()
    for record in records:
        result.total_challenges += 1
        solved = bool(record["solved"])
        if solved:
            result.solved_challenges += 1
        result.total_duration_seconds += float(record["duration_seconds"])
        result.total_cost_usd += float(record["total_cost_usd"])

        difficulty = str(record["difficulty"])
        stats = result.by_difficulty.setdefault(difficulty, DifficultyStats())
        stats.total += 1
        if solved:
            stats.solved += 1

    return result


# ---------------------------------------------------------------------------
# Markdown rendering, matching the shape of the existing benchmarks/README.md
# tables so that file's tables can be replaced wholesale by this output.
# ---------------------------------------------------------------------------


def _format_minutes(seconds: float) -> str:
    return f"~{round(seconds / 60)} minutes"


def _format_cost(usd: float) -> str:
    return f"~${usd:,.0f}"


def render_markdown(agg: AggregateResult) -> str:
    lines: list[str] = []
    lines.append("| Benchmark | Challenges | Success Rate |")
    lines.append("|-----------|------------|--------------|")
    lines.append(
        f"| XBEN | {agg.total_challenges} | **{agg.success_rate:.0f}%** |",
    )
    lines.append("")
    lines.append("**Performance by Difficulty:**")
    lines.append("")
    lines.append("| Difficulty | Solved | Success Rate |")
    lines.append("|------------|--------|--------------|")
    for key in _DIFFICULTY_ORDER:
        stats = agg.by_difficulty.get(key)
        if stats is None:
            continue
        label = _DIFFICULTY_LABELS[key]
        lines.append(f"| {label} | {stats.solved}/{stats.total} | {stats.success_rate:.0f}% |")
    lines.append("")
    lines.append("**Resource Usage:**")
    lines.append(f"- Average solve time: {_format_minutes(agg.avg_duration_seconds)}")
    lines.append(
        f"- Total cost: {_format_cost(agg.total_cost_usd)} for {agg.total_challenges} challenges",
    )
    return "\n".join(lines) + "\n"


# ---------------------------------------------------------------------------
# --check: parse the numbers currently hand-typed in benchmarks/README.md and
# compare them against what's computed from committed data.
# ---------------------------------------------------------------------------


@dataclass
class ReadmeClaims:
    total_challenges: int
    success_rate: float
    by_difficulty: dict[str, DifficultyStats]


_OVERALL_ROW_RE = re.compile(
    r"\|\s*\[?XBEN\]?[^|]*\|\s*(\d+)\s*\|\s*\*\*(\d+(?:\.\d+)?)%\*\*\s*\|",
)
_DIFFICULTY_ROW_RE = re.compile(
    r"\|\s*Level\s+(\d+)\s*\(([A-Za-z]+)\)\s*\|\s*(\d+)/(\d+)\s*\|\s*(\d+(?:\.\d+)?)%\s*\|",
)


def parse_readme_claims(readme_text: str) -> ReadmeClaims:
    """Extract the headline numbers from the existing hand-typed README table."""
    overall_match = _OVERALL_ROW_RE.search(readme_text)
    if not overall_match:
        raise SchemaValidationError(
            "could not find the XBEN results row (e.g. '| XBEN | 104 | **96%** |') in the README",
        )
    total_challenges = int(overall_match.group(1))
    success_rate = float(overall_match.group(2))

    by_difficulty: dict[str, DifficultyStats] = {}
    for match in _DIFFICULTY_ROW_RE.finditer(readme_text):
        level_name = match.group(2).lower()
        difficulty = next((d for d in _DIFFICULTY_ORDER if d == level_name), None)
        if difficulty is None:
            continue
        solved, total = int(match.group(3)), int(match.group(4))
        by_difficulty[difficulty] = DifficultyStats(solved=solved, total=total)

    return ReadmeClaims(
        total_challenges=total_challenges,
        success_rate=success_rate,
        by_difficulty=by_difficulty,
    )


def diff_against_claims(agg: AggregateResult, claims: ReadmeClaims) -> list[str]:
    """Return a list of human-readable mismatches between ``agg`` and ``claims``."""
    mismatches: list[str] = []

    if agg.total_challenges != claims.total_challenges:
        mismatches.append(
            f"total challenges: README claims {claims.total_challenges}, "
            f"committed data has {agg.total_challenges}",
        )
    if round(agg.success_rate) != round(claims.success_rate):
        mismatches.append(
            f"overall success rate: README claims {claims.success_rate:.0f}%, "
            f"committed data computes {agg.success_rate:.0f}%",
        )

    for difficulty in _DIFFICULTY_ORDER:
        # A difficulty absent from either side is equivalent to a zero-challenge
        # DifficultyStats(0, 0) for that side, so a table row with "0/0" and no
        # committed challenges of that difficulty compare as equal rather than
        # as "present on one side only".
        claimed = claims.by_difficulty.get(difficulty, DifficultyStats())
        actual = agg.by_difficulty.get(difficulty, DifficultyStats())
        if claimed.solved != actual.solved or claimed.total != actual.total:
            mismatches.append(
                f"difficulty '{difficulty}': README claims {claimed.solved}/{claimed.total}, "
                f"committed data has {actual.solved}/{actual.total}",
            )

    return mismatches


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description=(
            "Validate and aggregate committed XBEN run records into the "
            "benchmarks/README.md results table."
        ),
    )
    parser.add_argument(
        "results_dir",
        type=Path,
        nargs="?",
        default=_DEFAULT_RESULTS_DIR,
        help=f"Directory of run-record *.json files (default: {_DEFAULT_RESULTS_DIR}).",
    )
    parser.add_argument(
        "--schema",
        type=Path,
        default=_DEFAULT_SCHEMA_PATH,
        help=f"Path to the run-record JSON Schema (default: {_DEFAULT_SCHEMA_PATH}).",
    )
    parser.add_argument(
        "--out",
        type=Path,
        default=None,
        help="Write the markdown table to this file instead of stdout.",
    )
    parser.add_argument(
        "--check",
        action="store_true",
        help=(
            "Exit non-zero if the aggregated numbers don't match what's currently "
            "hand-typed in the README (this is what CI runs)."
        ),
    )
    parser.add_argument(
        "--readme",
        type=Path,
        default=_DEFAULT_README_PATH,
        help=f"README to check against with --check (default: {_DEFAULT_README_PATH}).",
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)

    try:
        schema = load_schema(args.schema)
        records = load_results(args.results_dir, schema)
    except (SchemaValidationError, FileNotFoundError) as exc:
        error_console.print(f"[bold red]error:[/bold red] {exc}")
        return 1

    agg = aggregate(records)
    markdown = render_markdown(agg)

    if args.out:
        args.out.write_text(markdown, encoding="utf-8")
        console.print(f"Wrote markdown table to {args.out}")
    else:
        console.print(markdown, highlight=False, soft_wrap=True)

    if args.check:
        if not args.readme.is_file():
            error_console.print(f"[bold red]error:[/bold red] README not found: {args.readme}")
            return 1
        readme_text = args.readme.read_text(encoding="utf-8")
        try:
            claims = parse_readme_claims(readme_text)
        except SchemaValidationError as exc:
            error_console.print(f"[bold red]error:[/bold red] {exc}")
            return 1

        mismatches = diff_against_claims(agg, claims)
        if mismatches:
            error_console.print(
                f"[bold red]--check failed:[/bold red] aggregated numbers from "
                f"{args.results_dir} do not match {args.readme}:",
            )
            for mismatch in mismatches:
                error_console.print(f"  - {mismatch}")
            return 1
        console.print(
            f"[bold green]--check passed:[/bold green] {args.readme} matches committed data."
        )

    return 0


if __name__ == "__main__":
    sys.exit(main())
