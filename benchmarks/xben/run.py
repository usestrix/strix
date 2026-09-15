#!/usr/bin/env python3
"""Run the XBEN challenge suite against a real Strix install and emit run records.

This is the actual reproduction path for GitHub issues #1263 and #1264 on
usestrix/strix: given a checkout of the challenges from the external
``usestrix/benchmarks`` repository and a target model, this drives ``strix``
as a subprocess once per challenge and writes a conformant run-record JSON
(see ``benchmarks/xben/schema/run_record.schema.json``) for each one under
``benchmarks/xben/results/``.

Requires a live environment this repository's CI/dev sandbox does not have:
Docker (to run Strix's sandbox runtime) and a working LLM API key for the
selected model. Nothing in this module is exercised end-to-end without that
environment; the argument-parsing and record-construction logic is unit
tested with mocked subprocess calls (see ``tests/test_xben_run.py``), but
actually launching a challenge and getting a real flag match is not faked
here.

Challenge discovery
--------------------
The XBEN challenge set lives in the external ``usestrix/benchmarks``
repository, not in this one. This script does not know that repository's
exact on-disk layout, so it supports two ways to tell it about challenges:

1. ``--manifest PATH``: a JSON file you provide explicitly, shaped as a list
   of objects: ``{"challenge_id", "challenge_name", "difficulty", "target",
   "flag"}`` (``flag`` is optional; when omitted, ``flag_matched`` in the
   emitted record is always ``false`` and must be graded manually).
2. ``--challenges-dir PATH`` (no manifest): every immediate subdirectory of
   ``PATH`` containing a ``challenge.json`` file (with the same shape as one
   manifest entry, minus ``challenge_id`` which defaults to the directory
   name) is treated as one challenge. Adjust ``discover_challenges`` here if
   the real ``usestrix/benchmarks`` layout differs once you have it checked
   out.

Usage:
    python3 benchmarks/xben/run.py --manifest challenges.json \\
        --model anthropic/claude-sonnet-4-5 --mode black-box \\
        --out-dir benchmarks/xben/results
"""

from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
from dataclasses import dataclass
from datetime import UTC, datetime
from importlib.metadata import version
from pathlib import Path
from typing import Any

from rich.console import Console

from strix.core.paths import run_dir_for


console = Console()
error_console = Console(stderr=True)

_DEFAULT_OUT_DIR = Path(__file__).parent / "results"
_VALID_DIFFICULTIES = ("easy", "medium", "hard")
_VALID_MODES = ("black-box", "grey-box", "white-box")


class ChallengeSpecError(Exception):
    """A challenge manifest/directory entry is missing required fields."""


@dataclass
class ChallengeSpec:
    challenge_id: str
    challenge_name: str
    difficulty: str
    target: str
    flag: str | None = None


def _challenge_from_dict(
    data: dict[str, Any], *, default_id: str | None, source: str
) -> ChallengeSpec:
    challenge_id = str(data.get("challenge_id") or default_id or "")
    if not challenge_id:
        raise ChallengeSpecError(f"{source}: missing 'challenge_id'")

    difficulty = str(data.get("difficulty", ""))
    if difficulty not in _VALID_DIFFICULTIES:
        raise ChallengeSpecError(
            f"{source}: 'difficulty' must be one of {_VALID_DIFFICULTIES}, got {difficulty!r}",
        )

    target = data.get("target")
    if not target or not isinstance(target, str):
        raise ChallengeSpecError(f"{source}: missing or invalid 'target'")

    flag = data.get("flag")
    return ChallengeSpec(
        challenge_id=challenge_id,
        challenge_name=str(data.get("challenge_name") or challenge_id),
        difficulty=difficulty,
        target=target,
        flag=str(flag) if flag else None,
    )


def load_manifest(manifest_path: Path) -> list[ChallengeSpec]:
    raw: Any = json.loads(manifest_path.read_text(encoding="utf-8"))
    if not isinstance(raw, list):
        raise ChallengeSpecError(f"{manifest_path}: manifest must be a JSON array")
    return [
        _challenge_from_dict(entry, default_id=None, source=f"{manifest_path}[{i}]")
        for i, entry in enumerate(raw)
        if isinstance(entry, dict)
    ]


def discover_challenges(challenges_dir: Path) -> list[ChallengeSpec]:
    """Discover challenges from ``<challenges_dir>/<name>/challenge.json`` entries.

    This assumes each challenge has a ``challenge.json`` describing its target
    and difficulty. Adjust this function once the real usestrix/benchmarks
    XBEN layout is available to run against — this repository was built
    without network access to check it out.
    """
    if not challenges_dir.is_dir():
        raise FileNotFoundError(f"challenges directory not found: {challenges_dir}")

    specs: list[ChallengeSpec] = []
    for child in sorted(challenges_dir.iterdir()):
        manifest_file = child / "challenge.json"
        if not child.is_dir() or not manifest_file.is_file():
            continue
        raw: Any = json.loads(manifest_file.read_text(encoding="utf-8"))
        if not isinstance(raw, dict):
            raise ChallengeSpecError(f"{manifest_file}: must be a JSON object")
        specs.append(_challenge_from_dict(raw, default_id=child.name, source=str(manifest_file)))

    if not specs:
        raise ChallengeSpecError(
            f"no challenge.json files found under {challenges_dir} "
            "(pass --manifest instead if the challenge set uses a different layout)",
        )
    return specs


def build_strix_command(
    *,
    strix_bin: str,
    target: str,
    run_name: str,
    max_budget_usd: float | None,
    max_turns: int | None,
) -> list[str]:
    """Build the ``strix`` CLI invocation for one challenge run.

    Mirrors the flags documented in ``strix/interface/cli_args.py``:
    ``--target``/``-t``, ``--non-interactive``/``-n`` (required for a
    subprocess run — the interactive TUI would hang), and the optional
    ``--max-budget`` / ``--max-turns`` guards so a single stuck challenge
    can't burn the whole benchmark's budget.
    """
    command = [
        strix_bin,
        "--target",
        target,
        "--non-interactive",
        "--run-name",
        run_name,
    ]
    if max_budget_usd is not None:
        command += ["--max-budget", str(max_budget_usd)]
    if max_turns is not None:
        command += ["--max-turns", str(max_turns)]
    return command


def run_strix_subprocess(
    command: list[str], *, env: dict[str, str]
) -> subprocess.CompletedProcess[str]:
    """Invoke the ``strix`` CLI as a subprocess and capture its output.

    Requires Docker and a working LLM API key in ``env`` — this is the part
    of the pipeline that cannot be exercised in a sandbox without either.
    """
    return subprocess.run(  # noqa: S603
        command,
        env=env,
        capture_output=True,
        text=True,
        check=False,
    )


def read_run_json(run_dir: Path) -> dict[str, Any]:
    run_json_path = run_dir / "run.json"
    if not run_json_path.is_file():
        raise FileNotFoundError(f"no run.json produced under {run_dir}")
    data: Any = json.loads(run_json_path.read_text(encoding="utf-8"))
    if not isinstance(data, dict):
        raise TypeError(f"{run_json_path} is not a JSON object")
    return data


def flag_was_matched(run_dir: Path, flag: str | None) -> bool:
    """Best-effort check for the challenge flag in the run's saved artifacts.

    Searches ``vulnerabilities.json`` and the executive report markdown for
    the literal flag string. A real grading pass may want something more
    precise (e.g. the agent's own "finish" tool call payload); this is
    intentionally simple and documented as best-effort.
    """
    if not flag:
        return False
    candidates = [run_dir / "vulnerabilities.json", run_dir / "penetration_test_report.md"]
    return any(path.is_file() and flag in path.read_text(encoding="utf-8") for path in candidates)


def get_strix_version() -> str:
    try:
        return version("strix-agent")
    except Exception:  # noqa: BLE001
        return "unknown"


def build_run_record(
    *,
    challenge: ChallengeSpec,
    run_dir: Path,
    run_id: str,
    model: str,
    mode: str,
    started_at: datetime,
    finished_at: datetime,
) -> dict[str, Any]:
    """Construct a schema-conformant run record from a completed run's artifacts."""
    run_json = read_run_json(run_dir)
    llm_usage = run_json.get("llm_usage") or {}
    status = run_json.get("status")

    matched = flag_was_matched(run_dir, challenge.flag)
    solved = matched if challenge.flag else status == "completed"

    return {
        "challenge_id": challenge.challenge_id,
        "challenge_name": challenge.challenge_name,
        "difficulty": challenge.difficulty,
        "strix_version": get_strix_version(),
        "model": model,
        "mode": mode,
        "solved": bool(solved),
        "flag_matched": bool(matched),
        "duration_seconds": (finished_at - started_at).total_seconds(),
        "total_cost_usd": float(llm_usage.get("cost") or 0.0),
        "input_tokens": int(llm_usage.get("input_tokens") or 0),
        "output_tokens": int(llm_usage.get("output_tokens") or 0),
        "started_at": started_at.isoformat(),
        "finished_at": finished_at.isoformat(),
        "run_id": run_id,
    }


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    source = parser.add_mutually_exclusive_group(required=True)
    source.add_argument(
        "--manifest",
        type=Path,
        help="JSON file listing challenges explicitly (see module docstring for shape).",
    )
    source.add_argument(
        "--challenges-dir",
        type=Path,
        help="Directory of <challenge>/challenge.json entries (see module docstring).",
    )
    parser.add_argument(
        "--model",
        required=True,
        help="LLM identifier to run with, passed through as the STRIX_LLM env var "
        "(litellm-style, e.g. 'anthropic/claude-sonnet-4-5').",
    )
    parser.add_argument(
        "--mode",
        choices=_VALID_MODES,
        default="black-box",
        help="Testing mode recorded in the run record (default: black-box).",
    )
    parser.add_argument(
        "--out-dir",
        type=Path,
        default=_DEFAULT_OUT_DIR,
        help=f"Directory to write run-record JSON files to (default: {_DEFAULT_OUT_DIR}).",
    )
    parser.add_argument(
        "--strix-bin",
        default="strix",
        help="Path to the strix executable to invoke (default: 'strix' on PATH).",
    )
    parser.add_argument(
        "--max-budget",
        type=float,
        default=None,
        help="Per-challenge --max-budget passed through to strix, in USD.",
    )
    parser.add_argument(
        "--max-turns",
        type=int,
        default=None,
        help="Per-challenge --max-turns passed through to strix.",
    )
    parser.add_argument(
        "--challenge-id",
        action="append",
        dest="challenge_ids",
        default=None,
        help="Only run this challenge id (repeatable). Default: run every discovered challenge.",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Print the strix commands that would run, without executing them.",
    )
    return parser


def _select_challenges(
    challenges: list[ChallengeSpec], challenge_ids: list[str] | None
) -> list[ChallengeSpec]:
    if not challenge_ids:
        return challenges
    wanted = set(challenge_ids)
    selected = [c for c in challenges if c.challenge_id in wanted]
    missing = wanted - {c.challenge_id for c in selected}
    if missing:
        raise ChallengeSpecError(f"unknown --challenge-id value(s): {sorted(missing)}")
    return selected


def run_one_challenge(
    challenge: ChallengeSpec,
    *,
    args: argparse.Namespace,
    env: dict[str, str],
    run_dir_for_name: Any,
) -> dict[str, Any]:
    """Run a single challenge end-to-end and return its run record."""
    run_name = f"xben-{challenge.challenge_id}-{int(datetime.now(tz=UTC).timestamp())}"
    command = build_strix_command(
        strix_bin=args.strix_bin,
        target=challenge.target,
        run_name=run_name,
        max_budget_usd=args.max_budget,
        max_turns=args.max_turns,
    )

    started_at = datetime.now(tz=UTC)
    result = run_strix_subprocess(command, env=env)
    finished_at = datetime.now(tz=UTC)

    if result.returncode != 0:
        error_console.print(
            f"[bold red]strix exited {result.returncode} for {challenge.challenge_id}[/bold red]",
        )
        error_console.print(result.stderr)

    run_dir = run_dir_for_name(run_name)
    return build_run_record(
        challenge=challenge,
        run_dir=run_dir,
        run_id=run_name,
        model=args.model,
        mode=args.mode,
        started_at=started_at,
        finished_at=finished_at,
    )


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)

    try:
        challenges = (
            load_manifest(args.manifest)
            if args.manifest
            else discover_challenges(args.challenges_dir)
        )
        challenges = _select_challenges(challenges, args.challenge_ids)
    except (ChallengeSpecError, FileNotFoundError, json.JSONDecodeError) as exc:
        error_console.print(f"[bold red]error:[/bold red] {exc}")
        return 1

    if args.dry_run:
        for challenge in challenges:
            command = build_strix_command(
                strix_bin=args.strix_bin,
                target=challenge.target,
                run_name=f"xben-{challenge.challenge_id}-<timestamp>",
                max_budget_usd=args.max_budget,
                max_turns=args.max_turns,
            )
            console.print(f"[{challenge.challenge_id}] {' '.join(command)}")
        return 0

    env = dict(os.environ)
    env["STRIX_LLM"] = args.model

    args.out_dir.mkdir(parents=True, exist_ok=True)
    exit_code = 0
    for challenge in challenges:
        try:
            record = run_one_challenge(
                challenge,
                args=args,
                env=env,
                run_dir_for_name=run_dir_for,
            )
        except (FileNotFoundError, TypeError) as exc:
            error_console.print(f"[bold red]{challenge.challenge_id} failed:[/bold red] {exc}")
            exit_code = 1
            continue

        out_path = args.out_dir / f"{challenge.challenge_id}.{args.model.replace('/', '_')}.json"
        out_path.write_text(json.dumps(record, indent=2) + "\n", encoding="utf-8")
        console.print(f"[green]wrote[/green] {out_path}")

    return exit_code


if __name__ == "__main__":
    sys.exit(main())
