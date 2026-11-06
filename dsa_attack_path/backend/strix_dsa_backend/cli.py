"""CLI entry for post-run attack-path analysis."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from .analyze_run import AnalyzeOptions, analyze_run_dir
from .paths_util import resolve_run_dir


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="strix-dsa-backend",
        description=(
            "Analyze a Strix run directory into modeled attack-path artifacts "
            "under strix_runs/<run>/attack_path/. Simulated lateral is OFF by default."
        ),
    )
    parser.add_argument(
        "run",
        help="Run name under ./strix_runs/ or path to a run directory",
    )
    parser.add_argument(
        "--cwd",
        default=".",
        help="Working directory that contains strix_runs/ (default: .)",
    )
    parser.add_argument(
        "--engine",
        help="Path to strix_dsa_cli (else auto-detect / STRIX_DSA_ENGINE)",
    )
    parser.add_argument("--start", type=int)
    parser.add_argument("--target", type=int)
    parser.add_argument("--max-depth", type=int)
    parser.add_argument("--max-paths", type=int)
    parser.add_argument(
        "--allow-simulated-lateral",
        action="store_true",
        help="Opt-in: add labeled simulated lateral edges (OFF by default)",
    )
    parser.add_argument(
        "--no-simulated-entry",
        action="store_true",
        help="Do not add the simulated external-attacker entry node",
    )
    parser.add_argument(
        "--skip-engine",
        action="store_true",
        help="Only emit graph artifacts; do not invoke the C++ engine",
    )
    parser.add_argument(
        "--json",
        action="store_true",
        help="Print meta.json summary to stdout",
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        run_dir = resolve_run_dir(args.run, cwd=Path(args.cwd))
    except FileNotFoundError as exc:
        print(str(exc), file=sys.stderr)
        return 2

    options = AnalyzeOptions(
        allow_simulated_entry=not args.no_simulated_entry,
        allow_simulated_lateral=bool(args.allow_simulated_lateral),
        run_engine=not args.skip_engine,
        engine_path=Path(args.engine) if args.engine else None,
        start=args.start,
        target=args.target,
        max_depth=args.max_depth,
        max_paths=args.max_paths,
    )
    try:
        meta = analyze_run_dir(run_dir, options)
    except Exception as exc:  # noqa: BLE001 — CLI boundary
        print(f"attack-path analysis failed: {exc}", file=sys.stderr)
        return 1

    if args.json:
        print(json.dumps(meta, indent=2))
    else:
        arts = meta["artifacts"]
        print("MODELED attack-path artifacts written (not confirmed multi-hop exploits):")
        print(f"  graph:    {arts['attack_graph_json']}")
        print(f"  topology: {arts['topology_txt']}")
        print(f"  analysis: {arts['analysis_txt']}")
        print(f"  meta:     {arts['meta_json']}")
        print(
            f"  simulated_lateral={meta['product_defaults']['allow_simulated_lateral']} "
            f"engine_invoked={meta['engine']['invoked']}"
        )
        if meta["engine"].get("skipped_reason"):
            print(f"  note: {meta['engine']['skipped_reason']}")
    return 0 if (not meta["engine"]["invoked"] or meta["engine"]["returncode"] == 0) else 1


if __name__ == "__main__":
    raise SystemExit(main())
