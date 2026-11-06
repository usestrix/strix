"""CLI: convert Strix finding artifacts → DSA graph; optional engine demo."""

from __future__ import annotations

import argparse
import json
import subprocess
import sys
from pathlib import Path

from .emit import emit_graph_json, emit_topology_txt, load_findings_file, load_run_record
from .mapper import BridgeOptions, build_attack_graph


def _default_engine() -> Path | None:
    here = Path(__file__).resolve().parents[2]  # dsa_attack_path/
    candidates = [
        here / "build" / "strix_dsa_cli.exe",
        here / "build" / "strix_dsa_cli",
    ]
    for path in candidates:
        if path.exists():
            return path
    return None


def cmd_convert(args: argparse.Namespace) -> int:
    findings = load_findings_file(Path(args.findings))
    run_record = load_run_record(Path(args.run_json) if args.run_json else None)
    options = BridgeOptions(
        allow_simulated_entry=not args.no_simulated_entry,
        allow_simulated_lateral=args.allow_simulated_lateral,
        mark_highest_severity_as_crown=not args.no_crown,
    )
    graph = build_attack_graph(findings, run_record=run_record, options=options)

    out_dir = Path(args.output)
    out_dir.mkdir(parents=True, exist_ok=True)
    json_path = emit_graph_json(graph, out_dir / "attack_graph.json")
    txt_path = emit_topology_txt(graph, out_dir / "topology.txt")

    summary = {
        "disclaimer": graph["disclaimer"],
        "counts": graph["counts"],
        "analysis_defaults": graph["analysis_defaults"],
        "warnings": graph["warnings"],
        "outputs": {"json": str(json_path), "topology": str(txt_path)},
    }
    print(json.dumps(summary, indent=2))
    return 0


def cmd_analyze(args: argparse.Namespace) -> int:
    # Convert first into a temp/output dir, then invoke C++ CLI.
    convert_ns = argparse.Namespace(
        findings=args.findings,
        run_json=args.run_json,
        output=args.output,
        no_simulated_entry=args.no_simulated_entry,
        allow_simulated_lateral=args.allow_simulated_lateral,
        no_crown=args.no_crown,
    )
    rc = cmd_convert(convert_ns)
    if rc != 0:
        return rc

    out_dir = Path(args.output)
    graph = json.loads((out_dir / "attack_graph.json").read_text(encoding="utf-8"))
    start = args.start or graph.get("analysis_defaults", {}).get("start")
    target = args.target or graph.get("analysis_defaults", {}).get("target")
    if start is None or target is None:
        print("No start/target available for analysis.", file=sys.stderr)
        return 1

    engine = Path(args.engine) if args.engine else _default_engine()
    if engine is None or not engine.exists():
        print(
            "C++ engine not found. Build dsa_attack_path first or pass --engine.",
            file=sys.stderr,
        )
        return 1

    topology = out_dir / "topology.txt"
    cmd = [str(engine), str(topology), str(start), str(target)]
    if args.max_depth is not None:
        cmd.append(str(args.max_depth))
    if args.max_paths is not None:
        cmd.append(str(args.max_paths))

    print(
        "\n=== Invoking C++ DSA engine on MODELED topology "
        "(not real pentest multi-hop proof) ===\n",
        file=sys.stderr,
    )
    completed = subprocess.run(cmd, check=False)
    return completed.returncode


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="strix-dsa-bridge",
        description=(
            "Bridge Strix vulnerabilities.json into a labeled DSA attack graph. "
            "Simulated scaffolding is always labeled and is never real pentest proof."
        ),
    )
    sub = parser.add_subparsers(dest="command", required=True)

    convert = sub.add_parser("convert", help="Emit attack_graph.json + topology.txt")
    convert.add_argument("findings", help="Path to vulnerabilities.json (or list fixture)")
    convert.add_argument("--run-json", help="Optional run.json for targets_info")
    convert.add_argument("-o", "--output", default="bridge_out", help="Output directory")
    convert.add_argument(
        "--no-simulated-entry",
        action="store_true",
        help="Do not add the simulated external-attacker entry node",
    )
    convert.add_argument(
        "--allow-simulated-lateral",
        action="store_true",
        help="Add labeled simulated lateral edges between finding hosts",
    )
    convert.add_argument(
        "--no-crown",
        action="store_true",
        help="Do not auto-mark the highest-impact node as crown jewel",
    )
    convert.set_defaults(func=cmd_convert)

    analyze = sub.add_parser(
        "analyze",
        help="Convert then run the Phase-1 C++ CLI on the modeled topology",
    )
    analyze.add_argument("findings", help="Path to vulnerabilities.json")
    analyze.add_argument("--run-json", help="Optional run.json")
    analyze.add_argument("-o", "--output", default="bridge_out")
    analyze.add_argument("--engine", help="Path to strix_dsa_cli executable")
    analyze.add_argument("--start", type=int, help="Override start node id")
    analyze.add_argument("--target", type=int, help="Override target node id")
    analyze.add_argument("--max-depth", type=int)
    analyze.add_argument("--max-paths", type=int)
    analyze.add_argument("--no-simulated-entry", action="store_true")
    analyze.add_argument("--allow-simulated-lateral", action="store_true")
    analyze.add_argument("--no-crown", action="store_true")
    analyze.set_defaults(func=cmd_analyze)

    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    return int(args.func(args))


if __name__ == "__main__":
    raise SystemExit(main())
