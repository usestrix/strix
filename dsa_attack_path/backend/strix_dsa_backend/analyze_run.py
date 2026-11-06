"""Run bridge + optional C++ engine against a Strix run directory."""

from __future__ import annotations

import json
import os
import subprocess
import sys
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any


from .paths_util import attack_path_dir


def _ensure_bridge_on_path() -> None:
    bridge_root = Path(__file__).resolve().parents[2] / "bridge"
    bridge_str = str(bridge_root)
    if bridge_str not in sys.path:
        sys.path.insert(0, bridge_str)


def _default_engine() -> Path | None:
    root = Path(__file__).resolve().parents[2]  # dsa_attack_path/
    for name in ("strix_dsa_cli.exe", "strix_dsa_cli"):
        candidate = root / "build" / name
        if candidate.exists():
            return candidate
    env = os.environ.get("STRIX_DSA_ENGINE")
    if env:
        path = Path(env)
        if path.exists():
            return path
    return None


@dataclass
class AnalyzeOptions:
    """Product defaults: simulated lateral OFF."""

    allow_simulated_entry: bool = True
    allow_simulated_lateral: bool = False  # hard default for product entrypoints
    mark_highest_severity_as_crown: bool = True
    run_engine: bool = True
    engine_path: Path | None = None
    start: int | None = None
    target: int | None = None
    max_depth: int | None = None
    max_paths: int | None = None


def _load_json(path: Path, default: Any) -> Any:
    if not path.exists():
        return default
    return json.loads(path.read_text(encoding="utf-8"))


def analyze_run_dir(run_dir: Path, options: AnalyzeOptions | None = None) -> dict[str, Any]:
    """Build attack-path artifacts under ``<run_dir>/attack_path/``.

    Reads ``vulnerabilities.json`` and optional ``run.json``. Does not mutate
    Strix agent state. All outputs are labeled modeled analysis.
    """
    opts = options or AnalyzeOptions()
    run_dir = run_dir.resolve()
    vulns_path = run_dir / "vulnerabilities.json"
    if not vulns_path.exists():
        raise FileNotFoundError(f"Missing {vulns_path}")

    _ensure_bridge_on_path()
    from strix_dsa_bridge.emit import emit_graph_json, emit_topology_txt, load_findings_file
    from strix_dsa_bridge.mapper import BridgeOptions, build_attack_graph

    findings = load_findings_file(vulns_path)
    run_record = _load_json(run_dir / "run.json", {})
    if not isinstance(run_record, dict):
        run_record = {}

    bridge_opts = BridgeOptions(
        allow_simulated_entry=opts.allow_simulated_entry,
        allow_simulated_lateral=opts.allow_simulated_lateral,
        mark_highest_severity_as_crown=opts.mark_highest_severity_as_crown,
    )
    graph = build_attack_graph(findings, run_record=run_record, options=bridge_opts)

    out_dir = attack_path_dir(run_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    graph_path = emit_graph_json(graph, out_dir / "attack_graph.json")
    topology_path = emit_topology_txt(graph, out_dir / "topology.txt")

    analysis_text_path = out_dir / "analysis.txt"
    engine_meta: dict[str, Any] = {
        "invoked": False,
        "skipped_reason": None,
        "returncode": None,
        "executable": None,
    }

    start = opts.start if opts.start is not None else graph.get("analysis_defaults", {}).get("start")
    target = (
        opts.target if opts.target is not None else graph.get("analysis_defaults", {}).get("target")
    )

    if opts.run_engine:
        engine = opts.engine_path or _default_engine()
        if engine is None or not Path(engine).exists():
            engine_meta["skipped_reason"] = (
                "C++ engine not found; graph artifacts written. "
                "Build dsa_attack_path or set STRIX_DSA_ENGINE."
            )
            analysis_text_path.write_text(
                "Engine skipped: " + engine_meta["skipped_reason"] + "\n",
                encoding="utf-8",
            )
        elif start is None or target is None:
            engine_meta["skipped_reason"] = "No start/target node available in modeled graph."
            analysis_text_path.write_text(
                "Engine skipped: " + engine_meta["skipped_reason"] + "\n",
                encoding="utf-8",
            )
        else:
            cmd = [str(engine), str(topology_path), str(start), str(target)]
            if opts.max_depth is not None:
                cmd.append(str(opts.max_depth))
            if opts.max_paths is not None:
                cmd.append(str(opts.max_paths))
            completed = subprocess.run(cmd, capture_output=True, text=True, check=False)
            engine_meta.update(
                {
                    "invoked": True,
                    "returncode": completed.returncode,
                    "executable": str(engine),
                    "start": start,
                    "target": target,
                    "command": cmd,
                }
            )
            # stderr often carries the load banner; keep both streams in the artifact.
            blob = (
                "=== MODELED ATTACK-PATH ANALYSIS (not confirmed multi-hop exploits) ===\n"
                f"engine: {engine}\n"
                f"start={start} target={target}\n"
                f"simulated_lateral={opts.allow_simulated_lateral}\n\n"
                "--- stdout ---\n"
                f"{completed.stdout}"
                "--- stderr ---\n"
                f"{completed.stderr}"
            )
            analysis_text_path.write_text(blob, encoding="utf-8")

    meta = {
        "schema_version": "1.0",
        "generated_at": datetime.now(UTC).isoformat(),
        "run_dir": str(run_dir),
        "disclaimer": graph.get("disclaimer"),
        "product_defaults": {
            "allow_simulated_lateral": opts.allow_simulated_lateral,
            "allow_simulated_entry": opts.allow_simulated_entry,
            "note": "Simulated lateral is OFF by default for product entrypoints.",
        },
        "counts": graph.get("counts"),
        "warnings": graph.get("warnings"),
        "analysis_defaults": graph.get("analysis_defaults"),
        "engine": engine_meta,
        "artifacts": {
            "attack_graph_json": str(graph_path),
            "topology_txt": str(topology_path),
            "analysis_txt": str(analysis_text_path),
            "meta_json": str(out_dir / "meta.json"),
        },
    }
    meta_path = out_dir / "meta.json"
    meta_path.write_text(json.dumps(meta, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    meta["artifacts"]["meta_json"] = str(meta_path)
    return meta
