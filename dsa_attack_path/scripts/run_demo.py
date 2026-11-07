#!/usr/bin/env python3
"""One-click thesis demo launcher (Windows-friendly).

Builds/uses the C++ engine, analyzes the synthetic fixture (simulated lateral OFF),
copies into strix_runs/dsa-demo, then opens ``strix view`` when possible.

MODELED attack graph only — not a confirmed multi-hop exploit chain.
"""

from __future__ import annotations

import argparse
import os
import shutil
import subprocess
import sys
from pathlib import Path


RUN_NAME = "dsa-demo"
DISCLAIMER = (
    "MODELED ATTACK GRAPH — not a confirmed multi-hop exploit chain. "
    "Simulated lateral stays OFF for this demo."
)


def _is_frozen() -> bool:
    return bool(getattr(sys, "frozen", False))


def _anchor_dir() -> Path:
    """Directory of this script, or of the PyInstaller exe."""
    if _is_frozen():
        return Path(sys.executable).resolve().parent
    return Path(__file__).resolve().parent


def _find_dsa_root() -> Path:
    """Walk up from the launcher / cwd until ``dsa_attack_path/CMakeLists.txt`` exists."""
    starts = [_anchor_dir(), Path.cwd().resolve()]
    seen: set[Path] = set()
    for start in starts:
        cur = start
        for _ in range(8):
            if cur in seen:
                break
            seen.add(cur)
            candidate = cur if cur.name == "dsa_attack_path" else cur / "dsa_attack_path"
            if (candidate / "CMakeLists.txt").is_file():
                return candidate
            # exe living in scripts/ or scripts/dist/
            if (cur / "CMakeLists.txt").is_file() and (cur / "backend").is_dir():
                return cur
            if cur.parent == cur:
                break
            cur = cur.parent
    raise RuntimeError(
        "Cannot locate dsa_attack_path/. Run from the repo checkout "
        "(double-click dsa_attack_path\\Run-Demo.bat) or place the exe under scripts\\."
    )


def _dsa_root() -> Path:
    return _find_dsa_root()


def _repo_root() -> Path:
    return _dsa_root().parent


def _scripts_dir() -> Path:
    return _dsa_root() / "scripts"


def _python() -> str:
    """Interpreter for spawning backend/fixture scripts (not the frozen exe)."""
    if not _is_frozen():
        return sys.executable
    venv_py = _repo_root() / ".venv" / "Scripts" / "python.exe"
    if venv_py.exists():
        return str(venv_py)
    found = shutil.which("python") or shutil.which("python3")
    if found:
        return found
    raise RuntimeError(
        "Frozen demo exe needs a system/venv Python to run fixture + backend. "
        "Install Python 3.12+ or use Run-Demo.bat instead."
    )


def _engine_path() -> Path:
    return _dsa_root() / "build" / "strix_dsa_cli.exe"


def _prepend_toolchain_path() -> None:
    extras = [
        r"C:\Program Files\CMake\bin",
        r"C:\TDM-GCC-64\bin",
        str(Path.home() / "AppData" / "Roaming" / "Python" / "Python314" / "Scripts"),
    ]
    parts = [p for p in extras if Path(p).exists()]
    if parts:
        os.environ["Path"] = os.pathsep.join(parts + [os.environ.get("Path", "")])


def _run(cmd: list[str], *, cwd: Path | None = None, check: bool = True) -> subprocess.CompletedProcess[str]:
    print(f"\n> {' '.join(cmd)}")
    completed = subprocess.run(
        cmd,
        cwd=str(cwd) if cwd else None,
        text=True,
        check=False,
    )
    if check and completed.returncode != 0:
        raise RuntimeError(f"Command failed ({completed.returncode}): {' '.join(cmd)}")
    return completed


def ensure_engine(*, rebuild: bool = False) -> Path:
    engine = _engine_path()
    build_dir = _dsa_root() / "build"
    if engine.exists() and not rebuild:
        print(f"[ok] Using existing engine: {engine}")
        return engine

    print("[..] Building C++ engine (MinGW Makefiles)…")
    if shutil.which("cmake") is None:
        raise RuntimeError(
            "cmake not found. Install CMake and ensure "
            r"'C:\Program Files\CMake\bin' is on PATH."
        )
    if shutil.which("g++") is None and shutil.which("c++") is None:
        raise RuntimeError(
            "g++ not found. Install TDM-GCC or MinGW and ensure "
            r"'C:\TDM-GCC-64\bin' is on PATH."
        )

    if not build_dir.exists():
        _run(
            [
                "cmake",
                "-S",
                str(_dsa_root()),
                "-B",
                str(build_dir),
                "-G",
                "MinGW Makefiles",
                "-DCMAKE_BUILD_TYPE=Release",
            ]
        )
    _run(["cmake", "--build", str(build_dir)])
    if not engine.exists():
        raise RuntimeError(f"Build finished but engine missing: {engine}")
    print(f"[ok] Engine ready: {engine}")
    return engine


def analyze_fixture(engine: Path) -> Path:
    backend = _dsa_root() / "backend"
    fixture_script = backend / "fixtures" / "make_fixture_run.py"
    sample_run = backend / "fixtures" / "sample_run_dir"
    print("[..] Preparing synthetic fixture run (not a live pentest)…")
    py = _python()
    _run([py, str(fixture_script), str(sample_run)], cwd=backend)
    # Product default: simulated lateral OFF (do not pass --allow-simulated-lateral).
    _run(
        [
            py,
            "-m",
            "strix_dsa_backend",
            str(sample_run),
            "--engine",
            str(engine),
        ],
        cwd=backend,
    )
    meta = sample_run / "attack_path" / "meta.json"
    if not meta.exists():
        raise RuntimeError(f"Expected artifacts missing: {meta}")
    print(f"[ok] Artifacts at {sample_run / 'attack_path'}")
    return sample_run


def stage_strix_run(sample_run: Path) -> Path:
    dest = _repo_root() / "strix_runs" / RUN_NAME
    if dest.exists():
        shutil.rmtree(dest)
    dest.mkdir(parents=True)
    for item in sample_run.iterdir():
        target = dest / item.name
        if item.is_dir():
            shutil.copytree(item, target)
        else:
            shutil.copy2(item, target)
    print(f"[ok] Staged viewer run: {dest}")
    return dest


def _viewer_candidates() -> list[list[str]]:
    repo = _repo_root()
    venv_strix = repo / ".venv" / "Scripts" / "strix.exe"
    candidates: list[list[str]] = []
    if shutil.which("uv"):
        candidates.append(["uv", "run", "strix", "view", RUN_NAME])
    if venv_strix.exists():
        candidates.append([str(venv_strix), "view", RUN_NAME])
    if shutil.which("strix"):
        candidates.append(["strix", "view", RUN_NAME])
    return candidates


def open_viewer(*, no_open: bool = False) -> int:
    repo = _repo_root()
    candidates = _viewer_candidates()
    if not candidates:
        print("\n[!] Could not find `uv` / `.venv\\Scripts\\strix.exe` / `strix` on PATH.")
        print("    Next command (after `uv sync` in repo root):")
        print(f"      cd /d {_repo_root()}")
        print(f"      uv run strix view {RUN_NAME}")
        return 2

    extra = ["--no-open"] if no_open else []
    last_rc = 1
    for base in candidates:
        cmd = [*base, *extra]
        print(f"[..] Trying viewer: {' '.join(cmd)}")
        completed = _run(cmd, cwd=repo, check=False)
        last_rc = completed.returncode
        if completed.returncode == 0:
            print("[ok] Viewer launched.")
            return 0
        print(f"[!] Viewer exit {completed.returncode}; trying next candidate…")

    print("\n[!] Viewer did not start. Artifacts are ready — run manually:")
    print(f"      cd /d {repo}")
    print(f"      uv run strix view {RUN_NAME}")
    return last_rc


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="One-click DSA attack-path thesis demo (MODELED graph only)."
    )
    parser.add_argument(
        "--rebuild-engine",
        action="store_true",
        help="Force cmake --build even if strix_dsa_cli.exe already exists.",
    )
    parser.add_argument(
        "--skip-viewer",
        action="store_true",
        help="Only build/analyze/stage; print the strix view command.",
    )
    parser.add_argument(
        "--no-open",
        action="store_true",
        help="Pass --no-open to strix view (do not auto-open a browser).",
    )
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)
    print("=" * 60)
    print("Strix DSA Attack Path — thesis demo launcher")
    print(DISCLAIMER)
    print("=" * 60)
    _prepend_toolchain_path()

    try:
        engine = ensure_engine(rebuild=args.rebuild_engine)
        sample = analyze_fixture(engine)
        stage_strix_run(sample)
    except Exception as exc:  # noqa: BLE001 — user-facing launcher
        print(f"\n[ERROR] {exc}", file=sys.stderr)
        return 1

    if args.skip_viewer:
        print("\n[ok] Analyze complete. Open the viewer with:")
        print(f"      cd /d {_repo_root()}")
        print(f"      uv run strix view {RUN_NAME}")
        return 0

    return open_viewer(no_open=args.no_open)


if __name__ == "__main__":
    raise SystemExit(main())
