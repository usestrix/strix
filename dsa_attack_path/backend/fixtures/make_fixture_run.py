"""Create a minimal strix_runs-shaped fixture for backend integration tests."""

from __future__ import annotations

import json
import shutil
import sys
from pathlib import Path


def main() -> int:
    backend_root = Path(__file__).resolve().parents[1]
    bridge_fixtures = backend_root.parent / "bridge" / "fixtures"
    out = Path(sys.argv[1]) if len(sys.argv) > 1 else backend_root / "fixtures" / "sample_run_dir"
    if out.exists():
        shutil.rmtree(out)
    out.mkdir(parents=True)
    shutil.copy(bridge_fixtures / "sample_vulnerabilities.json", out / "vulnerabilities.json")
    shutil.copy(bridge_fixtures / "sample_run.json", out / "run.json")
    # Mark clearly as fixture
    note = {
        "fixture": True,
        "disclaimer": "SYNTHETIC Strix run layout for DSA backend tests — not a live scan.",
    }
    (out / "FIXTURE_NOTE.json").write_text(json.dumps(note, indent=2) + "\n", encoding="utf-8")
    print(out)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
