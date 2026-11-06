"""Optional ``strix attack-path`` subcommand (Phase 3).

Thin shim: does not run inside agent/scanner loops. Delegates to the
independent ``dsa_attack_path/backend`` module when present in this checkout.
Simulated lateral stays off unless the user passes ``--allow-simulated-lateral``.
"""

from __future__ import annotations

import sys
from pathlib import Path


def _repo_root() -> Path:
    # strix/interface/attack_path_cli.py → parents[2] = repository root
    return Path(__file__).resolve().parents[2]


def _load_backend_main():
    repo = _repo_root()
    backend = repo / "dsa_attack_path" / "backend"
    if not backend.is_dir():
        return None
    backend_str = str(backend)
    if backend_str not in sys.path:
        sys.path.insert(0, backend_str)
    from strix_dsa_backend.cli import main as backend_main

    return backend_main


def run_attack_path(argv: list[str] | None = None) -> int:
    """Entrypoint used by ``strix attack-path …``."""
    backend_main = _load_backend_main()
    if backend_main is None:
        print(
            "Attack-path backend not found.\n"
            "This optional thesis module lives at dsa_attack_path/backend/ in the "
            "DSA-enhanced checkout. Build the C++ engine under dsa_attack_path/ and "
            "re-run from that repository tree.\n"
            "See dsa_attack_path/backend/README.md.",
            file=sys.stderr,
        )
        return 2
    return int(backend_main(argv))
