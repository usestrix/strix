import sys
from pathlib import Path


def get_strix_resource_path(*parts: str) -> Path:
    frozen_base = getattr(sys, "_MEIPASS", None)
    if frozen_base:
        base = Path(frozen_base) / "strix"
        if base.exists():
            return base.joinpath(*parts)

    base = Path(__file__).resolve().parent.parent
    return base.joinpath(*parts)
