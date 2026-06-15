"""Durable per-target inventory store backed by ``strix/core/paths.py``."""

from __future__ import annotations

import json
from datetime import UTC, datetime
from pathlib import Path  # noqa: TC003  used at runtime by save/load signatures
from typing import Any, cast

from strix.core.inventory.models import RankedSurfaceMap
from strix.core.paths import inventory_path


def _model_dump(model: RankedSurfaceMap) -> dict[str, Any]:
    """Return a JSON-serializable dict of the ranked surface map."""
    return cast("dict[str, Any]", json.loads(model.model_dump_json()))


def save_ranked_map(run_dir: Path, ranked_map: RankedSurfaceMap) -> Path:
    """Persist a ranked surface map to the per-target inventory path."""
    path = inventory_path(run_dir, ranked_map.target_id)
    path.parent.mkdir(parents=True, exist_ok=True)
    payload = _model_dump(ranked_map)
    payload["created_at"] = datetime.now(UTC).isoformat()
    path.write_text(json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8")
    return path


def load_ranked_map(run_dir: Path, target_id: str) -> RankedSurfaceMap:
    """Load a ranked surface map from the per-target inventory path."""
    path = inventory_path(run_dir, target_id)
    if not path.exists():
        return RankedSurfaceMap(target_id=target_id)
    data = json.loads(path.read_text(encoding="utf-8"))
    return RankedSurfaceMap.model_validate(data)
