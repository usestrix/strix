from __future__ import annotations

from strix.scan import PreparedScan, ScanRequest, build_targets_info, generate_scan_id, prepare_scan


def generate_task_id(raw_targets: list[str]) -> str:
    return generate_scan_id(raw_targets)


__all__ = [
    "PreparedScan",
    "ScanRequest",
    "build_targets_info",
    "generate_task_id",
    "prepare_scan",
]
