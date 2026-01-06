"""
Checkpoint management for scan resumption.

This module provides functionality to save and restore agent state,
enabling scans to resume after interruption.
"""

import json
import logging
from datetime import UTC, datetime
from pathlib import Path
from typing import Any


logger = logging.getLogger(__name__)

# Checkpoint format version - increment when schema changes
CHECKPOINT_VERSION = 1


class CheckpointError(Exception):
    """Raised when checkpoint operations fail."""


def get_checkpoint_path(run_dir: Path) -> Path:
    """
    Get path to checkpoint file for a run.

    Args:
        run_dir: Run directory (e.g., strix_runs/my-scan)

    Returns:
        Path to checkpoint.json
    """
    return run_dir / "checkpoint.json"


def save_checkpoint(
    run_dir: Path,
    agent_state: Any,  # AgentState from state.py
    scan_config: dict[str, Any],
    tracer_data: dict[str, Any] | None = None,
) -> None:
    """
    Save checkpoint for resumption.

    Args:
        run_dir: Run directory
        agent_state: Current AgentState instance
        scan_config: Scan configuration dict
        tracer_data: Optional tracer metadata

    Note:
        - Fails silently if save fails (logs error)
        - Uses same error handling pattern as tracer.save_run_data()
    """
    try:
        checkpoint_path = get_checkpoint_path(run_dir)

        # Build checkpoint data
        checkpoint = {
            "version": CHECKPOINT_VERSION,
            "created_at": datetime.now(UTC).isoformat(),
            "scan_config": scan_config,
            "agent_state": agent_state.model_dump(
                mode="json"
            ),  # Pydantic serialization with JSON mode
            "tracer_data": tracer_data or {},
        }

        # Write atomically: write to temp file, then rename
        temp_path = checkpoint_path.with_suffix(".tmp")
        with temp_path.open("w", encoding="utf-8") as f:
            json.dump(checkpoint, f, indent=2)

        # Atomic rename (overwrites existing checkpoint)
        temp_path.replace(checkpoint_path)

        logger.info(f"Saved checkpoint at iteration {agent_state.iteration}")

    except (OSError, RuntimeError, TypeError, ValueError):
        # Match tracer.py error handling pattern
        logger.exception("Failed to save checkpoint")


def load_checkpoint(run_dir: Path) -> dict[str, Any] | None:
    """
    Load checkpoint for resumption.

    Args:
        run_dir: Run directory

    Returns:
        Checkpoint dict if valid, None if missing/invalid

    Note:
        - Returns None on any error (graceful degradation)
        - Validates checkpoint version and structure
    """
    try:
        checkpoint_path = get_checkpoint_path(run_dir)

        if not checkpoint_path.exists():
            logger.debug(f"No checkpoint found at {checkpoint_path}")
            return None

        with checkpoint_path.open("r", encoding="utf-8") as f:
            checkpoint = json.load(f)

        # Validate version
        version = checkpoint.get("version")
        if version != CHECKPOINT_VERSION:
            logger.warning(
                f"Checkpoint version mismatch: expected {CHECKPOINT_VERSION}, "
                f"got {version}. Cannot resume."
            )
            return None

        # Validate required fields
        required = ["scan_config", "agent_state"]
        missing = [field for field in required if field not in checkpoint]
        if missing:
            logger.warning(f"Checkpoint missing fields: {missing}. Cannot resume.")
            return None

        logger.info("Loaded valid checkpoint")

    except (OSError, json.JSONDecodeError, KeyError, TypeError):
        logger.exception("Failed to load checkpoint")
        return None
    else:
        return checkpoint


def can_resume(run_dir: Path, current_scan_config: dict[str, Any]) -> bool:
    """
    Check if scan can be resumed from checkpoint.

    Args:
        run_dir: Run directory
        current_scan_config: Configuration for current scan attempt

    Returns:
        True if checkpoint exists and is compatible
    """
    checkpoint = load_checkpoint(run_dir)
    if not checkpoint:
        return False

    # Check if scan already completed
    agent_state_data = checkpoint.get("agent_state", {})
    if agent_state_data.get("completed", False):
        logger.info("Checkpoint found but scan already completed")
        return False

    # Validate target compatibility (targets should match)
    saved_config = checkpoint.get("scan_config", {})
    saved_targets = saved_config.get("targets", [])
    current_targets = current_scan_config.get("targets", [])

    # Simple comparison: same number of targets
    if len(saved_targets) != len(current_targets):
        logger.warning(
            f"Target mismatch: checkpoint has {len(saved_targets)} targets, "
            f"current scan has {len(current_targets)}. Cannot resume."
        )
        return False

    return True


def delete_checkpoint(run_dir: Path) -> None:
    """
    Delete checkpoint file.

    Args:
        run_dir: Run directory

    Note:
        - Silently succeeds if checkpoint doesn't exist
    """
    try:
        checkpoint_path = get_checkpoint_path(run_dir)
        if checkpoint_path.exists():
            checkpoint_path.unlink()
            logger.info("Deleted checkpoint")
    except OSError as e:
        logger.warning(f"Failed to delete checkpoint: {e}")
