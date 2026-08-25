"""Isolated execution for a safety model's single inspection script."""

from __future__ import annotations

import asyncio
import contextlib
import logging
import os
import tempfile
from pathlib import Path
from typing import TYPE_CHECKING, Protocol

import docker


if TYPE_CHECKING:
    from strix.config.settings import SafetySettings


logger = logging.getLogger(__name__)


class InspectionRunner(Protocol):
    async def run(self, *, evidence_dir: str, script: str) -> str: ...


class DockerInspectionRunner:
    """Run model-authored analysis in a networkless, read-only container."""

    def __init__(self, *, settings: SafetySettings, fallback_image: str) -> None:
        self._settings = settings
        self._image = settings.inspection_image or fallback_image

    async def run(self, *, evidence_dir: str, script: str) -> str:
        return await asyncio.to_thread(self._run_sync, evidence_dir, script)

    def _run_sync(self, evidence_dir: str, script: str) -> str:
        evidence = Path(evidence_dir).resolve()
        if not evidence.is_dir():
            return "Inspection failed: frozen evidence directory is unavailable."

        with tempfile.TemporaryDirectory(prefix="strix-safety-script-") as script_tmp:
            script_dir = Path(script_tmp)
            script_path = script_dir / "inspect.py"
            script_path.write_text(script, encoding="utf-8")
            script_path.chmod(0o644)
            for root, dirs, files in os.walk(evidence):
                Path(root).chmod(0o755)
                for name in dirs:
                    (Path(root) / name).chmod(0o755)
                for name in files:
                    (Path(root) / name).chmod(0o644)

            client = docker.from_env()
            container = None
            try:
                container = client.containers.create(
                    self._image,
                    command=["-I", "-S", "/inspection/inspect.py"],
                    entrypoint=["python3"],
                    detach=True,
                    network_disabled=True,
                    read_only=True,
                    cap_drop=["ALL"],
                    security_opt=["no-new-privileges:true"],
                    pids_limit=8,
                    mem_limit="256m",
                    user="pentester",
                    working_dir="/evidence",
                    volumes={
                        str(evidence): {"bind": "/evidence", "mode": "ro"},
                        str(script_dir): {"bind": "/inspection", "mode": "ro"},
                    },
                    tmpfs={"/tmp": "rw,noexec,nosuid,nodev,size=16m"},  # noqa: S108  # nosec B108 - in-container tmpfs, not a host path
                )
                container.start()
                try:
                    result = container.wait(timeout=self._settings.inspection_timeout)
                except Exception as exc:  # noqa: BLE001 - timeout/transport both fail closed.
                    with contextlib.suppress(Exception):
                        container.kill()
                    return f"Inspection failed or timed out: {type(exc).__name__}"
                output = container.logs(stdout=True, stderr=True)
                text = output.decode("utf-8", errors="replace")
                limit = self._settings.inspection_output_bytes
                encoded = text.encode("utf-8")
                truncated = len(encoded) > limit
                if truncated:
                    text = encoded[:limit].decode("utf-8", errors="replace")
                    text += (
                        "\n[inspection output truncated; do not allow based on incomplete output]"
                    )
                status = int(result.get("StatusCode", 1))
                return f"Inspection exit code: {status}\n{text}".strip()
            except Exception as exc:
                logger.exception("safety inspection container failed")
                return f"Inspection failed: {type(exc).__name__}: {exc}"
            finally:
                if container is not None:
                    try:
                        container.remove(force=True)
                    except Exception:  # noqa: BLE001 - cleanup is best effort.
                        logger.debug("failed to remove safety inspection container", exc_info=True)
                client.close()
