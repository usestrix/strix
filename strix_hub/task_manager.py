"""Task Lifecycle & Process Supervisor for Strix Hub.

Controls Strix scans via subprocesses and OS signals (SIGSTOP, SIGCONT, SIGTERM).
Supports Dual-Channel Model Routing and Hot-Reloading.
"""

from __future__ import annotations

import json
import logging
import os
import signal
import subprocess
import threading
import time
from pathlib import Path
from typing import Any

from strix_hub import db
from strix_hub.model_router import ModelRouterServer

logger = logging.getLogger("strix_hub.task_manager")

STRIX_RUNS_DIR = Path(os.environ.get("STRIX_RUNS_DIR", "/opt/strix/strix_runs"))
if not STRIX_RUNS_DIR.exists():
    try:
        STRIX_RUNS_DIR.mkdir(parents=True, exist_ok=True)
    except Exception:
        STRIX_RUNS_DIR = Path.cwd() / "strix_runs"
        STRIX_RUNS_DIR.mkdir(parents=True, exist_ok=True)

# Active runners in memory: {task_id: {"process": Popen, "router": ModelRouterServer, "start_time": float}}
_ACTIVE_TASKS: dict[str, dict[str, Any]] = {}
_LOCK = threading.Lock()


def get_strix_bin_path() -> str:
    """Find the strix executable binary path."""
    venv_strix = Path("/opt/strix/.venv/bin/strix")
    if venv_strix.is_file():
        return str(venv_strix)
    uv_bin = Path("/usr/local/bin/uv")
    if uv_bin.is_file():
        return "/usr/local/bin/uv run strix"
    return "strix"


def start_task(task_id: str) -> dict[str, Any]:
    """Launch a pentest task as a background subprocess with dual-channel routing."""
    task = db.get_task_full(task_id)
    if not task:
        raise ValueError("Task not found")

    with _LOCK:
        if task_id in _ACTIVE_TASKS:
            existing = _ACTIVE_TASKS[task_id].get("process")
            if existing and existing.poll() is None:
                return db.get_task_by_id(task_id) or {}

        # 1. Start dedicated Dual-Channel ModelRouter on a free port for this task
        port = 18800 + (abs(hash(task_id)) % 1000)
        
        # Fallback to server env if task channel is left blank
        default_base = os.environ.get("OPENAI_BASE_URL") or os.environ.get("LLM_API_BASE", "https://api.openai.com/v1")
        default_key = os.environ.get("OPENAI_API_KEY") or os.environ.get("LLM_API_KEY", "")

        root_base = task.get("root_api_base") or task.get("api_base") or default_base
        root_key = task.get("root_api_key_raw") or task.get("api_key_raw") or default_key

        sub_base = task.get("subagent_api_base") or task.get("api_base") or default_base
        sub_key = task.get("subagent_api_key_raw") or task.get("api_key_raw") or default_key

        router = ModelRouterServer(
            host="127.0.0.1",
            port=port,
            root_model=task["root_model"],
            root_api_base=root_base,
            root_api_key=root_key,
            subagent_model=task["subagent_model"],
            subagent_api_base=sub_base,
            subagent_api_key=sub_key,
        )
        router.start()

        # 2. Build subprocess environment (directs LiteLLM / OpenAI to local ModelRouter)
        env = dict(os.environ)
        env["OPENAI_BASE_URL"] = f"http://127.0.0.1:{port}/v1"
        env["LLM_API_BASE"] = f"http://127.0.0.1:{port}/v1"
        root_m = task["root_model"]
        env["STRIX_LLM"] = root_m if root_m.startswith("openai/") else f"openai/{root_m}"
        # A dummy key to satisfy litellm validation if empty
        env["OPENAI_API_KEY"] = root_key or "strix-hub-key"
        env["LLM_API_KEY"] = root_key or "strix-hub-key"
        # Disable streaming so ModelRouter can accurately parse & auto-recover Qwen text tool-calls
        env["LLM_DISABLE_STREAMING"] = "true"

        # 3. Assemble command line arguments
        target = task["target"]
        scan_mode = task["scan_mode"]
        instruction = task["instruction"]

        strix_bin = get_strix_bin_path()
        cmd = f"{strix_bin} -n --target {target} --scan-mode {scan_mode}"
        if instruction:
            clean_inst = instruction.replace('"', '\\"')
            cmd += f' --instruction "{clean_inst}"'

        # Work directory
        work_dir = "/opt/strix" if Path("/opt/strix").is_dir() else str(Path.cwd())
        log_file_path = STRIX_RUNS_DIR / f"{task_id}.log"
        log_f = open(log_file_path, "w", encoding="utf-8")

        # Spawn in a new process group so SIGSTOP/SIGCONT pauses all children (Docker/tools)
        proc = subprocess.Popen(
            cmd,
            shell=True,
            cwd=work_dir,
            env=env,
            stdout=log_f,
            stderr=subprocess.STDOUT,
            preexec_fn=os.setsid if hasattr(os, "setsid") else None,
        )

        start_time = time.time()
        _ACTIVE_TASKS[task_id] = {
            "process": proc,
            "router": router,
            "start_time": start_time,
            "log_file": log_f,
        }

        db.update_task_status(task_id, status="running", pid=proc.pid)

    # Spawn background monitor thread for this task
    threading.Thread(target=_monitor_task_process, args=(task_id,), daemon=True).start()
    return db.get_task_by_id(task_id) or {}


def hot_update_task_config(
    task_id: str,
    root_model: str | None = None,
    root_api_base: str | None = None,
    root_api_key: str | None = None,
    subagent_model: str | None = None,
    subagent_api_base: str | None = None,
    subagent_api_key: str | None = None,
) -> bool:
    """Hot-reload model configuration in DB and live ModelRouter on the fly."""
    # 1. Update in SQLite DB
    db.update_task_model_config(
        task_id=task_id,
        root_model=root_model,
        root_api_base=root_api_base,
        root_api_key=root_api_key,
        subagent_model=subagent_model,
        subagent_api_base=subagent_api_base,
        subagent_api_key=subagent_api_key,
    )

    # 2. Hot-reload active ModelRouter instance if task is currently running / paused
    with _LOCK:
        info = _ACTIVE_TASKS.get(task_id)
        if info and info.get("router"):
            router: ModelRouterServer = info["router"]
            update_payload: dict[str, Any] = {}
            if root_model is not None:
                update_payload["root_model"] = root_model
            if root_api_base is not None:
                update_payload["root_api_base"] = root_api_base
            if root_api_key is not None:
                update_payload["root_api_key"] = root_api_key
            if subagent_model is not None:
                update_payload["subagent_model"] = subagent_model
            if subagent_api_base is not None:
                update_payload["subagent_api_base"] = subagent_api_base
            if subagent_api_key is not None:
                update_payload["subagent_api_key"] = subagent_api_key
            router.update_config(**update_payload)
            logger.info("Hot-updated running ModelRouter for task %s", task_id)

    return True


def pause_task(task_id: str) -> bool:
    """Pause task execution using SIGSTOP."""
    with _LOCK:
        info = _ACTIVE_TASKS.get(task_id)
        if not info or not info.get("process"):
            return False
        proc = info["process"]
        if proc.poll() is not None:
            return False

        try:
            pgid = os.getpgid(proc.pid)
            os.killpg(pgid, signal.SIGSTOP)
            db.update_task_status(task_id, status="paused")
            logger.info("Paused task %s (PID %d, PGID %d)", task_id, proc.pid, pgid)
            return True
        except Exception:
            logger.exception("Failed to pause task %s", task_id)
            return False


def resume_task(task_id: str) -> bool:
    """Resume task execution using SIGCONT."""
    with _LOCK:
        info = _ACTIVE_TASKS.get(task_id)
        if not info or not info.get("process"):
            return False
        proc = info["process"]
        if proc.poll() is not None:
            return False

        try:
            pgid = os.getpgid(proc.pid)
            os.killpg(pgid, signal.SIGCONT)
            db.update_task_status(task_id, status="running")
            logger.info("Resumed task %s (PID %d, PGID %d)", task_id, proc.pid, pgid)
            return True
        except Exception:
            logger.exception("Failed to resume task %s", task_id)
            return False


def stop_task(task_id: str) -> bool:
    """Stop/Kill task execution using SIGTERM / SIGKILL."""
    with _LOCK:
        info = _ACTIVE_TASKS.get(task_id)
        if not info or not info.get("process"):
            db.update_task_status(task_id, status="stopped")
            return True
        proc = info["process"]

        try:
            pgid = os.getpgid(proc.pid)
            os.killpg(pgid, signal.SIGTERM)
            time.sleep(0.5)
            if proc.poll() is None:
                os.killpg(pgid, signal.SIGKILL)
        except Exception:
            pass

        if info.get("router"):
            info["router"].stop()
        if info.get("log_file") and not info["log_file"].closed:
            info["log_file"].close()

        _ACTIVE_TASKS.pop(task_id, None)
        db.update_task_status(task_id, status="stopped")
        logger.info("Stopped task %s", task_id)
        return True


def _monitor_task_process(task_id: str) -> None:
    """Monitor task process completion, update status and parse findings."""
    with _LOCK:
        info = _ACTIVE_TASKS.get(task_id)
    if not info:
        return

    proc: subprocess.Popen = info["process"]
    router: ModelRouterServer = info["router"]
    start_time: float = info["start_time"]

    while proc.poll() is None:
        time.sleep(1.0)
        elapsed = int(time.time() - start_time)
        run_dir_name, vulns_cnt = _inspect_strix_runs_dir(task_id)
        current_task = db.get_task_by_id(task_id)
        current_status = current_task.get("status") if current_task else "running"
        new_status = "paused" if current_status == "paused" else "running"
        db.update_task_status(
            task_id,
            status=new_status,
            duration_seconds=elapsed,
            run_dir_name=run_dir_name,
            vulns_count=vulns_cnt,
        )

    exit_code = proc.returncode
    elapsed = int(time.time() - start_time)
    run_dir_name, vulns_cnt = _inspect_strix_runs_dir(task_id)

    final_status = "completed" if exit_code in [0, 2] else "failed"
    db.update_task_status(
        task_id,
        status=final_status,
        duration_seconds=elapsed,
        run_dir_name=run_dir_name,
        vulns_count=vulns_cnt,
    )

    router.stop()
    if info.get("log_file") and not info["log_file"].closed:
        info["log_file"].close()

    with _LOCK:
        _ACTIVE_TASKS.pop(task_id, None)
    logger.info("Task %s completed with status [%s] (code %d)", task_id, final_status, exit_code)


def _inspect_strix_runs_dir(task_id: str) -> tuple[str | None, int]:
    """Inspect newest run artifacts to find linked run_dir and vulnerability counts."""
    if not STRIX_RUNS_DIR.is_dir():
        return None, 0

    runs = sorted(
        [d for d in STRIX_RUNS_DIR.iterdir() if d.is_dir() and not d.name.startswith(".")],
        key=lambda p: p.stat().st_mtime,
        reverse=True,
    )

    if not runs:
        return None, 0

    latest = runs[0]
    vuln_count = 0
    vulns_file = latest / "vulnerabilities.json"
    if vulns_file.is_file():
        try:
            with open(vulns_file, "r", encoding="utf-8") as f:
                vulns = json.load(f)
                if isinstance(vulns, list):
                    vuln_count = len(vulns)
        except Exception:
            pass

    return latest.name, vuln_count


def get_task_logs(task_id: str, max_lines: int = 100) -> str:
    """Read the latest log output for a task."""
    log_path = STRIX_RUNS_DIR / f"{task_id}.log"
    if not log_path.is_file():
        return "No log output available yet."
    try:
        with open(log_path, "r", encoding="utf-8", errors="replace") as f:
            lines = f.readlines()
            return "".join(lines[-max_lines:])
    except Exception as e:
        return f"Error reading logs: {e}"
