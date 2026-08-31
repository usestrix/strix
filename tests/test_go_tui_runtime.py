from __future__ import annotations

import argparse
import asyncio
import json
import os
import shutil
import socket
import struct
import sys
import threading
from pathlib import Path
from types import SimpleNamespace
from typing import Any, cast

import pytest

from strix.config.settings import DEFAULT_MAX_TURNS
from strix.interface.tui import runtime as go_tui
from strix.interface.tui import sidecar
from strix.interface.tui.runtime import GoTuiRuntime


def args() -> argparse.Namespace:
    return argparse.Namespace(
        needs_setup=True,
        targets_info=[],
        instruction=None,
        scan_mode="deep",
        max_budget_usd=None,
        max_turns=DEFAULT_MAX_TURNS,
        scope_mode="auto",
        diff_base=None,
        local_sources=[],
        diff_scope={"active": False},
        user_explicit_instruction=None,
        run_name="test-run",
    )


def test_binary_command_prefers_packaged_sidecar(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Any,
) -> None:
    sidecar = tmp_path / "strix-tui"
    sidecar.write_text("binary")
    monkeypatch.setattr(go_tui, "tui_source_dir", lambda: tmp_path / "tui-src")
    monkeypatch.setattr(go_tui, "get_strix_resource_path", lambda *_parts: sidecar)
    monkeypatch.setattr(
        shutil,
        "which",
        lambda _name: pytest.fail("PATH lookup should not run"),
    )

    assert GoTuiRuntime.binary_command() == [str(sidecar)]


def test_binary_command_prefers_current_source_over_packaged_sidecar(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Any,
) -> None:
    source = tmp_path / "tui-src"
    source.mkdir()
    (source / "go.mod").write_text("module test\n")
    sidecar = tmp_path / "strix-tui"
    sidecar.write_text("stale")
    monkeypatch.setattr(go_tui, "tui_source_dir", lambda: tmp_path / "tui-src")
    monkeypatch.setattr(go_tui, "get_strix_resource_path", lambda *_parts: sidecar)
    monkeypatch.setattr(shutil, "which", lambda name: "/usr/bin/go" if name == "go" else None)

    assert GoTuiRuntime.binary_command() == ["go", "run", "./cmd/strix-tui"]


def test_binary_command_reports_missing_sidecar(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Any,
) -> None:
    monkeypatch.setattr(go_tui, "get_strix_resource_path", lambda *_parts: tmp_path / "missing")
    monkeypatch.setattr(shutil, "which", lambda _name: None)
    monkeypatch.setattr(go_tui, "tui_source_dir", lambda: tmp_path / "tui-src")

    with pytest.raises(RuntimeError, match="Bubble Tea TUI binary not found"):
        GoTuiRuntime.binary_command()


def test_binary_command_ignores_unconstrained_path_sidecar(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Any,
) -> None:
    monkeypatch.setattr(go_tui, "get_strix_resource_path", lambda *_parts: tmp_path / "missing")
    monkeypatch.setattr(go_tui, "tui_source_dir", lambda: tmp_path / "tui-src")
    monkeypatch.setattr(shutil, "which", lambda _name: "/untrusted/path/strix-tui")

    with pytest.raises(RuntimeError, match="Bubble Tea TUI binary not found"):
        GoTuiRuntime.binary_command()


def test_child_environment_excludes_credentials(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("OPENAI_API_KEY", "openai-secret")
    monkeypatch.setenv("AWS_ACCESS_KEY_ID", "aws-id")
    monkeypatch.setenv("AWS_SECRET_ACCESS_KEY", "aws-secret")
    monkeypatch.setenv("AWS_SESSION_TOKEN", "aws-token")
    monkeypatch.setenv("AWS_WEB_IDENTITY_TOKEN_FILE", "/var/run/secrets/aws-token")
    monkeypatch.setenv("VERTEXAI_CREDENTIALS", '{"private_key":"secret"}')
    monkeypatch.setenv("STRIX_TUI_TOKEN", "stale-transport-token")
    monkeypatch.setenv("TERM", "xterm-256color")

    env = sidecar.child_environment()

    assert env["TERM"] == "xterm-256color"
    assert "OPENAI_API_KEY" not in env
    assert "AWS_ACCESS_KEY_ID" not in env
    assert "AWS_SECRET_ACCESS_KEY" not in env
    assert "AWS_SESSION_TOKEN" not in env
    assert "AWS_WEB_IDENTITY_TOKEN_FILE" not in env
    assert "VERTEXAI_CREDENTIALS" not in env
    assert "STRIX_TUI_TOKEN" not in env


def test_accept_authenticated_connection() -> None:
    listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    listener.bind(("127.0.0.1", 0))
    listener.listen(1)
    address = listener.getsockname()

    def connect() -> None:
        with socket.create_connection(address) as connection:
            connection.sendall(b"one-use-token")

    thread = threading.Thread(target=connect)
    thread.start()
    connection = sidecar._accept_authenticated_connection(listener, "one-use-token")
    connection.close()
    listener.close()
    thread.join()


def test_rejects_invalid_connection_token() -> None:
    listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    listener.bind(("127.0.0.1", 0))
    listener.listen(1)
    address = listener.getsockname()

    def connect() -> None:
        with socket.create_connection(address) as connection:
            connection.sendall(b"invalidd-token")

    thread = threading.Thread(target=connect)
    thread.start()
    with pytest.raises(PermissionError, match="authentication failed"):
        sidecar._accept_authenticated_connection(listener, "expected-token")
    listener.close()
    thread.join()


@pytest.mark.asyncio
async def test_windows_transport_launches_without_inherited_fd() -> None:
    child = """
import os
import socket

host, port = os.environ["STRIX_TUI_ADDR"].rsplit(":", 1)
with socket.create_connection((host, int(port))) as connection:
    connection.sendall(os.environ["STRIX_TUI_TOKEN"].encode("ascii"))
"""
    env = os.environ.copy()
    env.pop("STRIX_TUI_FD", None)

    process, connection = await sidecar._launch_windows_tui_process(
        [sys.executable, "-c", child], env, None
    )
    connection.close()

    assert await sidecar.wait_process(process) == 0


async def _receive_exactly(connection: socket.socket, size: int) -> bytes:
    result = b""
    while len(result) < size:
        chunk = await asyncio.get_running_loop().sock_recv(connection, size - len(result))
        if not chunk:
            raise EOFError
        result += chunk
    return result


async def _receive_message(connection: socket.socket) -> dict[str, Any]:
    size = struct.unpack(">I", await _receive_exactly(connection, 4))[0]
    message: dict[str, Any] = json.loads(await _receive_exactly(connection, size))
    return message


async def _send_message(connection: socket.socket, message: dict[str, Any]) -> None:
    raw = json.dumps(message).encode()
    await asyncio.get_running_loop().sock_sendall(connection, struct.pack(">I", len(raw)) + raw)


@pytest.mark.asyncio
async def test_runtime_does_not_initialize_or_scan_before_ready(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    runtime_args = args()
    runtime_args.needs_setup = False
    runtime = GoTuiRuntime(runtime_args)
    backend, child = socket.socketpair()
    child.setblocking(False)  # noqa: FBT003
    calls: list[str] = []
    scan_started = asyncio.Event()

    async def launch(
        _command: list[str], _env: dict[str, str], _cwd: str | None
    ) -> tuple[SimpleNamespace, socket.socket]:
        return SimpleNamespace(returncode=None), backend

    async def wait_process(_process: object) -> int:
        await scan_started.wait()
        return 0

    def init_state() -> None:
        calls.append("state")

    def start_scan() -> None:
        calls.append("scan")
        scan_started.set()

    async def preflight(_model: str) -> None:
        calls.append("preflight")

    monkeypatch.setattr(runtime, "binary_command", lambda: ["test-sidecar"])
    monkeypatch.setattr(go_tui, "launch_tui_process", launch)
    monkeypatch.setattr(go_tui, "wait_process", wait_process)
    monkeypatch.setattr(go_tui, "preflight_model_connection", preflight)
    monkeypatch.setattr(go_tui, "persist_current", lambda: None)
    monkeypatch.setattr(go_tui, "prepare_run", lambda _args: None)
    monkeypatch.setattr(go_tui, "telemetry_start", lambda _args: None)
    monkeypatch.setattr(runtime, "init_run_state", init_state)
    monkeypatch.setattr(runtime, "start_scan", start_scan)

    run_task = asyncio.create_task(runtime.run())
    try:
        hello = await _receive_message(child)
        assert hello["type"] == "hello"
        assert calls == []
        await _send_message(
            child,
            {
                "version": 3,
                "type": "ready",
                "payload": {
                    "capabilities": [
                        "state-revisions",
                        "collection-deltas",
                        "structured-command-errors",
                        "agents-collection",
                    ]
                },
            },
        )
        await asyncio.wait_for(run_task, timeout=2)
        assert calls == ["preflight", "state", "scan"]
    finally:
        child.close()
        if not run_task.done():
            run_task.cancel()


@pytest.mark.asyncio
async def test_pre_activation_failure_propagates_to_dispatcher(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    class FailedRuntime:
        async def run(self) -> None:
            raise go_tui.GoTuiPreActivationError("protocol mismatch")

    monkeypatch.setattr(go_tui, "GoTuiRuntime", lambda _args: FailedRuntime())

    with pytest.raises(go_tui.GoTuiPreActivationError, match="protocol mismatch"):
        await go_tui.run_go_tui(args())


@pytest.mark.asyncio
async def test_post_activation_failure_is_surfaced(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    class ActivatedRuntime:
        async def run(self) -> None:
            raise RuntimeError("sidecar failed after ready")

    monkeypatch.setattr(go_tui, "GoTuiRuntime", lambda _args: ActivatedRuntime())

    with pytest.raises(RuntimeError, match="after ready"):
        await go_tui.run_go_tui(args())


@pytest.mark.asyncio
async def test_setup_preflights_model_before_starting(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    runtime_args = args()
    runtime_args.instruction = "CLI instruction"
    runtime = GoTuiRuntime(runtime_args)
    assert runtime.controller.instruction == "CLI instruction"
    runtime.controller.targets = ["https://example.com", "/workspace/mounted"]
    runtime.controller.scan_mode = "quick"
    runtime.controller.instruction = ""
    runtime.controller.max_budget_usd = 8.5
    runtime.controller.max_turns = 321
    runtime.controller.scope_mode = "diff"
    runtime.controller.diff_base = "origin/main"
    calls: list[str] = []

    async def preflight(model: str) -> None:
        assert model == "openrouter/test-model"
        calls.append("preflight")

    monkeypatch.setattr(
        go_tui,
        "load_settings",
        lambda: SimpleNamespace(llm=SimpleNamespace(model="openrouter/test-model")),
    )
    monkeypatch.setattr(go_tui, "preflight_model_connection", preflight)

    def build(candidate: argparse.Namespace, **_: object) -> None:
        calls.append("targets")
        assert candidate.target == ["https://example.com", "/workspace/mounted"]
        candidate.targets_info = [
            {
                "type": "web",
                "details": {"target_url": "https://example.com"},
                "original": "https://example.com",
            },
            {
                "type": "local_code",
                "details": {"target_path": "/workspace/mounted"},
                "original": "/workspace/mounted",
            },
        ]

    def prepare(candidate: argparse.Namespace) -> None:
        calls.append("prepare")
        assert candidate.max_budget_usd == 8.5
        assert candidate.max_turns == 321
        assert candidate.scope_mode == "diff"
        assert candidate.diff_base == "origin/main"

    monkeypatch.setattr(go_tui, "build_targets_info", build)
    monkeypatch.setattr(go_tui, "prepare_run", prepare)
    monkeypatch.setattr(go_tui, "telemetry_start", lambda _args: calls.append("telemetry"))
    monkeypatch.setattr(runtime, "init_run_state", lambda: calls.append("state"))
    monkeypatch.setattr(runtime, "start_scan", lambda: calls.append("scan"))

    await runtime.start_from_setup()

    assert calls == ["preflight", "targets", "prepare", "telemetry", "state", "scan"]
    assert runtime.args.scan_mode == "quick"
    assert runtime.args.instruction == ""
    assert runtime.args.max_budget_usd == 8.5
    assert runtime.args.max_turns == 321
    assert runtime.args.scope_mode == "diff"
    assert runtime.args.diff_base == "origin/main"


@pytest.mark.asyncio
async def test_optimistic_setup_skips_model_preflight(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    runtime = GoTuiRuntime(args())
    runtime.controller.targets = [str(Path.cwd())]
    calls: list[str] = []

    async def preflight(_model: str) -> None:
        calls.append("preflight")

    monkeypatch.setattr(
        go_tui,
        "load_settings",
        lambda: SimpleNamespace(llm=SimpleNamespace(model="openrouter/test-model")),
    )
    monkeypatch.setattr(go_tui, "preflight_model_connection", preflight)
    monkeypatch.setattr(go_tui, "build_targets_info", lambda _args, **_kw: calls.append("targets"))
    monkeypatch.setattr(go_tui, "prepare_run", lambda _args: calls.append("prepare"))
    monkeypatch.setattr(go_tui, "telemetry_start", lambda _args: calls.append("telemetry"))
    monkeypatch.setattr(runtime, "init_run_state", lambda: calls.append("state"))
    monkeypatch.setattr(runtime, "start_scan", lambda: calls.append("scan"))

    await runtime.start_from_setup(verify=False)

    # No preflight: the scan launches straight through and any model error
    # surfaces once the agent runs.
    assert "preflight" not in calls
    assert calls == ["targets", "prepare", "telemetry", "state", "scan"]


@pytest.mark.asyncio
async def test_confirmed_target_less_launch_mounts_workspace_without_targets(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The working directory reaches the run as a workspace, never as a target."""
    runtime = GoTuiRuntime(args())
    runtime.controller.workspace_mount = str(Path.home())
    prepared: list[argparse.Namespace] = []

    async def preflight(_model: str) -> None:
        return None

    monkeypatch.setattr(
        go_tui,
        "load_settings",
        lambda: SimpleNamespace(llm=SimpleNamespace(model="openrouter/test-model")),
    )
    monkeypatch.setattr(go_tui, "preflight_model_connection", preflight)
    monkeypatch.setattr(
        go_tui,
        "build_targets_info",
        lambda _args, **_kw: pytest.fail("a target-less launch must not build targets"),
    )
    monkeypatch.setattr(go_tui, "prepare_run", prepared.append)
    monkeypatch.setattr(go_tui, "telemetry_start", lambda _args: None)
    monkeypatch.setattr(runtime, "init_run_state", lambda: None)
    monkeypatch.setattr(runtime, "start_scan", lambda: None)

    await runtime.start_from_setup(verify=False)

    assert prepared[0].workspace_mount == str(Path.home())
    assert prepared[0].targets_info == []


@pytest.mark.asyncio
async def test_setup_preserves_prepared_cli_targets(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    runtime_args = args()
    runtime_args.target = ["https://example.com"]
    runtime_args.target_list = []
    runtime_args.targets_info = [
        {
            "type": "web",
            "details": {"url": "https://example.com"},
            "original": "https://example.com",
        }
    ]
    runtime = GoTuiRuntime(runtime_args)
    calls: list[str] = []

    async def preflight(_model: str) -> None:
        calls.append("preflight")

    monkeypatch.setattr(
        go_tui,
        "load_settings",
        lambda: SimpleNamespace(llm=SimpleNamespace(model="openrouter/test-model")),
    )
    monkeypatch.setattr(go_tui, "preflight_model_connection", preflight)
    monkeypatch.setattr(
        go_tui,
        "build_targets_info",
        lambda _args, **_kw: pytest.fail("prepared targets should not be rebuilt"),
    )
    monkeypatch.setattr(go_tui, "prepare_run", lambda _args: calls.append("prepare"))
    monkeypatch.setattr(go_tui, "telemetry_start", lambda _args: calls.append("telemetry"))
    monkeypatch.setattr(runtime, "init_run_state", lambda: calls.append("state"))
    monkeypatch.setattr(runtime, "start_scan", lambda: calls.append("scan"))

    await runtime.start_from_setup()

    assert runtime.controller.targets == ["https://example.com"]
    assert runtime.args.targets_info[0]["type"] == "web"
    assert calls == ["preflight", "prepare", "telemetry", "state", "scan"]


@pytest.mark.asyncio
async def test_setup_target_change_preserves_local_targets(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    runtime_args = args()
    runtime_args.target = []
    runtime_args.target_list = ["targets.txt"]
    runtime_args.targets_info = [
        {
            "type": "local_code",
            "details": {"target_path": "/workspace/source"},
            "original": "/workspace/source",
        }
    ]
    runtime = GoTuiRuntime(runtime_args)
    runtime.controller.targets.append("https://example.com")

    async def preflight(_model: str) -> None:
        return None

    def build(target_args: argparse.Namespace, **_: object) -> None:
        assert target_args.target == ["/workspace/source", "https://example.com"]
        target_args.targets_info = [
            {
                "type": "web",
                "details": {"url": "https://example.com"},
                "original": "https://example.com",
            },
            {
                "type": "local_code",
                "details": {"target_path": "/workspace/source"},
                "original": "/workspace/source",
            },
        ]

    monkeypatch.setattr(
        go_tui,
        "load_settings",
        lambda: SimpleNamespace(llm=SimpleNamespace(model="openrouter/test-model")),
    )
    monkeypatch.setattr(go_tui, "preflight_model_connection", preflight)
    monkeypatch.setattr(go_tui, "build_targets_info", build)
    monkeypatch.setattr(go_tui, "prepare_run", lambda _args: None)
    monkeypatch.setattr(go_tui, "telemetry_start", lambda _args: None)
    monkeypatch.setattr(runtime, "init_run_state", lambda: None)
    monkeypatch.setattr(runtime, "start_scan", lambda: None)

    await runtime.start_from_setup()

    assert runtime.args.target_list == []
    assert runtime.args.targets_info[0]["type"] == "web"
    assert runtime.args.targets_info[1]["type"] == "local_code"


@pytest.mark.asyncio
async def test_setup_same_basename_uses_combined_workspace_names_on_retry(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    existing_repo = "https://example.com/first/app.git"
    added_repo = "https://example.com/second/app.git"
    runtime_args = args()
    runtime_args.target = []
    runtime_args.target_list = ["targets.txt"]
    runtime_args.targets_info = [
        {
            "type": "repository",
            "details": {
                "target_repo": existing_repo,
                "workspace_subdir": "app",
                "cloned_repo_path": "/clones/app",
            },
            "original": existing_repo,
        }
    ]
    runtime = GoTuiRuntime(runtime_args)
    runtime.controller.targets.append(added_repo)
    prepare_attempts = 0
    started: list[str] = []

    async def preflight(_model: str) -> None:
        return None

    def build(target_args: argparse.Namespace, **_: object) -> None:
        assert target_args.target == [existing_repo, added_repo]
        target_args.targets_info = [
            {
                "type": "repository",
                "details": {
                    "target_repo": existing_repo,
                    "workspace_subdir": "app",
                },
                "original": existing_repo,
            },
            {
                "type": "repository",
                "details": {
                    "target_repo": added_repo,
                    "workspace_subdir": "app-2",
                },
                "original": added_repo,
            },
        ]

    def prepare(candidate: argparse.Namespace) -> None:
        nonlocal prepare_attempts
        prepare_attempts += 1
        assert [target["details"]["workspace_subdir"] for target in candidate.targets_info] == [
            "app",
            "app-2",
        ]
        if prepare_attempts == 1:
            candidate.targets_info[0]["details"]["target_repo"] = "/mutated"
            candidate.targets_info[1]["details"]["workspace_subdir"] = "mutated"
            raise ValueError("retry setup")

    monkeypatch.setattr(
        go_tui,
        "load_settings",
        lambda: SimpleNamespace(llm=SimpleNamespace(model="openrouter/test-model")),
    )
    monkeypatch.setattr(go_tui, "preflight_model_connection", preflight)
    monkeypatch.setattr(go_tui, "build_targets_info", build)
    monkeypatch.setattr(go_tui, "prepare_run", prepare)
    monkeypatch.setattr(go_tui, "telemetry_start", lambda _args: None)
    monkeypatch.setattr(runtime, "init_run_state", lambda: started.append("state"))
    monkeypatch.setattr(runtime, "start_scan", lambda: started.append("scan"))

    with pytest.raises(ValueError, match="retry setup"):
        await runtime.start_from_setup()

    assert runtime.args.targets_info[0]["details"] == {
        "target_repo": existing_repo,
        "workspace_subdir": "app",
        "cloned_repo_path": "/clones/app",
    }
    assert started == []

    await runtime.start_from_setup()

    assert prepare_attempts == 2
    assert runtime.args.target_list == []
    assert [target["details"]["workspace_subdir"] for target in runtime.args.targets_info] == [
        "app",
        "app-2",
    ]
    assert runtime.args.targets_info[0]["details"]["target_repo"] == existing_repo
    assert started == ["state", "scan"]


@pytest.mark.asyncio
async def test_setup_target_rebuild_restores_all_target_fields_on_failure(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    runtime_args = args()
    runtime_args.target = None
    runtime_args.target_list = ["targets.txt"]
    runtime_args.targets_info = [
        {
            "type": "local_code",
            "details": {"target_path": "/workspace/source"},
            "original": "/workspace/source",
        }
    ]
    original_targets_info = json.loads(json.dumps(runtime_args.targets_info))
    runtime = GoTuiRuntime(runtime_args)
    runtime.controller.targets.append("https://example.com")

    async def preflight(_model: str) -> None:
        return None

    def fail_rebuild(target_args: argparse.Namespace, **_: object) -> None:
        target_args.target = ["mutated"]
        target_args.target_list = ["mutated.txt"]
        target_args.targets_info = [{"original": "partial"}]
        raise ValueError("bad target")

    monkeypatch.setattr(
        go_tui,
        "load_settings",
        lambda: SimpleNamespace(llm=SimpleNamespace(model="openrouter/test-model")),
    )
    monkeypatch.setattr(go_tui, "preflight_model_connection", preflight)
    monkeypatch.setattr(go_tui, "build_targets_info", fail_rebuild)

    with pytest.raises(ValueError, match="bad target"):
        await runtime.start_from_setup()

    assert runtime.args.target is None
    assert runtime.args.target_list == ["targets.txt"]
    assert runtime.args.targets_info == original_targets_info


@pytest.mark.asyncio
async def test_setup_rebuild_canonicalizes_relative_local_target(
    tmp_path: Any,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    source = tmp_path / "source"
    source.mkdir()
    monkeypatch.chdir(tmp_path)
    runtime_args = args()
    runtime_args.target = []
    runtime_args.target_list = []
    runtime = GoTuiRuntime(runtime_args)
    runtime.controller.targets = ["source"]
    prepared = False

    async def preflight(_model: str) -> None:
        return None

    def prepare(candidate: argparse.Namespace) -> None:
        nonlocal prepared
        prepared = True
        assert len(candidate.targets_info) == 1
        assert candidate.targets_info[0]["details"]["target_path"] == str(source.resolve())

    monkeypatch.setattr(
        go_tui,
        "load_settings",
        lambda: SimpleNamespace(llm=SimpleNamespace(model="openrouter/test-model")),
    )
    monkeypatch.setattr(go_tui, "preflight_model_connection", preflight)
    monkeypatch.setattr(go_tui, "prepare_run", prepare)
    monkeypatch.setattr(go_tui, "telemetry_start", lambda _args: None)
    monkeypatch.setattr(runtime, "init_run_state", lambda: None)
    monkeypatch.setattr(runtime, "start_scan", lambda: None)

    await runtime.start_from_setup()

    assert prepared is True
    assert runtime.args.targets_info[0]["original"] == str(source.resolve())


@pytest.mark.asyncio
@pytest.mark.asyncio
async def test_setup_prepare_system_exit_is_recoverable_and_transactional(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    runtime_args = args()
    runtime_args.instruction = "CLI instruction"
    runtime_args.scan_mode = "deep"
    runtime_args.target = ["https://example.com"]
    runtime_args.target_list = []
    runtime_args.targets_info = [
        {
            "type": "web",
            "details": {"url": "https://example.com"},
            "original": "https://example.com",
        }
    ]
    original_args = json.loads(json.dumps(vars(runtime_args)))
    runtime = GoTuiRuntime(runtime_args)
    runtime.controller.scan_mode = "quick"
    runtime.controller.instruction = ""
    telemetry_started = False

    async def preflight(_model: str) -> None:
        return None

    def fail_prepare(candidate: argparse.Namespace) -> None:
        assert candidate is not runtime.args
        candidate.run_name = "mutated-run"
        candidate.targets_info[0]["details"]["url"] = "https://mutated.example"
        raise ValueError("invalid diff scope")

    def telemetry(_candidate: argparse.Namespace) -> None:
        nonlocal telemetry_started
        telemetry_started = True

    monkeypatch.setattr(
        go_tui,
        "load_settings",
        lambda: SimpleNamespace(llm=SimpleNamespace(model="openrouter/test-model")),
    )
    monkeypatch.setattr(go_tui, "preflight_model_connection", preflight)
    monkeypatch.setattr(go_tui, "prepare_run", fail_prepare)
    monkeypatch.setattr(go_tui, "telemetry_start", telemetry)

    with pytest.raises(ValueError, match="invalid diff scope"):
        await runtime.start_from_setup()

    assert vars(runtime.args) == original_args
    assert telemetry_started is False
    assert runtime.scan_task is None


@pytest.mark.asyncio
async def test_scan_passes_max_turns_and_budget(monkeypatch: pytest.MonkeyPatch) -> None:
    runtime_args = args()
    runtime_args.max_turns = 37
    runtime_args.max_budget_usd = 4.25
    runtime = GoTuiRuntime(runtime_args)
    runtime.scan_config = {"run_name": "test-run"}
    captured: dict[str, Any] = {}

    async def run_scan(**kwargs: Any) -> None:
        captured.update(kwargs)
        coordinator = kwargs["coordinator"]
        await coordinator.register("root", "Root", parent_id=None)
        await coordinator.set_status("root", "stopped")

    monkeypatch.setattr(
        go_tui,
        "load_settings",
        lambda: SimpleNamespace(runtime=SimpleNamespace(image="test-image")),
    )
    monkeypatch.setattr(go_tui, "run_strix_scan", run_scan)

    await runtime._run_scan()

    assert captured["max_turns"] == 37
    assert captured["max_budget_usd"] == 4.25
    assert runtime.controller.scan_state == "stopped"


@pytest.mark.asyncio
async def test_setup_preflight_failure_does_not_start_scan(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    runtime = GoTuiRuntime(args())
    runtime.controller.targets = ["https://example.com"]
    started = False

    async def preflight(_model: str) -> None:
        raise ValueError("401 Unauthorized")

    def mark_started(*_args: Any) -> None:
        nonlocal started
        started = True

    monkeypatch.setattr(
        go_tui,
        "load_settings",
        lambda: SimpleNamespace(llm=SimpleNamespace(model="openrouter/test-model")),
    )
    monkeypatch.setattr(go_tui, "preflight_model_connection", preflight)
    monkeypatch.setattr(go_tui, "build_targets_info", mark_started)
    monkeypatch.setattr(runtime, "init_run_state", mark_started)
    monkeypatch.setattr(runtime, "start_scan", mark_started)

    with pytest.raises(RuntimeError, match="Model connection failed: 401 Unauthorized"):
        await runtime.start_from_setup()

    assert started is False
    assert runtime.scan_task is None


@pytest.mark.asyncio
async def test_agent_state_sync_uses_latest_graph_snapshot_shape() -> None:
    runtime = GoTuiRuntime(args())
    await runtime.coordinator.register("root", "Strix", parent_id=None)
    await runtime.coordinator.register("child", "Recon", parent_id="root")
    await runtime.coordinator.set_status("child", "failed", error="provider rejected request")

    await runtime._sync_agent_state()

    assert runtime.live_view.agents["root"]["name"] == "Strix"
    child = runtime.live_view.agents["child"]
    assert child["name"] == "Recon"
    assert child["parent_id"] == "root"
    assert child["status"] == "failed"
    assert child["error_message"] == "provider rejected request"


@pytest.mark.asyncio
async def test_agent_state_sync_projects_completed_report() -> None:
    runtime = GoTuiRuntime(args())
    runtime.report_state = cast("Any", SimpleNamespace(run_record={"status": "completed"}))
    await runtime.coordinator.register("root", "Strix", parent_id=None)
    await runtime.coordinator.set_status("root", "completed")

    await runtime._sync_agent_state()

    assert runtime.controller.scan_state == "completed"


@pytest.mark.asyncio
async def test_agent_state_sync_does_not_mask_root_failure_with_completed_report() -> None:
    runtime = GoTuiRuntime(args())
    runtime.report_state = cast("Any", SimpleNamespace(run_record={"status": "completed"}))
    await runtime.coordinator.register("root", "Strix", parent_id=None)
    await runtime.coordinator.set_status("root", "failed", error="finalization failed")

    await runtime._sync_agent_state()

    assert runtime.controller.scan_state == "failed"
    assert runtime.controller.error == "finalization failed"


@pytest.mark.asyncio
async def test_agent_state_sync_clears_root_failure_after_user_resume() -> None:
    runtime = GoTuiRuntime(args())
    await runtime.coordinator.register("root", "Strix", parent_id=None)
    await runtime.coordinator.set_status("root", "failed", error="provider rejected request")

    await runtime._sync_agent_state()
    assert runtime.controller.scan_state == "failed"
    assert runtime.live_view.agents["root"]["error_message"] == "provider rejected request"

    await runtime.coordinator.send("root", {"from": "user", "content": "try again"})
    await runtime._sync_agent_state()

    assert runtime.controller.scan_state == "running"
    assert runtime.controller.error is None
    root = runtime.live_view.agents["root"]
    assert root["status"] == "waiting"
    assert "error_message" not in root


@pytest.mark.asyncio
async def test_agent_state_sync_does_not_reopen_stopped_scan_with_active_root() -> None:
    runtime = GoTuiRuntime(args())
    runtime.controller.scan_state = "stopped"
    await runtime.coordinator.register("root", "Strix", parent_id=None)

    await runtime._sync_agent_state()

    assert runtime.controller.scan_state == "stopped"


def _direct_launch_args() -> argparse.Namespace:
    launch_args = args()
    launch_args.needs_setup = False
    return launch_args


@pytest.mark.asyncio
async def test_prepare_and_start_reports_ordinary_connection_failures(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    runtime = GoTuiRuntime(_direct_launch_args())
    started: list[str] = []

    async def preflight(_model: str) -> None:
        raise TimeoutError("connection timed out")

    monkeypatch.setattr(go_tui, "preflight_model_connection", preflight)
    monkeypatch.setattr(runtime, "start_scan", lambda: started.append("scan"))

    await runtime.prepare_and_start()

    assert started == []
    assert runtime.controller.setup_mode is False
    assert runtime.controller.scan_state == "failed"
    assert "connection timed out" in (runtime.controller.error or "")


@pytest.mark.asyncio
async def test_prepare_and_start_runs_the_scan_after_preparation(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    runtime = GoTuiRuntime(_direct_launch_args())
    order: list[str] = []

    async def preflight(_model: str) -> None:
        order.append("preflight")

    monkeypatch.setattr(go_tui, "preflight_model_connection", preflight)
    monkeypatch.setattr(go_tui, "persist_current", lambda: order.append("persist"))
    monkeypatch.setattr(go_tui, "prepare_run", lambda _args: order.append("prepare"))
    monkeypatch.setattr(go_tui, "telemetry_start", lambda _args: order.append("telemetry"))
    monkeypatch.setattr(runtime, "init_run_state", lambda: order.append("state"))
    monkeypatch.setattr(runtime, "start_scan", lambda: order.append("scan"))

    await runtime.prepare_and_start()

    assert order == ["preflight", "persist", "prepare", "telemetry", "state", "scan"]
    assert runtime.controller.scan_state == "running"
