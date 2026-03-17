import asyncio
import logging
import os
import subprocess
import threading
import uuid
from pathlib import Path

import pytest

from strix.agents.state import AgentState
from strix.runtime.docker_runtime import DockerRuntime
from strix.tools.browser.browser_actions import browser_action
from strix.tools.context import set_current_agent_id

from . import console as ui


def pytest_addoption(parser):
    parser.addoption("--pretty", action="store_true", default=False, help="Clean TUI output")


def _preflight():
    missing = [v for v in ("STRIX_LLM", "LLM_API_KEY") if not os.environ.get(v)]
    if missing:
        pytest.exit(
            f"Missing required env vars: {', '.join(missing)}\n"
            "  STRIX_LLM=<model, eg: openrouter/xyz>\n"
            "  LLM_API_KEY=<api key>",
            returncode=1,
        )

    image = os.environ.get("STRIX_IMAGE", "")
    if not image:
        ui.log_warn("STRIX_IMAGE not set — falling back to config default")
    elif "dev" not in image:
        ui.log_warn(f"STRIX_IMAGE={image} — consider using strix-sandbox:dev for integration tests")


_preflight()

if ui.is_pretty():
    for _name in (
        "strix.tests.integration",
        "strix.tests.integration.browser",
        "strix.tests.integration.container",
        "strix.tools.browser.browser_actions",
        "strix.tools.browser.browser_manager",
    ):
        _lg = logging.getLogger(_name)
        _lg.handlers = []
        _lg.propagate = False
        _lg.setLevel(logging.CRITICAL)

_SESSION_AGENT_ID = f"integration-{uuid.uuid4().hex[:8]}"

_bg_loop = asyncio.new_event_loop()
_bg_thread = threading.Thread(target=_bg_loop.run_forever, daemon=True)
_bg_thread.start()


def _run_in_bg(coro):
    future = asyncio.run_coroutine_threadsafe(coro, _bg_loop)
    return future.result(timeout=120)


@pytest.hookimpl(trylast=True)
def pytest_configure(config):
    if not ui.is_pretty():
        return
    # redirect pytest's stdout writes to devnull so "PASSED"/"FAILED"/dots don't show
    terminal = config.pluginmanager.get_plugin("terminalreporter")
    if terminal is not None:
        terminal._tw = type(terminal._tw)(Path(os.devnull).open("w"))  # noqa: SIM115


def pytest_report_teststatus(report, config):
    if not ui.is_pretty():
        return None
    if report.when == "call":
        return "", "", ""
    return None


# -- fixtures ------------------------------------------------------------------


@pytest.fixture(scope="session", autouse=True)
def _ui_lifecycle():
    ui.start()
    yield
    ui.stop()


@pytest.fixture(scope="session")
def docker_runtime():
    ui.status("Creating DockerRuntime…")
    runtime = DockerRuntime()
    yield runtime
    runtime.cleanup()


@pytest.fixture(scope="session")
def sandbox_info(docker_runtime):
    agent_id = _SESSION_AGENT_ID
    ui.status(f"Creating sandbox ({agent_id})…")
    info = _run_in_bg(docker_runtime.create_sandbox(agent_id))
    ui.log(f"Sandbox ready: container={info['workspace_id'][:12]} api={info['api_url']}")

    yield info

    subprocess.Popen(
        ["docker", "rm", "-f", info["workspace_id"]],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    docker_runtime._scan_container = None
    docker_runtime._tool_server_port = None
    docker_runtime._tool_server_token = None
    docker_runtime._caido_port = None


@pytest.fixture(scope="session")
def agent_state(sandbox_info):
    return AgentState(
        agent_id=_SESSION_AGENT_ID,
        sandbox_id=sandbox_info["workspace_id"],
        sandbox_token=sandbox_info["auth_token"],
        sandbox_info=sandbox_info,
    )


@pytest.fixture
def browsers(agent_state, request):
    from strix.tools.browser.browser_manager import _manager

    from .helpers import Browser

    marker = request.node.get_closest_marker("browsers")
    count = marker.args[0] if marker else 1

    agent_ids = [f"{_SESSION_AGENT_ID}-{i}" for i in range(count)]
    for aid in agent_ids:
        set_current_agent_id(aid)
        result = _run_in_bg(browser_action(action="launch", agent_state=agent_state))
        if "error" in result:
            pytest.fail(f"Browser launch failed for {aid}: {result}")

    yield [Browser(aid, agent_state) for aid in agent_ids]

    for aid in agent_ids:
        session = _manager.remove(aid)
        if session:
            _run_in_bg(session.dispose_context())
    set_current_agent_id(_SESSION_AGENT_ID)


@pytest.fixture
def browser(browsers):
    return browsers[0]


def pytest_runtest_logstart(nodeid, location):
    name = nodeid.split("::")[-1]
    ui.test_start(name)


def pytest_runtest_logreport(report):
    if report.when != "call":
        return
    name = report.nodeid.split("::")[-1]
    if report.passed:
        ui.test_passed(name)
    elif report.failed:
        ui.test_failed(name, details=report.longreprtext)


@pytest.fixture(autouse=True)
def _set_agent_context():
    set_current_agent_id(_SESSION_AGENT_ID)
