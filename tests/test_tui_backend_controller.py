from __future__ import annotations

import argparse
import asyncio
import json
import os
from typing import TYPE_CHECKING

import pytest

from strix.config import (
    ProviderModelGroup,
    apply_config_override,
    clear_provider_credentials_invalid,
    mark_provider_credentials_invalid,
    read_config_env,
    reset_settings_cache,
)
from strix.interface.tui_backend.controller import TuiController


if TYPE_CHECKING:
    from pathlib import Path


def args() -> argparse.Namespace:
    return argparse.Namespace(needs_setup=True, targets_info=[], instruction=None)


@pytest.fixture(autouse=True)
def isolated_config(tmp_path: Path) -> None:
    for key in (
        "STRIX_LLM",
        "OPENAI_API_KEY",
        "ANTHROPIC_API_KEY",
        "LLM_API_KEY",
        "LLM_API_BASE",
        "AZURE_API_KEY",
        "AZURE_API_BASE",
        "AZURE_API_VERSION",
    ):
        os.environ.pop(key, None)
    apply_config_override(tmp_path / "config.json")
    for provider in ("openai", "anthropic", "azure"):
        clear_provider_credentials_invalid(provider)
    reset_settings_cache()


@pytest.mark.asyncio
async def test_setup_state_is_serializable() -> None:
    controller = TuiController(args())
    await controller.handle("setup.add_target", {"target": "https://example.com"})
    await controller.handle("setup.set_instruction", {"instruction": "focus on auth"})
    snapshot = controller.snapshot()
    assert snapshot["targets"] == ["https://example.com"]
    assert snapshot["instruction"] == "focus on auth"
    assert snapshot["scan_state"] == "setup"
    assert snapshot["scan_mode"] == "deep"


@pytest.mark.asyncio
async def test_setup_instruction_starts_from_cli_and_can_be_cleared() -> None:
    setup_args = args()
    setup_args.instruction = "  CLI instruction  "
    controller = TuiController(setup_args)

    assert controller.snapshot()["instruction"] == "CLI instruction"

    result = await controller.handle("setup.set_instruction", {"instruction": ""})

    assert result == {"instruction": ""}
    assert controller.snapshot()["instruction"] == ""


@pytest.mark.asyncio
async def test_scan_mode_is_validated_and_saved_in_setup_state() -> None:
    controller = TuiController(args())

    result = await controller.handle("setup.set_mode", {"mode": "quick"})

    assert result == {"mode": "quick"}
    assert controller.snapshot()["scan_mode"] == "quick"
    with pytest.raises(ValueError, match="quick, standard, deep"):
        await controller.handle("setup.set_mode", {"mode": "invalid"})


def test_saved_model_restores_provider() -> None:
    os.environ["STRIX_LLM"] = "litellm/anthropic/claude-sonnet-4"
    reset_settings_cache()

    controller = TuiController(args())

    assert controller.snapshot()["provider"] == "anthropic"


def test_state_populates_model_warning_for_non_frontier_model() -> None:
    os.environ["STRIX_LLM"] = "openai/gpt-3.5-turbo"
    reset_settings_cache()

    warning = TuiController(args()).snapshot()["model_warning"]

    assert "openai/gpt-3.5-turbo" in warning
    assert "not a recommended frontier model" in warning


def test_setup_restores_prepared_cli_targets() -> None:
    setup_args = args()
    setup_args.targets_info = [
        {"type": "web", "details": {}, "original": "https://example.com"},
        {"type": "local_code", "details": {}, "original": "/workspace/source"},
    ]

    controller = TuiController(setup_args)

    assert controller.snapshot()["targets"] == ["https://example.com", "/workspace/source"]


@pytest.mark.asyncio
async def test_start_validates_model_before_callback() -> None:
    started = False

    async def start() -> None:
        nonlocal started
        started = True

    controller = TuiController(args(), on_start=start)
    await controller.handle("setup.add_target", {"target": "https://example.com"})
    with pytest.raises(ValueError, match="No model configured"):
        await controller.handle("setup.start", {})
    assert started is False


@pytest.mark.asyncio
async def test_start_resolves_routed_model_provider() -> None:
    started = False

    async def start() -> None:
        nonlocal started
        started = True

    os.environ["STRIX_LLM"] = "litellm/anthropic/claude-sonnet-4"
    os.environ["ANTHROPIC_API_KEY"] = "test-key"
    reset_settings_cache()
    controller = TuiController(args(), on_start=start)
    await controller.handle("setup.add_target", {"target": "https://example.com"})

    result = await controller.handle("setup.start", {})

    assert result == {"started": True}
    assert started is True


@pytest.mark.asyncio
async def test_start_rejects_concurrent_and_repeated_submissions() -> None:
    entered = asyncio.Event()
    release = asyncio.Event()

    async def start() -> None:
        entered.set()
        await release.wait()

    os.environ["STRIX_LLM"] = "anthropic/claude-sonnet-4"
    os.environ["ANTHROPIC_API_KEY"] = "test-key"
    reset_settings_cache()
    controller = TuiController(args(), on_start=start)
    await controller.handle("setup.add_target", {"target": "https://example.com"})

    first_start = asyncio.create_task(controller.handle("setup.start", {}))
    await entered.wait()
    with pytest.raises(RuntimeError, match="already starting or running"):
        await controller.handle("setup.start", {})
    release.set()
    await first_start
    with pytest.raises(RuntimeError, match="already starting or running"):
        await controller.handle("setup.start", {})


@pytest.mark.asyncio
@pytest.mark.parametrize("status", ["completed", "failed", "crashed", "stopped"])
async def test_stop_rejects_terminal_agents(status: str) -> None:
    class Coordinator:
        def __init__(self) -> None:
            self.calls: list[str] = []

        async def cancel_descendants_graceful(self, agent_id: str) -> bool:
            self.calls.append(agent_id)
            return True

    coordinator = Coordinator()
    controller = TuiController(args(), coordinator=coordinator)
    controller.set_runtime(scan_loop=asyncio.get_running_loop())
    controller.live_view.upsert_agent("agent-1", name="Agent", status=status)

    with pytest.raises(RuntimeError, match=f"cannot be stopped while {status}"):
        await controller.handle("agent.stop", {"agent_id": "agent-1"})

    assert coordinator.calls == []


@pytest.mark.asyncio
@pytest.mark.parametrize("status", ["running", "waiting", "budget_paused"])
async def test_stop_allows_active_agents(status: str) -> None:
    class Coordinator:
        def __init__(self) -> None:
            self.calls: list[str] = []

        async def cancel_descendants_graceful(self, agent_id: str) -> bool:
            self.calls.append(agent_id)
            return True

    coordinator = Coordinator()
    controller = TuiController(args(), coordinator=coordinator)
    controller.set_runtime(scan_loop=asyncio.get_running_loop())
    controller.live_view.upsert_agent("agent-1", name="Agent", status=status)

    result = await controller.handle("agent.stop", {"agent_id": "agent-1"})

    assert result == {"stopped": True}
    assert coordinator.calls == ["agent-1"]


@pytest.mark.asyncio
async def test_stop_handles_coordinator_rejection_after_stale_active_projection() -> None:
    class Coordinator:
        async def cancel_descendants_graceful(self, _agent_id: str) -> bool:
            return False

    controller = TuiController(args(), coordinator=Coordinator())
    controller.set_runtime(scan_loop=asyncio.get_running_loop())
    controller.live_view.upsert_agent("agent-1", name="Agent", status="running")

    with pytest.raises(RuntimeError, match="no longer active"):
        await controller.handle("agent.stop", {"agent_id": "agent-1"})


@pytest.mark.asyncio
async def test_unknown_command_is_rejected() -> None:
    controller = TuiController(args())
    with pytest.raises(ValueError, match="Unknown command"):
        await controller.handle("nope", {})


@pytest.mark.asyncio
async def test_custom_provider_flow_accepts_manual_model_and_optional_key() -> None:
    controller = TuiController(args())

    added = await controller.handle(
        "setup.add_custom_provider",
        {
            "name": "Local vLLM",
            "api_base": "http://localhost:8000",
            "api_key": "",
            "kind": "vllm",
        },
    )
    provider = added["provider"]
    selected = await controller.handle(
        "setup.select_model",
        {"provider": provider, "model": f"{provider}/local-model"},
    )

    assert added["label"] == "Local vLLM"
    assert selected == {"model": f"{provider}/local-model"}
    assert read_config_env()["STRIX_LLM"] == f"{provider}/local-model"
    providers = await controller.handle("providers.list", {})
    assert providers["providers"][-1]["name"] == "__add_custom__"


@pytest.mark.asyncio
async def test_disconnected_custom_provider_remains_listable() -> None:
    controller = TuiController(args())
    added = await controller.handle(
        "setup.add_custom_provider",
        {
            "name": "Local vLLM",
            "api_base": "http://localhost:8000",
            "api_key": "",
            "kind": "vllm",
        },
    )

    disconnected = await controller.handle(
        "setup.disconnect_provider",
        {"provider": added["provider"]},
    )
    providers = await controller.handle("providers.list", {})
    row = next(item for item in providers["providers"] if item["name"] == added["provider"])

    assert disconnected == row
    assert row["configured"] is False
    assert row["key_env"] is None
    assert row["custom"] is True
    assert row["state"] == "missing"
    assert row["detail"] == "disconnected; select to reconnect"
    assert row["source"] is None
    assert row["disconnectable"] is False


@pytest.mark.asyncio
async def test_provider_configuration_does_not_change_selected_model() -> None:
    os.environ["STRIX_LLM"] = "openai/gpt-5.4"
    os.environ["OPENAI_API_KEY"] = "openai-key"
    reset_settings_cache()
    controller = TuiController(args())

    result = await controller.handle("setup.select_provider", {"provider": "anthropic"})
    await controller.handle(
        "setup.save_api_key",
        {"provider": "anthropic", "api_key": "anthropic-key"},
    )

    assert result["configured"] is False
    assert controller.snapshot()["model"] == "openai/gpt-5.4"
    assert controller.snapshot()["provider"] == "openai"


@pytest.mark.asyncio
async def test_disconnect_provider_keeps_selected_model() -> None:
    os.environ["STRIX_LLM"] = "openai/gpt-5.4"
    os.environ["OPENAI_API_KEY"] = "openai-key"
    reset_settings_cache()
    controller = TuiController(args())
    await controller.handle(
        "setup.save_api_key",
        {"provider": "anthropic", "api_key": "anthropic-key"},
    )

    result = await controller.handle(
        "setup.disconnect_provider",
        {"provider": "anthropic"},
    )

    assert result["configured"] is False
    assert result["disconnectable"] is False
    assert result["source"] is None
    assert controller.snapshot()["model"] == "openai/gpt-5.4"
    assert controller.snapshot()["provider"] == "openai"


@pytest.mark.asyncio
async def test_rejected_saved_key_opens_replacement_flow() -> None:
    controller = TuiController(args())
    await controller.handle(
        "setup.save_api_key",
        {"provider": "anthropic", "api_key": "wrong-key"},
    )
    mark_provider_credentials_invalid("anthropic")

    invalid = await controller.handle(
        "setup.select_provider",
        {"provider": "anthropic"},
    )
    replacement = await controller.handle(
        "setup.save_api_key",
        {"provider": "anthropic", "api_key": "replacement-key"},
    )

    assert invalid["state"] == "invalid"
    assert invalid["configured"] is False
    assert invalid["key_env"] == "ANTHROPIC_API_KEY"
    assert replacement["state"] == "configured"
    assert replacement["configured"] is True


@pytest.mark.asyncio
async def test_rejected_environment_key_is_not_editable_in_tui(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("ANTHROPIC_API_KEY", "wrong-environment-key")
    mark_provider_credentials_invalid("anthropic")
    controller = TuiController(args())

    result = await controller.handle(
        "setup.select_provider",
        {"provider": "anthropic"},
    )

    assert result["state"] == "invalid"
    assert result["source"] == "env"
    assert result["key_env"] is None


@pytest.mark.asyncio
async def test_models_list_returns_aggregate_groups(monkeypatch: pytest.MonkeyPatch) -> None:
    async def groups(*, current_model: str | None = None) -> list[ProviderModelGroup]:
        assert current_model == "openai/gpt-5.4"
        return [
            ProviderModelGroup("openai", "OpenAI", ("openai/gpt-5.4",)),
            ProviderModelGroup(
                "custom-id",
                "Local",
                (),
                allow_manual=True,
                error="offline",
            ),
        ]

    os.environ["STRIX_LLM"] = "openai/gpt-5.4"
    reset_settings_cache()
    monkeypatch.setattr(
        "strix.interface.tui_backend.controller.configured_provider_model_groups",
        groups,
    )
    controller = TuiController(args())

    result = await controller.handle("models.list", {})

    assert result["cursor"] == 0
    assert result["next_cursor"] == 1
    assert result["done"] is True
    assert result["providers"] == []
    assert result["groups"] == [
        {
            "provider": "openai",
            "label": "OpenAI",
            "models": ["openai/gpt-5.4"],
            "allow_manual": False,
            "error": "",
        },
        {
            "provider": "custom-id",
            "label": "Local",
            "models": [],
            "allow_manual": True,
            "error": "offline",
        },
    ]


@pytest.mark.asyncio
async def test_models_list_pages_one_immutable_snapshot_under_command_limit(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    calls = 0
    models = tuple(f"openai/model-{index}-{'x' * 900}" for index in range(180))

    async def groups(*, current_model: str | None = None) -> list[ProviderModelGroup]:
        nonlocal calls
        assert current_model == ""
        calls += 1
        return [ProviderModelGroup("openai", "OpenAI", models)]

    monkeypatch.setattr(
        "strix.interface.tui_backend.controller.configured_provider_model_groups",
        groups,
    )
    controller = TuiController(args())

    page = await controller.handle("models.list", {})
    listing_id = page["listing_id"]
    first_page_models = list(page["groups"][0]["models"])
    page["groups"][0]["models"].append("caller-mutation")
    repeated = await controller.handle(
        "models.list",
        {"listing_id": listing_id, "cursor": 0},
    )
    assert repeated["groups"][0]["models"] == first_page_models
    page = repeated
    received: list[str] = []
    pages = 0
    while True:
        pages += 1
        assert page["listing_id"] == listing_id
        assert len(json.dumps(page, separators=(",", ":")).encode()) < 64 * 1024
        for group in page["groups"]:
            received.extend(group["models"])
        if page["done"]:
            break
        page = await controller.handle(
            "models.list",
            {"listing_id": listing_id, "cursor": page["next_cursor"]},
        )

    assert pages > 1
    assert tuple(received) == models
    assert calls == 1


@pytest.mark.asyncio
async def test_models_list_rejects_expired_snapshot(monkeypatch: pytest.MonkeyPatch) -> None:
    models = tuple(f"openai/model-{index}-{'x' * 900}" for index in range(100))

    async def groups(*, current_model: str | None = None) -> list[ProviderModelGroup]:
        assert current_model == ""
        return [ProviderModelGroup("openai", "OpenAI", models)]

    now = 100.0
    monkeypatch.setattr(
        "strix.interface.tui_backend.controller.configured_provider_model_groups",
        groups,
    )
    monkeypatch.setattr("strix.interface.tui_backend.controller.time.monotonic", lambda: now)
    controller = TuiController(args())
    first = await controller.handle("models.list", {})
    now += 61

    with pytest.raises(ValueError, match="expired or is unknown"):
        await controller.handle(
            "models.list",
            {"listing_id": first["listing_id"], "cursor": first["next_cursor"]},
        )


def test_setup_recovery_messages_are_sanitized_and_agents_are_collection_only() -> None:
    setup_args = args()
    setup_args.setup_invalid_provider = "anthropic\x1b[31m"
    setup_args.setup_guidance = "replace\x1b]52;c;Y2xpcA==\x07 key\x85"
    controller = TuiController(setup_args)
    for index in range(40):
        controller.live_view.upsert_agent(f"agent-{index}", name=f"Agent {index}")

    snapshot = controller.snapshot()

    assert "agents" not in snapshot
    assert [message["text"] for message in snapshot["messages"]] == [
        "Provider requiring setup: anthropic",
        "replace key",
    ]
    assert len(controller.collection("agents")) == 40


@pytest.mark.asyncio
async def test_models_list_returns_provider_rows_when_none_are_connected(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    async def groups(*, current_model: str | None = None) -> list[ProviderModelGroup]:
        assert current_model == ""
        return []

    async def providers(_payload: dict[str, object]) -> dict[str, object]:
        return {
            "providers": [
                {
                    "name": "anthropic",
                    "label": "Anthropic",
                    "configured": False,
                }
            ]
        }

    monkeypatch.setattr(
        "strix.interface.tui_backend.controller.configured_provider_model_groups",
        groups,
    )
    controller = TuiController(args())
    monkeypatch.setattr(controller, "_providers", providers)

    result = await controller.handle("models.list", {})

    assert result["groups"] == []
    assert result["providers"] == [{"name": "anthropic", "label": "Anthropic", "configured": False}]
    assert result["done"] is True


@pytest.mark.asyncio
async def test_manual_deployment_model_is_accepted_for_builtin_provider(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("AZURE_API_KEY", "azure-key")
    monkeypatch.setenv("AZURE_API_BASE", "https://example.openai.azure.com")
    monkeypatch.setenv("AZURE_API_VERSION", "2025-11-01-preview")
    controller = TuiController(args())

    result = await controller.handle(
        "setup.select_model",
        {"provider": "azure", "model": "azure/my-private-deployment"},
    )

    assert result == {"model": "azure/my-private-deployment"}
    assert read_config_env()["STRIX_LLM"] == "azure/my-private-deployment"


@pytest.mark.asyncio
async def test_custom_provider_flow_requires_url() -> None:
    controller = TuiController(args())

    with pytest.raises(ValueError, match="api_base must be a non-empty string"):
        await controller.handle(
            "setup.add_custom_provider",
            {"name": "Broken", "api_base": "", "api_key": "", "kind": "openai"},
        )


@pytest.mark.asyncio
async def test_existing_viewer_is_reopened_and_closed(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    opened: list[str] = []

    class ViewerServer:
        shutdown_called = False
        close_called = False

        def shutdown(self) -> None:
            self.shutdown_called = True

        def server_close(self) -> None:
            self.close_called = True

    controller = TuiController(args())
    controller.viewer_status = "running"
    controller.viewer_url = "http://127.0.0.1:1234/?token=test"
    server = ViewerServer()
    controller._viewer_httpd = server
    monkeypatch.setattr("strix.interface.tui_backend.controller.webbrowser.open", opened.append)

    result = await controller.handle("viewer.open", {})
    controller.close_viewer()

    assert result == {"status": "running", "url": controller.viewer_url}
    assert opened == [controller.viewer_url]
    assert server.shutdown_called is True
    assert server.close_called is True
