from __future__ import annotations

from types import SimpleNamespace
from typing import TYPE_CHECKING, Any, cast

from strix.mcp import service as service_module
from strix.mcp.service import StrixMCPService


if TYPE_CHECKING:
    import pytest

    from strix.report.state import ReportState


async def test_sandbox_exec_requires_active_scan() -> None:
    service = StrixMCPService()

    result = await service.sandbox_exec(["id"])

    assert result == {"success": False, "error": "Call start_scan first"}


async def test_sandbox_exec_returns_decoded_result() -> None:
    class Session:
        async def exec(self, *args: str, timeout: int) -> Any:
            assert args == ("printf", "ok")
            assert timeout == 10
            return SimpleNamespace(
                ok=lambda: True,
                exit_code=0,
                stdout=b"ok",
                stderr=b"",
            )

    service = StrixMCPService()
    service.bundle = {"session": Session()}

    result = await service.sandbox_exec(["printf", "ok"], timeout=10)

    assert result == {"success": True, "exit_code": 0, "stdout": "ok", "stderr": ""}


async def test_create_finding_forces_model_free_dedupe(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    captured: dict[str, Any] = {}

    async def fake_create(**kwargs: Any) -> dict[str, bool]:
        captured.update(kwargs)
        return {"success": True}

    monkeypatch.setattr(service_module, "_do_create", fake_create)
    service = StrixMCPService()
    service.report_state = cast("ReportState", SimpleNamespace())

    result = await service.create_finding(title="Verified issue")

    assert result == {"success": True}
    assert captured["allow_model_dedupe"] is False
    assert captured["agent_id"] == "coding-agent"


def test_load_knowledge_returns_scan_mode() -> None:
    service = StrixMCPService()

    result = service.load_knowledge("scan_modes/quick")

    assert result["success"] is True
    assert "quick" in result["content"].lower()
