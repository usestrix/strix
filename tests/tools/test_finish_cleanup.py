from typing import Any

from strix.tools.finish.finish_actions import finish_scan


class FakeTracer:
    def __init__(self) -> None:
        self.vulnerability_reports: list[dict[str, Any]] = []
        self.captured: dict[str, str] = {}

    def update_scan_final_fields(
        self,
        executive_summary: str,
        methodology: str,
        technical_analysis: str,
        recommendations: str,
        cleanup_summary: str,
    ) -> None:
        self.captured = {
            "executive_summary": executive_summary,
            "methodology": methodology,
            "technical_analysis": technical_analysis,
            "recommendations": recommendations,
            "cleanup_summary": cleanup_summary,
        }


def test_finish_scan_requires_cleanup_summary() -> None:
    result = finish_scan(
        executive_summary="Summary",
        methodology="Methodology",
        technical_analysis="Analysis",
        recommendations="Recommendations",
        cleanup_summary="",
        agent_state=None,
    )

    assert result["success"] is False
    assert "Cleanup summary cannot be empty" in result["errors"]


def test_finish_scan_persists_cleanup_summary(monkeypatch: Any) -> None:
    tracer = FakeTracer()
    monkeypatch.setattr("strix.telemetry.tracer.get_global_tracer", lambda: tracer)

    result = finish_scan(
        executive_summary="Summary",
        methodology="Methodology",
        technical_analysis="Analysis",
        recommendations="Recommendations",
        cleanup_summary="Deleted test account",
        agent_state=None,
    )

    assert result["success"] is True
    assert result["cleanup_summary"] == "Deleted test account"
    assert tracer.captured["cleanup_summary"] == "Deleted test account"
