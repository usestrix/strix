"""Copy a named sandbox markdown report into the host run directory."""

from __future__ import annotations

import io
import json
from collections.abc import Iterator
from typing import TYPE_CHECKING, Any

import pytest
from agents.tool_context import ToolContext

from strix.report.state import ReportState, set_global_report_state
from strix.tools.reporting.tool import export_markdown_report


if TYPE_CHECKING:
    from pathlib import Path


class _Sandbox:
    def __init__(self, files: dict[str, bytes]) -> None:
        self.files = files
        self.reads: list[str] = []

    async def read(self, path: Path) -> io.BytesIO:
        self.reads.append(path.as_posix())
        payload = self.files.get(path.as_posix())
        if payload is None:
            raise FileNotFoundError(path.as_posix())
        return io.BytesIO(payload)


@pytest.fixture
def report_state(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Iterator[ReportState]:
    monkeypatch.chdir(tmp_path)
    state = ReportState(run_name="test-run")
    set_global_report_state(state)
    yield state
    set_global_report_state(None)


async def _export(context: dict[str, Any], path: str) -> dict[str, Any]:
    ctx = ToolContext(
        context=context,
        tool_name="export_markdown_report",
        tool_call_id="call-1",
        tool_arguments="{}",
    )
    raw = await export_markdown_report.on_invoke_tool(ctx, json.dumps({"path": path}))
    return json.loads(raw)  # type: ignore[no-any-return]


@pytest.mark.asyncio
async def test_copies_named_markdown_beside_existing_run_artifacts(
    report_state: ReportState,
) -> None:
    run_dir = report_state.get_run_dir()
    (run_dir / "findings.sarif").write_text("{}", encoding="utf-8")
    (run_dir / "penetration_test_report.md").write_text("# executive\n", encoding="utf-8")
    sandbox = _Sandbox({"/workspace/notes/report.md": b"# Findings\n\nUse the patch.\n"})

    result = await _export(
        {"sandbox_session": sandbox},
        "/workspace/notes/report.md",
    )

    exported = run_dir / "report.md"
    assert result["success"] is True
    assert result["filename"] == "report.md"
    assert sandbox.reads == ["/workspace/notes/report.md"]
    assert exported.read_text(encoding="utf-8") == "# Findings\n\nUse the patch.\n"
    assert (run_dir / "findings.sarif").read_text(encoding="utf-8") == "{}"
    assert (run_dir / "penetration_test_report.md").read_text(encoding="utf-8") == "# executive\n"


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "path",
    [
        "/etc/report.md",
        "/workspace/../report.md",
        "/workspace/notes.txt",
        "/workspace/penetration_test_report.md",
        "report.md",
    ],
)
async def test_rejects_paths_outside_a_named_workspace_markdown_file(
    report_state: ReportState,
    path: str,
) -> None:
    sandbox = _Sandbox({"/workspace/report.md": b"# ok\n"})

    result = await _export({"sandbox_session": sandbox}, path)

    assert result["success"] is False
    assert sandbox.reads == []
    assert not (report_state.get_run_dir() / "report.md").exists()
    assert not (report_state.get_run_dir() / "penetration_test_report.md").exists()
