"""Copy a named sandbox markdown report into the host run directory."""

from __future__ import annotations

import io
import json
from typing import TYPE_CHECKING, Any

import pytest
from agents.sandbox.files import EntryKind, FileEntry
from agents.sandbox.types import Permissions
from agents.tool_context import ToolContext

from strix.report.state import ReportState, set_global_report_state
from strix.tools.reporting.tool import _MAX_EXPORTED_REPORT_BYTES, export_markdown_report


if TYPE_CHECKING:
    from collections.abc import Iterator
    from pathlib import Path


def _file_entry(path: str, payload: bytes, *, kind: EntryKind = EntryKind.FILE) -> FileEntry:
    return FileEntry(
        path=path,
        permissions=Permissions.from_mode(0o100644),
        owner="root",
        group="root",
        size=len(payload),
        kind=kind,
    )


class _SimpleEntry:
    def __init__(self, path: str, *, kind: str = "file", size: int | None = None) -> None:
        self.path = path
        self.kind = kind
        if size is not None:
            self.size = size


class _Sandbox:
    def __init__(
        self,
        files: dict[str, bytes],
        *,
        kinds: dict[str, EntryKind] | None = None,
        listed: dict[str, object] | None = None,
    ) -> None:
        self.files = files
        self.kinds = kinds or {}
        self.listed = listed or {}
        self.reads: list[str] = []
        self.bytes_read = 0

    async def ls(self, path: Path) -> list[object]:
        parent = path.as_posix().rstrip("/") or "/"
        entries: list[object] = []
        for file_path, payload in self.files.items():
            if file_path.rsplit("/", 1)[0] == parent:
                entries.append(
                    self.listed.get(file_path)
                    or _file_entry(
                        file_path, payload, kind=self.kinds.get(file_path, EntryKind.FILE)
                    )
                )
        return entries

    async def read(self, path: Path) -> io.BytesIO:
        self.reads.append(path.as_posix())
        payload = self.files.get(path.as_posix())
        if payload is None:
            raise FileNotFoundError(path.as_posix())

        sandbox = self

        class _CountedBytes(io.BytesIO):
            def read(self, size: int | None = -1) -> bytes:
                chunk = super().read(-1 if size is None else size)
                sandbox.bytes_read += len(chunk)
                return chunk

        return _CountedBytes(payload)


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


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("payload", "kind", "match"),
    [
        (b"", EntryKind.FILE, "empty"),
        (b"# Findings\n\x00hidden\n", EntryKind.FILE, "markdown text file"),
        (b"\xff\xfe# Findings\n", EntryKind.FILE, "UTF-8"),
        (b"x" * (_MAX_EXPORTED_REPORT_BYTES + 1), EntryKind.FILE, "exceeds"),
        (b"# Findings\n", EntryKind.SYMLINK, "symlink"),
    ],
)
async def test_rejects_empty_invalid_oversized_and_symlink_reports(
    report_state: ReportState,
    payload: bytes,
    kind: EntryKind,
    match: str,
) -> None:
    sandbox = _Sandbox({"/workspace/report.md": payload}, kinds={"/workspace/report.md": kind})

    result = await _export({"sandbox_session": sandbox}, "/workspace/report.md")

    assert result["success"] is False
    assert match in result["error"]
    assert not (report_state.get_run_dir() / "report.md").exists()
    if kind is EntryKind.SYMLINK or match in {"empty", "exceeds"}:
        assert sandbox.reads == []
    if match == "exceeds":
        assert sandbox.bytes_read == 0


@pytest.mark.asyncio
async def test_size_limit_stops_the_sandbox_read_after_one_extra_byte(
    report_state: ReportState,
) -> None:
    oversized = b"x" * (_MAX_EXPORTED_REPORT_BYTES + 64)
    sandbox = _Sandbox(
        {"/workspace/report.md": oversized},
        listed={"/workspace/report.md": _SimpleEntry("/workspace/report.md")},
    )

    result = await _export({"sandbox_session": sandbox}, "/workspace/report.md")

    assert result["success"] is False
    assert "exceeds" in result["error"]
    assert sandbox.bytes_read == _MAX_EXPORTED_REPORT_BYTES + 1
    assert not (report_state.get_run_dir() / "report.md").exists()


@pytest.mark.asyncio
async def test_same_named_exports_do_not_overwrite_an_existing_report(
    report_state: ReportState,
) -> None:
    run_dir = report_state.get_run_dir()
    (run_dir / "report.md").write_text("# first\n", encoding="utf-8")
    sandbox = _Sandbox({"/workspace/notes/report.md": b"# second\n"})

    result = await _export({"sandbox_session": sandbox}, "/workspace/notes/report.md")

    assert result["success"] is False
    assert "already exists" in result["error"]
    assert (run_dir / "report.md").read_text(encoding="utf-8") == "# first\n"
