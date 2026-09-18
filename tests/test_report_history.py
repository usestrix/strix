"""Smoke-test the prompted Git command and agent-supplied report details."""

from __future__ import annotations

import argparse
import json
import os
import re
import shlex
import subprocess
import tempfile
from pathlib import Path
from typing import TYPE_CHECKING, Any

import pytest
from agents.tool_context import ToolContext

from strix.interface.scan_setup import build_targets_info, prepare_run
from strix.report.state import ReportState, set_global_report_state
from strix.tools.reporting.tool import create_vulnerability_report, update_vulnerability_report


if TYPE_CHECKING:
    from collections.abc import Iterator


_ANALYSIS = "The query interpolates attacker-controlled input."
_FIRST_AUTHOR = "Alice Original"
_LATEST_AUTHOR = "Bea Reviewer"
_LOCAL_AUTHOR = "Carol Local"
_CVSS = {
    "attack_vector": "N",
    "attack_complexity": "L",
    "privileges_required": "N",
    "user_interaction": "N",
    "scope": "U",
    "confidentiality": "H",
    "integrity": "H",
    "availability": "H",
}


def _git(path: Path, *args: str, author: str = _FIRST_AUTHOR) -> str:
    result = subprocess.run(  # noqa: S603
        ["git", "-c", "commit.gpgsign=false", "-C", str(path), *args],  # noqa: S607
        env={
            **os.environ,
            "GIT_AUTHOR_NAME": author,
            "GIT_AUTHOR_EMAIL": "author@example.test",
            "GIT_COMMITTER_NAME": author,
            "GIT_COMMITTER_EMAIL": "committer@example.test",
            "GIT_AUTHOR_DATE": "2024-01-02T03:04:05+00:00",
            "GIT_COMMITTER_DATE": "2024-01-02T03:04:05+00:00",
        },
        check=True,
        capture_output=True,
        text=True,
    )
    return result.stdout.strip()


@pytest.fixture(autouse=True)
def _isolate_git_config(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("GIT_CONFIG_GLOBAL", os.devnull)
    monkeypatch.setenv("GIT_CONFIG_NOSYSTEM", "1")


def _seed_repository(origin: Path) -> dict[str, str]:
    origin.mkdir()
    _git(origin, "init", "--quiet")
    (origin / "app.py").write_text("query = 'initial'\nresult = query\n", encoding="utf-8")
    _git(origin, "add", "app.py")
    _git(origin, "commit", "--quiet", "-m", "Add query handler")
    first_sha = _git(origin, "rev-parse", "HEAD")
    (origin / "app.py").write_text("query = 'initial'\nresult = execute(query)\n", encoding="utf-8")
    _git(origin, "commit", "--quiet", "-am", "Execute the query", author=_LATEST_AUTHOR)
    return {"first": first_sha, "latest": _git(origin, "rev-parse", "HEAD")}


@pytest.fixture
def scan_setup_run(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> Iterator[tuple[ReportState, dict[str, str], dict[str, str]]]:
    """Build the run the way the CLI does: target inference, cloning, local sources."""
    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr(tempfile, "tempdir", str(tmp_path / "tmp"))
    commits = _seed_repository(tmp_path / "origin.git")
    repo_target = (tmp_path / "origin.git").as_uri()
    local = tmp_path / "service"
    local.mkdir()
    _git(local, "init", "--quiet")
    (local / "app.py").write_text("token = request.args['token']\n", encoding="utf-8")
    _git(local, "add", "app.py")
    _git(local, "commit", "--quiet", "-m", "Read the token", author=_LOCAL_AUTHOR)

    args = argparse.Namespace(
        target=[str(local), repo_target],
        target_list=None,
        resume=None,
        scan_mode="quick",
        scope_mode="full",
        diff_base=None,
        non_interactive=True,
        instruction="",
        user_instruction=None,
        workspace_mount=None,
        workspace_files=[],
    )
    build_targets_info(args)
    prepare_run(args)
    clone = Path(args.targets_info[1]["details"]["cloned_repo_path"])
    assert clone.is_relative_to(tmp_path / "tmp")

    state = ReportState(args.run_name)
    state.hydrate_from_run_dir()
    state.set_scan_config(
        {
            "targets": args.targets_info,
            "local_sources": args.local_sources,
            "run_name": args.run_name,
            "scope_mode": args.scope_mode,
            "non_interactive": True,
        }
    )
    set_global_report_state(state)
    try:
        yield (
            state,
            {"local": str(local.resolve()), "repository": repo_target},
            {**commits, "local": _git(local, "rev-parse", "HEAD")},
        )
    finally:
        set_global_report_state(None)


async def _create(
    location: dict[str, Any], *, target: str, technical_analysis: str
) -> dict[str, Any]:
    arguments = {
        "title": "SQL injection in the query handler",
        "description": "The query handler executes unsanitized input.",
        "impact": "An anonymous caller can access other users' records.",
        "target": target,
        "technical_analysis": technical_analysis,
        "poc_description": "Submit a quote in the query parameter.",
        "poc_script_code": "GET /query?q='",
        "remediation_steps": "Use parameterized queries.",
        "evidence": "The response includes another user's record.",
        "assumptions": "The observed database role is available in production.",
        "counterevidence": "No input validation runs before the query.",
        "confidence": "high",
        "severity_change_conditions": "A read-only database role would limit the impact.",
        "fix_effort": "low",
        "cvss_breakdown": _CVSS,
        "code_locations": [location],
    }
    context = ToolContext(
        context={"agent_id": "root"},
        tool_name="create_vulnerability_report",
        tool_call_id="create-1",
        tool_arguments=json.dumps(arguments),
    )
    result: dict[str, Any] = json.loads(
        await create_vulnerability_report.on_invoke_tool(context, json.dumps(arguments))
    )
    return result


async def _update(report_id: str, **fields: Any) -> dict[str, Any]:
    arguments = {
        "report_id": report_id,
        "update_reason": "Refined the vulnerable location.",
        **fields,
    }
    context = ToolContext(
        context={"agent_id": "root"},
        tool_name="update_vulnerability_report",
        tool_call_id="update-1",
        tool_arguments=json.dumps(arguments),
    )
    result: dict[str, Any] = json.loads(
        await update_vulnerability_report.on_invoke_tool(context, json.dumps(arguments))
    )
    return result


def test_git_attribution_guidance_lives_only_in_technical_analysis() -> None:
    description = create_vulnerability_report.description
    summary, _, args = description.partition("Args:")
    assert "blame" not in summary
    assert "Last modified by" not in summary
    field = args.split("technical_analysis:", 1)[1].split("poc_description:", 1)[0]
    for instruction in (
        "exec_command",
        "git blame",
        "primary vulnerable line",
        "start_line",
        "Last modified by",
        "committer-time",
        "all-zero SHAs",
    ):
        assert instruction in field
    assert "blame" not in update_vulnerability_report.description


@pytest.mark.parametrize(
    "case", ["primary", "start", "local", "missing", "out_of_range", "uncommitted"]
)
async def test_prompted_blame_command_to_report_artifacts(
    scan_setup_run: tuple[ReportState, dict[str, str], dict[str, str]], case: str
) -> None:
    # Exercise real CLI setup and Git, then supply the analysis as an agent would.
    # This is a tool/report smoke test, not an LLM compliance test.
    state, targets, commits = scan_setup_run
    local = case == "local"
    target = targets["local" if local else "repository"]
    checkout = Path(state.run_record["local_sources"][0 if local else 1]["source_path"])
    assert _git(checkout, "rev-parse", "--is-shallow-repository") == "false"
    file_path = "missing.py" if case == "missing" else "app.py"
    line = 999 if case == "out_of_range" else 2 if case == "primary" else 1
    if case == "uncommitted":
        (checkout / "app.py").write_text("uncommitted change\nresult = query\n", encoding="utf-8")

    # Execute the exact example exposed to the model, with quoted real paths.
    match = re.search(
        r"timeout 3s git.*?-- FILE",
        create_vulnerability_report.description,
        re.DOTALL,
    )
    assert match is not None
    command = (
        match.group()
        .replace("REPO", shlex.quote(str(checkout)))
        .replace("LINE", str(line))
        .replace("FILE", shlex.quote(file_path))
    )
    output = subprocess.run(  # noqa: S603
        ["bash", "-c", command],  # noqa: S607
        capture_output=True,
        text=True,
        timeout=5,
        check=False,
    )
    analysis = _ANALYSIS
    has_history = case in {"primary", "start", "local"}
    if has_history:
        assert output.returncode == 0
        sha = commits["local" if local else "latest" if case == "primary" else "first"]
        author = _LOCAL_AUTHOR if local else _LATEST_AUTHOR if case == "primary" else _FIRST_AUTHOR
        assert output.stdout.split()[0] == sha
        assert f"author {author}\n" in output.stdout
        assert "author-mail <author@example.test>" in output.stdout
        assert "committer-time 1704164645" in output.stdout
        summary = next(
            s.removeprefix("summary ")
            for s in output.stdout.splitlines()
            if s.startswith("summary ")
        )
        analysis += (
            f"\n\n### Last modified by\n\n{file_path}:{line} — {author} "
            f"(author@example.test); commit {sha}; "
            f"2024-01-02T03:04:05+00:00; {summary}"
        )
    elif case == "uncommitted":
        assert output.stdout.split()[0] == "0" * 40
    else:
        assert output.returncode != 0

    callbacks: list[dict[str, Any]] = []
    state.vulnerability_found_callback = lambda report: callbacks.append(dict(report))
    result = await _create(
        {"file": file_path, "start_line": 1, "end_line": 2},
        target=target,
        technical_analysis=analysis,
    )
    assert result["success"] is True
    report = state.vulnerability_reports[0]
    assert callbacks == [report]
    assert report["technical_analysis"] == analysis
    saved = json.loads((state.get_run_dir() / "vulnerabilities.json").read_text())
    assert saved == [report]
    markdown = (state.get_run_dir() / "vulnerabilities" / f"{report['id']}.md").read_text()
    assert (
        analysis in markdown.split("## Technical Analysis", 1)[1].split("## Proof of Concept", 1)[0]
    )

    if has_history:
        revised = await _update(
            report["id"],
            target="https://example.test/new-target",
            technical_analysis=_ANALYSIS,
        )
        assert revised["success"] is True
        assert state.vulnerability_reports[0]["technical_analysis"] == _ANALYSIS
