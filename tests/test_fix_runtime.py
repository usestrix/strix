from __future__ import annotations

import inspect
import subprocess
from typing import TYPE_CHECKING

import pytest


if TYPE_CHECKING:
    from pathlib import Path
from strix.fix import (
    CandidateLocation,
    CommandSpec,
    FixCandidateV1,
    FixEdit,
    FixPreparationRequestV1,
    ReproductionSpec,
    SourceIdentity,
    SourceIdentityKind,
)
from strix.fix import runtime as fix_runtime


def _git(workspace: Path, *args: str) -> str:
    result = subprocess.run(  # noqa: S603
        ["/usr/bin/git", *args],
        cwd=workspace,
        check=True,
        capture_output=True,
        text=True,
    )
    return result.stdout.strip()


def _workspace(tmp_path: Path) -> tuple[Path, str]:
    workspace = tmp_path / "repository"
    workspace.mkdir()
    _git(workspace, "init")
    (workspace / "app.py").write_text("def result():\n    return 'unsafe'\n", encoding="utf-8")
    _git(workspace, "add", "app.py")
    _git(
        workspace,
        "-c",
        "user.name=Strix Test",
        "-c",
        "user.email=strix@example.com",
        "commit",
        "-m",
        "fixture",
    )
    return workspace, _git(workspace, "rev-parse", "HEAD")


def _request(commit: str) -> FixPreparationRequestV1:
    candidate = FixCandidateV1(
        source_identity=SourceIdentity(
            kind=SourceIdentityKind.COMMIT,
            value=commit,
        ),
        security_invariant="The function must return the safe value.",
        finding_locations=[
            CandidateLocation(
                file="app.py",
                start_line=2,
                end_line=2,
                snippet="    return 'unsafe'",
            )
        ],
        draft_edits=[
            FixEdit(
                file="app.py",
                start_line=2,
                end_line=2,
                before="    return 'unsafe'",
                after="    return 'safe'",
            )
        ],
        reproduction=ReproductionSpec(
            instructions="Confirm that the function returns the safe value.",
            command=CommandSpec(
                name="security reproduction",
                argv=[
                    "/usr/bin/python3",
                    "-c",
                    "from app import result; assert result() == 'safe'",
                ],
            ),
        ),
    )
    return FixPreparationRequestV1(
        scan_id="scan-1",
        finding_id="finding-1",
        candidate=candidate,
        checks=[
            CommandSpec(
                name="repository check",
                argv=["/usr/bin/python3", "-m", "compileall", "app.py"],
            )
        ],
    )


def test_run_fix_preparation_requires_sandbox() -> None:
    parameter = inspect.signature(fix_runtime.run_fix_preparation).parameters["sandbox_session"]
    assert parameter.default is inspect.Parameter.empty


def test_role_budgets_default_and_legacy_override() -> None:
    request = _request("a" * 40)
    assert (request.repair_turn_limit, request.review_turn_limit) == (300, 250)
    request.max_agent_turns = 100
    assert (request.repair_turn_limit, request.review_turn_limit) == (100, 100)
    request.max_repair_turns = 180
    request.max_review_turns = 80
    assert (request.repair_turn_limit, request.review_turn_limit) == (180, 80)
    restored = FixPreparationRequestV1.model_validate_json(request.model_dump_json())
    assert (restored.repair_turn_limit, restored.review_turn_limit) == (180, 80)


def test_runtime_rejects_repository_metadata_paths(tmp_path: Path) -> None:
    workspace = tmp_path / "repository"
    (workspace / ".git").mkdir(parents=True)
    environment = fix_runtime._RuntimeEnvironment(
        workspace=workspace,
    )

    with pytest.raises(ValueError, match="repository source"):
        environment.resolve(".git/config")
