"""Run-scoped safety enforcement."""

from __future__ import annotations

import asyncio
import hashlib
import io
import json
from types import SimpleNamespace
from typing import TYPE_CHECKING, Any

import pytest

import strix.tools.proxy.tools as proxy_tools
from strix.config.settings import SafetySettings
from strix.safety.evidence import EvidenceBundle
from strix.safety.runtime import SafetyRuntime
from strix.safety.types import SafetyApprovalCallback, SafetyApprovalRequest, SafetyDecision


if TYPE_CHECKING:
    from pathlib import Path


_SNAPSHOT_HISTORY: list[dict[str, Any]] = [
    {
        "type": "function_call",
        "name": "exec_command",
        "call_id": "snapshot-1",
        "arguments": '{"cmd":"agent-browser snapshot -i"}',
    },
    {
        "type": "function_call_output",
        "call_id": "snapshot-1",
        "output": '@e3 [button type="submit"] "Search"',
    },
]


class _InspectionRunner:
    async def run(self, *, evidence_dir: str, script: str) -> str:
        return f"unused: {evidence_dir} {script}"


class _StubReviewer:
    """Stands in for the model review so a decision's source can be asserted."""

    def __init__(
        self,
        on_review: Any = None,
        decision: SafetyDecision | None = None,
    ) -> None:
        self.on_review = on_review
        self.decision = decision
        self.calls = 0
        self.human_approval_available: list[bool] = []

    async def review(
        self,
        bundle: Any,
        *,
        human_approval_available: bool = False,
        workspace_collector: Any = None,
    ) -> SafetyDecision:
        del workspace_collector
        self.calls += 1
        self.human_approval_available.append(human_approval_available)
        if self.on_review is not None:
            await self.on_review()
        if self.decision is not None:
            return SafetyDecision(
                allowed=self.decision.allowed,
                source=self.decision.source,
                reason=self.decision.reason,
                categories=self.decision.categories,
                case_id=bundle.case_id,
                risk=self.decision.risk,
                deferred=self.decision.deferred,
            )
        return SafetyDecision(
            allowed=True,
            source="reviewer",
            reason="allowed",
            case_id=bundle.case_id,
        )


def _runtime(
    tmp_path: Path,
    mode: str,
    approval_callback: SafetyApprovalCallback | None = None,
) -> SafetyRuntime:
    return SafetyRuntime(
        scan_id="scan-1",
        mode=mode,  # type: ignore[arg-type]
        scope={},
        user_instruction="",
        settings=SafetySettings(),
        run_dir=tmp_path,
        sandbox_image="image",
        inspection_runner=_InspectionRunner(),
        approval_callback=approval_callback,
    )


def _deferred() -> SafetyDecision:
    return SafetyDecision(
        allowed=False,
        source="reviewer",
        reason="the endpoint effect is ambiguous",
        categories=("ambiguous_effect",),
        risk="medium",
        deferred=True,
    )


def _ctx(
    *,
    agent_id: str = "agent-1",
    turn_input: list[dict[str, Any]] | None = None,
    coordinator: Any = None,
) -> Any:
    context = {"agent_id": agent_id, "sandbox_session": object()}
    if coordinator is not None:
        context["coordinator"] = coordinator
    return SimpleNamespace(
        context=context,
        tool_call_id="call-1",
        turn_input=turn_input or [],
    )


@pytest.mark.asyncio
async def test_known_read_command_executes_without_model_review(tmp_path: Path) -> None:
    seen: list[dict[str, Any]] = []

    async def invoke(_ctx: Any, raw_input: str) -> str:
        seen.append(json.loads(raw_input))
        return "ok"

    result = await _runtime(tmp_path, "guarded").invoke_exec(
        ctx=_ctx(),
        arguments={"cmd": "ls /workspace"},
        invoke_tool=invoke,
    )

    assert result == "ok"
    assert seen == [{"cmd": "ls /workspace"}]


@pytest.mark.asyncio
async def test_browser_sessions_are_disjoint_per_agent(tmp_path: Path) -> None:
    seen: list[str] = []

    async def invoke(_ctx: Any, raw_input: str) -> str:
        seen.append(json.loads(raw_input)["cmd"])
        return "snapshot"

    runtime = _runtime(tmp_path, "guarded")
    for agent_id in ("agent-1", "agent-2"):
        result = await runtime.invoke_exec(
            ctx=_ctx(agent_id=agent_id),
            arguments={"cmd": "agent-browser snapshot -i"},
            invoke_tool=invoke,
        )
        assert result == "snapshot"

    assert seen == [
        "AGENT_BROWSER_SESSION=strix-scan-1-agent-1 agent-browser snapshot -i",
        "AGENT_BROWSER_SESSION=strix-scan-1-agent-2 agent-browser snapshot -i",
    ]


@pytest.mark.asyncio
async def test_active_browser_action_reaches_the_reviewer(
    tmp_path: Path,
) -> None:
    runtime = _runtime(tmp_path, "guarded")
    reviewer = _StubReviewer()
    runtime._reviewer = reviewer

    async def invoke(_ctx: Any, _raw_input: str) -> str:
        return "clicked"

    result = await runtime.invoke_exec(
        ctx=_ctx(turn_input=_SNAPSHOT_HISTORY),
        arguments={"cmd": "agent-browser click @e3"},
        invoke_tool=invoke,
    )

    assert result == "clicked"
    assert reviewer.calls == 1


@pytest.mark.asyncio
async def test_passive_browser_read_keeps_the_fast_path(tmp_path: Path) -> None:
    async def invoke(_ctx: Any, _raw_input: str) -> str:
        return "snapshot"

    runtime = _runtime(tmp_path, "guarded")
    reviewer = _StubReviewer()
    runtime._reviewer = reviewer
    result = await runtime.invoke_exec(
        ctx=_ctx(),
        arguments={"cmd": "agent-browser snapshot -i"},
        invoke_tool=invoke,
    )

    assert result == "snapshot"
    assert reviewer.calls == 0


@pytest.mark.asyncio
async def test_repeat_request_without_id_fails_closed(tmp_path: Path) -> None:
    async def invoke(_ctx: Any, _raw_input: str) -> str:
        return "bad"

    result = await _runtime(tmp_path, "guarded").invoke_mutating_tool(
        ctx=_ctx(),
        tool_name="repeat_request",
        raw_input="{}",
        invoke_tool=invoke,
    )

    payload = json.loads(result)
    assert payload["status"] == "blocked"
    assert "request_id" in payload["safety"]["reason"]


def _patch_resolver(monkeypatch: pytest.MonkeyPatch, effective: dict[str, Any] | None) -> None:
    async def _resolve(_ctx: Any, _request_id: str, _modifications: dict[str, Any]) -> Any:
        return effective

    monkeypatch.setattr(proxy_tools, "resolve_effective_request_for_ctx", _resolve)


@pytest.mark.asyncio
async def test_repeat_request_is_reviewed_and_sent_when_allowed(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _patch_resolver(
        monkeypatch,
        {"method": "GET", "url": "https://target.test/health", "headers": {}, "body": ""},
    )
    runtime = _runtime(tmp_path, "guarded")
    reviewer = _StubReviewer(
        decision=SafetyDecision(allowed=True, source="reviewer", reason="read-only GET")
    )
    runtime._reviewer = reviewer
    sent: list[str] = []

    async def invoke(_ctx: Any, raw_input: str) -> str:
        sent.append(raw_input)
        return "response"

    raw = json.dumps({"request_id": "req-1", "modifications": {}})
    result = await runtime.invoke_mutating_tool(
        ctx=_ctx(), tool_name="repeat_request", raw_input=raw, invoke_tool=invoke
    )

    assert result == "response"
    assert sent == [raw]
    assert reviewer.calls == 1


@pytest.mark.asyncio
async def test_repeat_request_blocked_by_reviewer_is_not_sent(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _patch_resolver(
        monkeypatch,
        {"method": "DELETE", "url": "https://target.test/api/users/1", "headers": {}, "body": ""},
    )
    runtime = _runtime(tmp_path, "guarded")
    runtime._reviewer = _StubReviewer(
        decision=SafetyDecision(
            allowed=False, source="reviewer", reason="DELETE removes target state"
        )
    )
    sent: list[str] = []

    async def invoke(_ctx: Any, raw_input: str) -> str:
        sent.append(raw_input)
        return "response"

    result = await runtime.invoke_mutating_tool(
        ctx=_ctx(),
        tool_name="repeat_request",
        raw_input=json.dumps({"request_id": "req-1"}),
        invoke_tool=invoke,
    )

    assert json.loads(result)["status"] == "blocked"
    assert sent == []


@pytest.mark.asyncio
async def test_repeat_request_unresolvable_fails_closed_without_review(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _patch_resolver(monkeypatch, None)
    runtime = _runtime(tmp_path, "guarded")
    reviewer = _StubReviewer(decision=SafetyDecision(allowed=True, source="reviewer", reason="x"))
    runtime._reviewer = reviewer
    sent: list[str] = []

    async def invoke(_ctx: Any, raw_input: str) -> str:
        sent.append(raw_input)
        return "response"

    result = await runtime.invoke_mutating_tool(
        ctx=_ctx(),
        tool_name="repeat_request",
        raw_input=json.dumps({"request_id": "gone"}),
        invoke_tool=invoke,
    )

    payload = json.loads(result)
    assert payload["status"] == "blocked"
    assert "could not be resolved" in payload["safety"]["reason"]
    assert reviewer.calls == 0
    assert sent == []


@pytest.mark.asyncio
async def test_deferred_repeat_request_prompts_with_its_own_tool_name(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _patch_resolver(
        monkeypatch,
        {"method": "POST", "url": "https://target.test/api/orders", "headers": {}, "body": "{}"},
    )
    requests: list[SafetyApprovalRequest] = []

    async def approve(request: SafetyApprovalRequest) -> bool:
        requests.append(request)
        return True

    runtime = _runtime(tmp_path, "guarded", approve)
    runtime._reviewer = _StubReviewer(decision=_deferred())
    sent: list[str] = []

    async def invoke(_ctx: Any, raw_input: str) -> str:
        sent.append(raw_input)
        return "response"

    result = await runtime.invoke_mutating_tool(
        ctx=_ctx(),
        tool_name="repeat_request",
        raw_input=json.dumps({"request_id": "req-1"}),
        invoke_tool=invoke,
    )

    assert result == "response"
    assert sent  # approved, so it was sent
    assert len(requests) == 1
    assert requests[0].tool_name == "repeat_request"
    assert requests[0].action == "POST https://target.test/api/orders"


class _Sandbox:
    def __init__(self) -> None:
        self.files = {"/workspace/app.py": b"print(1)\n"}

    async def read(self, path: Path) -> io.BytesIO:
        try:
            return io.BytesIO(self.files[path.as_posix()])
        except KeyError as exc:
            raise FileNotFoundError(path) from exc


class _DirectorySandbox(_Sandbox):
    async def ls(self, path: Path) -> list[Any]:
        if path.as_posix() != "/workspace/recon":
            raise FileNotFoundError(path)
        return [
            SimpleNamespace(
                path="/workspace/recon/hosts.txt",
                kind=SimpleNamespace(value="file"),
                size=len(self.files["/workspace/recon/hosts.txt"]),
            ),
            SimpleNamespace(
                path="/workspace/recon/probe.py",
                kind=SimpleNamespace(value="file"),
                size=len(self.files["/workspace/recon/probe.py"]),
            ),
            SimpleNamespace(
                path="/workspace/recon/link",
                kind=SimpleNamespace(value="symlink"),
                size=4,
            ),
        ]


def _script_ctx(sandbox: _Sandbox | None = None) -> Any:
    return SimpleNamespace(
        context={"agent_id": "agent-1", "sandbox_session": sandbox or _Sandbox()},
        tool_call_id="call-1",
        turn_input=[],
    )


@pytest.mark.asyncio
async def test_runtime_collector_freezes_requested_workspace_file(tmp_path: Path) -> None:
    runtime = _runtime(tmp_path, "guarded")
    sandbox = _Sandbox()
    sandbox.files["/workspace/missing.py"] = b"print('safe')\n"
    evidence_root = tmp_path / "evidence"
    (evidence_root / "artifacts").mkdir(parents=True)
    bundle = EvidenceBundle(
        case_id="case-collect",
        root=evidence_root,
        packet={
            "artifacts": [],
            "completeness": {
                "status": "incomplete",
                "hard_gaps": ["cannot read script entrypoint: /workspace/missing.py"],
                "reviewable_issues": [],
            },
        },
        complete=False,
        incomplete_reasons=[
            "cannot read script entrypoint: /workspace/missing.py",
            (
                "compound command executes a script that cannot be frozen as one exact action; "
                "issue the script execution separately"
            ),
        ],
    )

    output, failed = await runtime._collect_workspace_evidence(
        ctx=_script_ctx(sandbox),
        bundle=bundle,
        paths=("/workspace/missing.py",),
    )

    assert failed is False
    assert bundle.complete is True
    assert bundle.workspace_evidence is True
    assert bundle.incomplete_reasons == []
    assert bundle.reviewable_issues == [
        "requested script requires semantic inspection: /workspace/missing.py"
    ]
    [artifact] = bundle.packet["artifacts"]
    assert artifact["path"] == "/workspace/missing.py"
    assert artifact["role"] == "requested_input"
    assert "sha256:" in output
    assert "print('safe')" in output


@pytest.mark.asyncio
async def test_already_frozen_script_source_is_surfaced_to_the_reviewer(
    tmp_path: Path,
) -> None:
    # A script artifact frozen at compile time carries only structural metadata in the
    # packet; its bytes live on disk under evidence_path. When the reviewer re-requests
    # that path to resolve a dynamic-destination issue, the collector must hand back the
    # real source instead of an empty string, or the review defers to a human for a file
    # it can actually read.
    runtime = _runtime(tmp_path, "guarded")
    evidence_root = tmp_path / "evidence-frozen"
    (evidence_root / "artifacts").mkdir(parents=True)
    script_source = 'import requests\nrequests.get("https://example.test/health")\n'
    (evidence_root / "artifacts" / "000-probe.py").write_text(script_source, encoding="utf-8")
    bundle = EvidenceBundle(
        case_id="case-frozen",
        root=evidence_root,
        packet={
            "artifacts": [
                {
                    "path": "/workspace/probe.py",
                    "digest": "sha256:abc",
                    "bytes": len(script_source),
                    "evidence_path": "artifacts/000-probe.py",
                }
            ],
            "completeness": {"status": "reviewable"},
        },
        complete=True,
        incomplete_reasons=[],
        reviewable_issues=["/workspace/probe.py: dynamic network destination in requests.get"],
    )

    output, failed = await runtime._collect_workspace_evidence(
        ctx=_script_ctx(),
        bundle=bundle,
        paths=("/workspace/probe.py",),
    )

    assert failed is False
    payload = json.loads(output)
    [result] = payload["workspace_artifacts"]
    assert result["status"] == "already frozen"
    assert 'requests.get("https://example.test/health")' in result["source"]


@pytest.mark.asyncio
async def test_runtime_collector_rejects_outside_workspace_path(tmp_path: Path) -> None:
    runtime = _runtime(tmp_path, "guarded")
    evidence_root = tmp_path / "evidence"
    (evidence_root / "artifacts").mkdir(parents=True)
    bundle = EvidenceBundle(
        case_id="case-outside",
        root=evidence_root,
        packet={"artifacts": [], "completeness": {}},
        complete=False,
        incomplete_reasons=["missing evidence"],
    )

    output, failed = await runtime._collect_workspace_evidence(
        ctx=_script_ctx(),
        bundle=bundle,
        paths=("/etc/passwd",),
    )

    assert failed is False
    assert "outside /workspace" in output
    assert bundle.packet["artifacts"] == []


@pytest.mark.asyncio
async def test_runtime_collector_freezes_bounded_workspace_directory(tmp_path: Path) -> None:
    runtime = _runtime(tmp_path, "guarded")
    sandbox = _DirectorySandbox()
    sandbox.files.update(
        {
            "/workspace/recon/hosts.txt": b"a.example.test\n",
            "/workspace/recon/probe.py": b"print('probe')\n",
        }
    )
    evidence_root = tmp_path / "evidence-tree"
    (evidence_root / "artifacts").mkdir(parents=True)
    bundle = EvidenceBundle(
        case_id="case-tree",
        root=evidence_root,
        packet={"artifacts": [], "completeness": {}},
        complete=True,
        incomplete_reasons=[],
    )

    output, failed = await runtime._collect_workspace_evidence(
        ctx=_script_ctx(sandbox),
        bundle=bundle,
        paths=("/workspace/recon/",),
    )

    assert failed is False
    assert {item["path"] for item in bundle.packet["artifacts"]} == {
        "/workspace/recon/hosts.txt",
        "/workspace/recon/probe.py",
    }
    assert "a.example.test" in output
    assert "symlink" in output


@pytest.mark.asyncio
async def test_write_stdin_is_blocked_in_guarded_mode(tmp_path: Path) -> None:
    invoked = False

    async def invoke(_ctx: Any, _raw_input: str) -> str:
        nonlocal invoked
        invoked = True
        return "bad"

    result = await _runtime(tmp_path, "guarded").invoke_write_stdin(
        ctx=_ctx(),
        arguments={"session_id": "s", "chars": "rm -rf /workspace/app\n"},
        invoke_tool=invoke,
    )

    payload = json.loads(result)
    assert payload["status"] == "blocked"
    assert "write_stdin is blocked" in payload["safety"]["reason"]
    assert invoked is False


@pytest.mark.asyncio
async def test_write_stdin_allows_an_interrupt(tmp_path: Path) -> None:
    async def invoke(_ctx: Any, _raw_input: str) -> str:
        return "interrupted"

    result = await _runtime(tmp_path, "guarded").invoke_write_stdin(
        ctx=_ctx(),
        arguments={"session_id": "s", "chars": "\x03"},
        invoke_tool=invoke,
    )

    assert result == "interrupted"


@pytest.mark.asyncio
async def test_write_stdin_is_untouched_when_safety_is_off(tmp_path: Path) -> None:
    async def invoke(_ctx: Any, _raw_input: str) -> str:
        return "typed"

    result = await _runtime(tmp_path, "off").invoke_write_stdin(
        ctx=_ctx(),
        arguments={"session_id": "s", "chars": "anything\n"},
        invoke_tool=invoke,
    )

    assert result == "typed"


@pytest.mark.asyncio
async def test_mutating_request_is_evidence_for_the_reviewer(
    tmp_path: Path,
) -> None:
    runtime = _runtime(tmp_path, "guarded")
    reviewer = _StubReviewer()
    runtime._reviewer = reviewer

    async def invoke(_ctx: Any, _raw_input: str) -> str:
        return "reviewed"

    result = await runtime.invoke_exec(
        ctx=_ctx(),
        arguments={"cmd": "curl -X DELETE https://example.test/v1/users/1042"},
        invoke_tool=invoke,
    )

    assert result == "reviewed"
    assert reviewer.calls == 1


@pytest.mark.asyncio
async def test_deferred_action_waits_for_human_and_executes_the_original_call(
    tmp_path: Path,
) -> None:
    requests: list[SafetyApprovalRequest] = []
    approval_started = asyncio.Event()
    release_approval = asyncio.Event()

    async def approve(request: SafetyApprovalRequest) -> bool:
        requests.append(request)
        approval_started.set()
        await release_approval.wait()
        return True

    runtime = _runtime(tmp_path, "guarded", approve)
    reviewer = _StubReviewer(decision=_deferred())
    runtime._reviewer = reviewer
    arguments = {"cmd": "nmap -sV example.test", "workdir": "/workspace"}
    original_arguments = dict(arguments)
    invoked: list[dict[str, Any]] = []

    async def invoke(_ctx: Any, raw_input: str) -> str:
        invoked.append(json.loads(raw_input))
        return "scanned"

    pending = asyncio.create_task(
        runtime.invoke_exec(ctx=_ctx(), arguments=arguments, invoke_tool=invoke)
    )
    await approval_started.wait()

    assert pending.done() is False
    arguments["cmd"] = "rm -rf /workspace"
    release_approval.set()

    assert await pending == "scanned"
    assert invoked == [original_arguments]
    assert reviewer.human_approval_available == [True]
    assert len(requests) == 1
    request = requests[0]
    assert request.agent_id == "agent-1"
    assert request.request_id == request.case_id
    assert request.tool_call_id == "call-1"
    assert request.tool_name == "exec_command"
    assert request.action == '{"cmd":"nmap -sV example.test","workdir":"/workspace"}'
    assert request.digest == hashlib.sha256(request.action.encode()).hexdigest()
    assert request.reason == "the endpoint effect is ambiguous"
    assert request.categories == ("ambiguous_effect",)
    assert request.risk == "medium"

    audit_path = tmp_path / ".state" / "safety-audit.jsonl"
    entries = [json.loads(line) for line in audit_path.read_text().splitlines()]
    assert any(
        entry["decision_source"] == "reviewer"
        and entry["summary"].get("approval", {}).get("status") == "requested"
        for entry in entries
    )
    assert any(
        entry["decision_source"] == "human"
        and entry["summary"].get("approval", {}).get("status") == "approved"
        for entry in entries
    )


@pytest.mark.asyncio
async def test_approval_cannot_execute_after_requesting_agent_stops(tmp_path: Path) -> None:
    class Coordinator:
        def __init__(self) -> None:
            self.calls = 0

        async def graph_snapshot(self) -> tuple[dict[str, str], dict[str, str], dict, dict]:
            self.calls += 1
            status = "running" if self.calls == 1 else "stopped"
            return {}, {"agent-1": status}, {}, {}

    async def approve(_request: SafetyApprovalRequest) -> bool:
        return True

    runtime = _runtime(tmp_path, "guarded", approve)
    runtime._reviewer = _StubReviewer(decision=_deferred())
    invoked = False

    async def invoke(_ctx: Any, _raw_input: str) -> str:
        nonlocal invoked
        invoked = True
        return "bad"

    result = await runtime.invoke_exec(
        ctx=_ctx(coordinator=Coordinator()),
        arguments={"cmd": "nmap example.test"},
        invoke_tool=invoke,
    )

    payload = json.loads(result)
    assert payload["status"] == "blocked"
    assert payload["safety"]["source"] == "system"
    assert payload["safety"]["categories"][-1] == "agent_inactive"
    assert invoked is False


@pytest.mark.asyncio
async def test_oversized_action_cannot_be_deferred_to_human(tmp_path: Path) -> None:
    approval_called = False

    async def approve(_request: SafetyApprovalRequest) -> bool:
        nonlocal approval_called
        approval_called = True
        return True

    runtime = _runtime(tmp_path, "guarded", approve)
    runtime._reviewer = _StubReviewer(decision=_deferred())
    result = await runtime.invoke_exec(
        ctx=_ctx(),
        arguments={"cmd": "nmap " + "a" * 600},
        invoke_tool=_noop_invoke,
    )

    payload = json.loads(result)
    assert payload["safety"]["categories"] == ["approval_action_too_large"]
    assert approval_called is False


@pytest.mark.asyncio
async def test_human_denial_returns_a_human_sourced_block(tmp_path: Path) -> None:
    async def deny(_request: SafetyApprovalRequest) -> bool:
        return False

    runtime = _runtime(tmp_path, "guarded", deny)
    runtime._reviewer = _StubReviewer(decision=_deferred())
    invoked = False

    async def invoke(_ctx: Any, _raw_input: str) -> str:
        nonlocal invoked
        invoked = True
        return "bad"

    result = await runtime.invoke_exec(
        ctx=_ctx(),
        arguments={"cmd": "nmap -sV example.test"},
        invoke_tool=invoke,
    )

    payload = json.loads(result)
    assert payload["status"] == "blocked"
    assert payload["safety"]["source"] == "human"
    assert payload["safety"]["risk"] == "medium"
    assert "Human denied" in payload["safety"]["reason"]
    assert invoked is False


@pytest.mark.asyncio
async def test_lifecycle_cancellation_is_not_recorded_as_human_denial(tmp_path: Path) -> None:
    async def cancel(_request: SafetyApprovalRequest) -> str:
        return "cancelled"

    runtime = _runtime(tmp_path, "guarded", cancel)  # type: ignore[arg-type]
    runtime._reviewer = _StubReviewer(decision=_deferred())

    result = await runtime.invoke_exec(
        ctx=_ctx(),
        arguments={"cmd": "nmap example.test"},
        invoke_tool=_noop_invoke,
    )

    payload = json.loads(result)
    assert payload["safety"]["source"] == "system"
    assert payload["safety"]["categories"][-1] == "approval_cancelled"
    assert "cancelled" in payload["safety"]["reason"]


@pytest.mark.asyncio
async def test_defer_without_an_approval_channel_blocks(tmp_path: Path) -> None:
    runtime = _runtime(tmp_path, "guarded")
    runtime._reviewer = _StubReviewer(decision=_deferred())

    result = await runtime.invoke_exec(
        ctx=_ctx(),
        arguments={"cmd": "nmap -sV example.test"},
        invoke_tool=_noop_invoke,
    )

    payload = json.loads(result)
    assert payload["status"] == "blocked"
    assert payload["safety"]["source"] == "reviewer"
    assert "no human approval channel" in payload["safety"]["reason"]


@pytest.mark.asyncio
async def test_deterministic_blocks_never_request_approval(tmp_path: Path) -> None:
    approval_calls = 0

    async def approve(_request: SafetyApprovalRequest) -> bool:
        nonlocal approval_calls
        approval_calls += 1
        return True

    runtime = _runtime(tmp_path, "guarded", approve)
    reviewer = _StubReviewer(decision=_deferred())
    runtime._reviewer = reviewer

    result = await runtime.invoke_exec(
        ctx=_ctx(),
        arguments={"cmd": "rm -rf /workspace"},
        invoke_tool=_noop_invoke,
    )

    assert json.loads(result)["status"] == "blocked"
    assert reviewer.calls == 0
    assert approval_calls == 0


@pytest.mark.asyncio
async def test_interactive_incomplete_evidence_reaches_reviewer_and_human(tmp_path: Path) -> None:
    approval_calls = 0

    async def deny(_request: SafetyApprovalRequest) -> bool:
        nonlocal approval_calls
        approval_calls += 1
        return False

    runtime = _runtime(tmp_path, "guarded", deny)
    reviewer = _StubReviewer(decision=_deferred())
    runtime._reviewer = reviewer

    result = await runtime.invoke_exec(
        ctx=_ctx(),
        arguments={"cmd": ""},
        invoke_tool=_noop_invoke,
    )

    payload = json.loads(result)
    assert payload["status"] == "blocked"
    assert payload["safety"]["source"] == "human"
    assert reviewer.calls == 1
    assert approval_calls == 1


@pytest.mark.asyncio
async def test_headless_incomplete_evidence_still_fails_closed(tmp_path: Path) -> None:
    runtime = _runtime(tmp_path, "guarded")
    reviewer = _StubReviewer(decision=_deferred())
    runtime._reviewer = reviewer

    result = await runtime.invoke_exec(
        ctx=_ctx(),
        arguments={"cmd": ""},
        invoke_tool=_noop_invoke,
    )

    payload = json.loads(result)
    assert payload["safety"]["categories"] == ["incomplete_evidence"]
    assert reviewer.calls == 0


@pytest.mark.asyncio
async def test_headless_reviewable_uncertainty_reaches_reviewer_and_can_allow(
    tmp_path: Path,
) -> None:
    sandbox = _Sandbox()
    sandbox.files["/workspace/app.py"] = b"import requests\nimport sys\nrequests.get(sys.argv[1])\n"
    runtime = _runtime(tmp_path, "guarded")
    reviewer = _StubReviewer()
    runtime._reviewer = reviewer

    result = await runtime.invoke_exec(
        ctx=_script_ctx(sandbox),
        arguments={"cmd": "python /workspace/app.py https://example.test"},
        invoke_tool=_noop_invoke,
    )

    assert result == "patched"
    assert reviewer.calls == 1


@pytest.mark.asyncio
async def test_interactive_resolved_reviewable_issue_does_not_prompt_user(tmp_path: Path) -> None:
    approval_calls = 0

    async def approve(_request: SafetyApprovalRequest) -> bool:
        nonlocal approval_calls
        approval_calls += 1
        return True

    sandbox = _Sandbox()
    sandbox.files["/workspace/app.py"] = b"import requests\nimport sys\nrequests.get(sys.argv[1])\n"
    runtime = _runtime(tmp_path, "guarded", approve)
    reviewer = _StubReviewer()
    runtime._reviewer = reviewer

    result = await runtime.invoke_exec(
        ctx=_script_ctx(sandbox),
        arguments={"cmd": "python /workspace/app.py https://example.test"},
        invoke_tool=_noop_invoke,
    )

    assert result == "patched"
    assert reviewer.calls == 1
    assert approval_calls == 0


@pytest.mark.parametrize(
    "decision",
    [
        SafetyDecision(
            allowed=False,
            source="review_error",
            reason="provider failed",
            categories=("review_error",),
        ),
        SafetyDecision(
            allowed=False,
            source="reviewer",
            reason="confidently destructive",
            categories=("destructive_effect",),
            risk="high",
        ),
    ],
)
@pytest.mark.asyncio
async def test_reviewer_errors_and_confident_blocks_never_request_approval(
    tmp_path: Path,
    decision: SafetyDecision,
) -> None:
    approval_calls = 0

    async def approve(_request: SafetyApprovalRequest) -> bool:
        nonlocal approval_calls
        approval_calls += 1
        return True

    runtime = _runtime(tmp_path, "guarded", approve)
    runtime._reviewer = _StubReviewer(decision=decision)

    result = await runtime.invoke_exec(
        ctx=_ctx(),
        arguments={"cmd": "nmap -sV example.test"},
        invoke_tool=_noop_invoke,
    )

    assert json.loads(result)["status"] == "blocked"
    assert approval_calls == 0


@pytest.mark.asyncio
async def test_review_does_not_hold_the_workspace_lock(tmp_path: Path) -> None:
    runtime = _runtime(tmp_path, "guarded")
    concurrent = 0
    peak = 0

    async def on_review() -> None:
        nonlocal concurrent, peak
        concurrent += 1
        peak = max(peak, concurrent)
        await asyncio.sleep(0.05)
        concurrent -= 1

    runtime._reviewer = _StubReviewer(on_review)

    async def invoke(_ctx: Any, _raw_input: str) -> str:
        return "ok"

    await asyncio.gather(
        *[
            runtime.invoke_exec(
                ctx=_ctx(),
                arguments={"cmd": f"nmap -sV host{index}"},
                invoke_tool=invoke,
            )
            for index in range(3)
        ]
    )

    assert peak == 3


@pytest.mark.asyncio
async def test_epoch_change_with_unchanged_evidence_executes(tmp_path: Path) -> None:
    runtime = _runtime(tmp_path, "guarded")

    async def on_review() -> None:
        runtime._workspace_epoch += 1

    runtime._reviewer = _StubReviewer(on_review)

    async def invoke(_ctx: Any, _raw_input: str) -> str:
        return "ran"

    result = await runtime.invoke_exec(
        ctx=_script_ctx(),
        arguments={"cmd": "python /workspace/app.py"},
        invoke_tool=invoke,
    )

    assert result == "ran"
    assert runtime._reviewer.calls == 1
    entries = [
        json.loads(line)
        for line in (tmp_path / ".state" / "safety-audit.jsonl").read_text().splitlines()
    ]
    assert any(entry["execution_status"] == "evidence_unchanged" for entry in entries)


@pytest.mark.asyncio
async def test_epoch_change_during_human_approval_with_unchanged_evidence_executes(
    tmp_path: Path,
) -> None:
    runtime: SafetyRuntime

    async def approve(_request: SafetyApprovalRequest) -> bool:
        runtime._workspace_epoch += 1
        return True

    runtime = _runtime(tmp_path, "guarded", approve)
    runtime._reviewer = _StubReviewer(decision=_deferred())

    async def invoke(_ctx: Any, _raw_input: str) -> str:
        return "ran"

    result = await runtime.invoke_exec(
        ctx=_script_ctx(),
        arguments={"cmd": "python /workspace/app.py"},
        invoke_tool=invoke,
    )

    assert result == "ran"


@pytest.mark.asyncio
async def test_unchanged_workspace_executes_after_review(tmp_path: Path) -> None:
    runtime = _runtime(tmp_path, "guarded")
    runtime._reviewer = _StubReviewer()

    async def invoke(_ctx: Any, _raw_input: str) -> str:
        return "ran"

    result = await runtime.invoke_exec(
        ctx=_script_ctx(),
        arguments={"cmd": "python /workspace/app.py"},
        invoke_tool=invoke,
    )

    assert result == "ran"


@pytest.mark.asyncio
async def test_mutating_tool_is_untouched_when_safety_is_off(tmp_path: Path) -> None:
    async def invoke(_ctx: Any, _raw_input: str) -> str:
        return "patched"

    result = await _runtime(tmp_path, "off").invoke_mutating_tool(
        ctx=_ctx(),
        tool_name="apply_patch",
        raw_input="{}",
        invoke_tool=invoke,
    )

    assert result == "patched"


@pytest.mark.asyncio
async def test_guarded_patch_runs_and_advances_the_workspace_epoch(tmp_path: Path) -> None:
    """The epoch is what makes a script decision go stale, so the write that invalidates
    inspected sources has to advance it."""
    runtime = _runtime(tmp_path, "guarded")

    async def invoke(_ctx: Any, _raw_input: str) -> str:
        return "patched"

    before = runtime._workspace_epoch
    result = await runtime.invoke_mutating_tool(
        ctx=_ctx(),
        tool_name="apply_patch",
        raw_input="{}",
        invoke_tool=invoke,
    )
    after = runtime._workspace_epoch

    assert result == "patched"
    assert after > before


@pytest.mark.asyncio
async def test_noop_patch_during_review_does_not_block_script_execution(tmp_path: Path) -> None:
    runtime = _runtime(tmp_path, "guarded")

    async def patch_during_review() -> None:
        await runtime.invoke_mutating_tool(
            ctx=_ctx(agent_id="agent-2"),
            tool_name="apply_patch",
            raw_input="{}",
            invoke_tool=_noop_invoke,
        )

    runtime._reviewer = _StubReviewer(patch_during_review)

    async def invoke(_ctx: Any, _raw_input: str) -> str:
        return "ran"

    result = await runtime.invoke_exec(
        ctx=_script_ctx(),
        arguments={"cmd": "python /workspace/app.py"},
        invoke_tool=invoke,
    )

    assert result == "ran"
    assert runtime._reviewer.calls == 1


@pytest.mark.asyncio
async def test_changed_reviewed_file_is_automatically_re_reviewed(tmp_path: Path) -> None:
    runtime = _runtime(tmp_path, "guarded")
    sandbox = _Sandbox()
    reviews = 0

    async def change_once() -> None:
        nonlocal reviews
        reviews += 1
        if reviews == 1:
            sandbox.files["/workspace/app.py"] = b"print(2)\n"
            runtime._workspace_epoch += 1

    runtime._reviewer = _StubReviewer(change_once)

    result = await runtime.invoke_exec(
        ctx=_script_ctx(sandbox),
        arguments={"cmd": "python /workspace/app.py"},
        invoke_tool=_noop_invoke,
    )

    assert result == "patched"
    assert runtime._reviewer.calls == 2
    entries = [
        json.loads(line)
        for line in (tmp_path / ".state" / "safety-audit.jsonl").read_text().splitlines()
    ]
    assert any(entry["execution_status"] == "evidence_changed_re_reviewing" for entry in entries)


@pytest.mark.asyncio
async def test_changed_file_after_human_approval_requires_new_approval(tmp_path: Path) -> None:
    runtime: SafetyRuntime
    sandbox = _Sandbox()
    approvals = 0

    async def approve(_request: SafetyApprovalRequest) -> bool:
        nonlocal approvals
        approvals += 1
        if approvals == 1:
            sandbox.files["/workspace/app.py"] = b"print(2)\n"
            runtime._workspace_epoch += 1
        return True

    runtime = _runtime(tmp_path, "guarded", approve)
    runtime._reviewer = _StubReviewer(decision=_deferred())

    result = await runtime.invoke_exec(
        ctx=_script_ctx(sandbox),
        arguments={"cmd": "python /workspace/app.py"},
        invoke_tool=_noop_invoke,
    )

    assert result == "patched"
    assert approvals == 2
    assert runtime._reviewer.calls == 2


@pytest.mark.asyncio
async def test_unchanged_human_approved_evidence_does_not_prompt_again(
    tmp_path: Path,
) -> None:
    runtime: SafetyRuntime
    sandbox = _Sandbox()
    sandbox.files["/workspace/app.py"] = b"exec(input())\n"
    approvals = 0

    async def approve(_request: SafetyApprovalRequest) -> bool:
        nonlocal approvals
        approvals += 1
        if approvals == 1:
            runtime._workspace_epoch += 1
        return True

    runtime = _runtime(tmp_path, "guarded", approve)
    runtime._reviewer = _StubReviewer(decision=_deferred())

    result = await runtime.invoke_exec(
        ctx=_script_ctx(sandbox),
        arguments={"cmd": "python /workspace/app.py"},
        invoke_tool=_noop_invoke,
    )

    assert result == "patched"
    assert approvals == 1
    assert runtime._reviewer.calls == 1


@pytest.mark.asyncio
async def test_repeated_evidence_churn_stops_after_bounded_re_reviews(tmp_path: Path) -> None:
    runtime = _runtime(tmp_path, "guarded")
    sandbox = _Sandbox()
    changes = 0

    async def change_every_time() -> None:
        nonlocal changes
        changes += 1
        sandbox.files["/workspace/app.py"] = f"print({changes + 1})\n".encode()
        runtime._workspace_epoch += 1

    runtime._reviewer = _StubReviewer(change_every_time)

    result = await runtime.invoke_exec(
        ctx=_script_ctx(sandbox),
        arguments={"cmd": "python /workspace/app.py"},
        invoke_tool=_noop_invoke,
    )

    payload = json.loads(result)
    assert payload["status"] == "blocked"
    assert payload["safety"]["categories"] == ["evidence_churn"]
    assert runtime._reviewer.calls == 3


async def _noop_invoke(_ctx: Any, _raw_input: str) -> str:
    return "patched"


@pytest.mark.asyncio
async def test_a_workspace_command_advances_the_epoch(tmp_path: Path) -> None:
    runtime = _runtime(tmp_path, "guarded")
    runtime._reviewer = _StubReviewer()

    before = runtime._workspace_epoch
    result = await runtime.invoke_exec(
        ctx=_script_ctx(),
        arguments={"cmd": "python /workspace/app.py"},
        invoke_tool=_noop_invoke,
    )
    after = runtime._workspace_epoch

    assert result == "patched"
    assert after > before


@pytest.mark.asyncio
async def test_a_read_only_command_leaves_the_epoch_alone(tmp_path: Path) -> None:
    """A read cannot invalidate another agent's inspected sources, so it must not bump the
    epoch; if it did, concurrent reads would spuriously stale each other's decisions."""
    runtime = _runtime(tmp_path, "guarded")

    before = runtime._workspace_epoch
    await runtime.invoke_exec(
        ctx=_ctx(),
        arguments={"cmd": "ls /workspace"},
        invoke_tool=_noop_invoke,
    )

    assert runtime._workspace_epoch == before


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "command",
    [
        "agent-browser tab new https://example.test/admin",
        "agent-browser tab close 2",
        "agent-browser session clear",
    ],
)
async def test_grouped_browser_verbs_reach_the_reviewer(tmp_path: Path, command: str) -> None:
    """The bare verb sits in the passive set, so these are the commands that would slip
    through if passivity were decided on the verb alone."""
    runtime = _runtime(tmp_path, "guarded")
    reviewer = _StubReviewer()
    runtime._reviewer = reviewer

    async def invoke(_ctx: Any, _raw_input: str) -> str:
        return "reviewed"

    result = await runtime.invoke_exec(
        ctx=_ctx(),
        arguments={"cmd": command},
        invoke_tool=invoke,
    )

    assert result == "reviewed"
    assert reviewer.calls == 1


@pytest.mark.asyncio
async def test_bare_tab_listing_keeps_the_fast_path(tmp_path: Path) -> None:
    runtime = _runtime(tmp_path, "guarded")
    reviewer = _StubReviewer()
    runtime._reviewer = reviewer

    result = await runtime.invoke_exec(
        ctx=_ctx(),
        arguments={"cmd": "agent-browser tab"},
        invoke_tool=_noop_invoke,
    )

    assert result == "patched"
    assert reviewer.calls == 0
