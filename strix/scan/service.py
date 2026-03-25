from __future__ import annotations

import asyncio
from dataclasses import dataclass
from typing import Any

from strix.agents.StrixAgent import StrixAgent
from strix.llm.config import LLMConfig
from strix.runtime import cleanup_runtime
from strix.runtime.docker_runtime import HOST_GATEWAY_HOSTNAME
from strix.telemetry.tracer import Tracer, set_global_tracer
from strix.tools.agents_graph.agents_graph_actions import reset_agent_graph_state
from strix.interface.utils import (
    assign_workspace_subdirs,
    clone_repository,
    collect_local_sources,
    generate_run_name,
    infer_target_type,
    rewrite_localhost_targets,
)


@dataclass
class ScanRequest:
    targets: list[str]
    instruction: str = ""
    scan_mode: str = "deep"
    run_name: str | None = None


@dataclass
class PreparedScan:
    request: ScanRequest
    run_name: str
    targets_info: list[dict[str, Any]]
    local_sources: list[dict[str, str]]

    def build_scan_config(self) -> dict[str, Any]:
        return build_scan_config(self)

    def build_agent_config(self, *, interactive: bool = False) -> dict[str, Any]:
        return build_agent_config(self, interactive=interactive)


@dataclass
class ScanExecutionResult:
    prepared_scan: PreparedScan
    tracer: Tracer
    result: dict[str, Any]


def build_targets_info(raw_targets: list[str]) -> list[dict[str, Any]]:
    targets_info: list[dict[str, Any]] = []
    for target in raw_targets:
        target_type, target_dict = infer_target_type(target)
        display_target = target_dict.get("target_path", target) if target_type == "local_code" else target
        targets_info.append(
            {
                "type": target_type,
                "details": target_dict,
                "original": display_target,
            }
        )

    assign_workspace_subdirs(targets_info)
    rewrite_localhost_targets(targets_info, HOST_GATEWAY_HOSTNAME)
    return targets_info


def generate_scan_id(raw_targets: list[str]) -> str:
    return generate_run_name(build_targets_info(raw_targets))


def prepare_scan(request: ScanRequest) -> PreparedScan:
    targets_info = build_targets_info(request.targets)

    run_name = request.run_name or generate_run_name(targets_info)

    for target_info in targets_info:
        if target_info["type"] != "repository":
            continue
        repo_url = target_info["details"]["target_repo"]
        dest_name = target_info["details"].get("workspace_subdir")
        cloned_path = clone_repository(repo_url, run_name, dest_name)
        target_info["details"]["cloned_repo_path"] = cloned_path

    local_sources = collect_local_sources(targets_info)
    return PreparedScan(
        request=request,
        run_name=run_name,
        targets_info=targets_info,
        local_sources=local_sources,
    )


def build_scan_config(prepared_scan: PreparedScan) -> dict[str, Any]:
    return {
        "scan_id": prepared_scan.run_name,
        "targets": prepared_scan.targets_info,
        "user_instructions": prepared_scan.request.instruction,
        "run_name": prepared_scan.run_name,
    }


def build_agent_config(
    prepared_scan: PreparedScan,
    *,
    interactive: bool = False,
) -> dict[str, Any]:
    agent_config: dict[str, Any] = {
        "llm_config": LLMConfig(
            scan_mode=prepared_scan.request.scan_mode,
            interactive=interactive,
        ),
        "max_iterations": 300,
    }
    if prepared_scan.local_sources:
        agent_config["local_sources"] = prepared_scan.local_sources
    return agent_config


async def execute_prepared_scan(
    prepared_scan: PreparedScan,
    *,
    interactive: bool = False,
    cleanup_after_run: bool = True,
) -> ScanExecutionResult:
    tracer = Tracer(prepared_scan.run_name)
    scan_config = build_scan_config(prepared_scan)
    agent_config = build_agent_config(prepared_scan, interactive=interactive)

    reset_agent_graph_state()
    tracer.set_scan_config(scan_config)
    set_global_tracer(tracer)

    try:
        agent = StrixAgent(agent_config)
        result = await agent.execute_scan(scan_config)
        return ScanExecutionResult(
            prepared_scan=prepared_scan,
            tracer=tracer,
            result=result,
        )
    except asyncio.CancelledError:
        raise
    finally:
        if cleanup_after_run:
            tracer.cleanup()
            cleanup_runtime()
            set_global_tracer(None)
            reset_agent_graph_state()
