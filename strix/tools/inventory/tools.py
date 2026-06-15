"""Inventory agent tools: collect, normalize, score, classify, spray, and persist."""

from __future__ import annotations

import json
from pathlib import Path
from typing import TYPE_CHECKING, Any, cast

from agents import RunContextWrapper, function_tool

from strix.core.inventory import (
    EndpointObservation,
    Param,
    build_ranked_map,
    classify_endpoint,
    collect_code,
    dedup_observations,
    extract_form_params,
    extract_js_params,
    extract_openapi_params,
    extract_proxy_params,
    load_ranked_map,
    save_ranked_map,
    spray_values_for_param,
)
from strix.core.inventory.parsers.reachability import annotate_reachability


if TYPE_CHECKING:
    from strix.core.inventory.models import ParamObservation


def _param_from_observation(obs: ParamObservation) -> Param:
    return Param(
        name=obs.name,
        location=obs.location,
        provenance=set(obs.provenance),
        example_values=set(obs.example_values),
    )


def _run_dir_from_ctx(ctx: RunContextWrapper) -> Path:
    """Return the run directory from the agent context."""
    context = cast("dict[str, Any] | None", getattr(ctx, "context", None))
    if isinstance(context, dict):
        run_dir = context.get("run_dir")
        if run_dir is not None:
            return Path(cast("str | Path", run_dir))
    raise RuntimeError("Tool context is missing 'run_dir'")


def _dump_json(obj: Any) -> str:
    return json.dumps(obj, ensure_ascii=False, default=str)


@function_tool(timeout=60)
async def collect_inventory_from_code(
    ctx: RunContextWrapper,
    source_path: str,
    target_id: str,
    base_url: str,
) -> str:
    """Collect attack-surface observations from a white-box code path (FastAPI only this phase)."""
    run_dir = _run_dir_from_ctx(ctx)
    observations = collect_code(Path(source_path), base_url=base_url)
    annotate_reachability(observations)
    return _dump_json(
        {
            "success": True,
            "target_id": target_id,
            "run_dir": str(run_dir),
            "observations": len(observations),
            "items": [_observation_to_json(obs) for obs in observations],
        },
    )


@function_tool(timeout=60)
async def collect_inventory_from_proxy(
    ctx: RunContextWrapper,
    records: list[dict[str, Any]],
    target_id: str,
) -> str:
    """Collect attack-surface observations from proxy request/response records."""
    run_dir = _run_dir_from_ctx(ctx)
    params = extract_proxy_params(records)
    # Proxy records alone don't give a single endpoint; return extracted params.
    return _dump_json(
        {
            "success": True,
            "target_id": target_id,
            "run_dir": str(run_dir),
            "params": {name: param.model_dump() for name, param in params.items()},
        },
    )


@function_tool(timeout=60)
async def build_ranked_surface_map(
    ctx: RunContextWrapper,
    observations: list[dict[str, Any]],
    target_id: str,
) -> str:
    """Normalize, dedup, and score a list of EndpointObservation dicts into a ranked map."""
    run_dir = _run_dir_from_ctx(ctx)
    obs_list = [EndpointObservation.model_validate(obs) for obs in observations]
    endpoints = dedup_observations(obs_list)
    ranked = build_ranked_map(target_id, endpoints)
    path = save_ranked_map(run_dir, ranked)
    return _dump_json(
        {
            "success": True,
            "target_id": target_id,
            "run_dir": str(run_dir),
            "endpoints": len(ranked.endpoints),
            "path": str(path),
        },
    )


@function_tool(timeout=60)
async def load_ranked_surface_map(
    ctx: RunContextWrapper,
    target_id: str,
) -> str:
    """Load a previously saved ranked surface map."""
    run_dir = _run_dir_from_ctx(ctx)
    ranked = load_ranked_map(run_dir, target_id)
    return _dump_json(
        {
            "success": True,
            "target_id": target_id,
            "run_dir": str(run_dir),
            "endpoints": len(ranked.endpoints),
            "map": ranked.model_dump(),
        },
    )


@function_tool(timeout=60)
async def classify_inventory_params(
    ctx: RunContextWrapper,
    target_id: str,
) -> str:
    """Classify every parameter on the saved ranked surface map and re-persist."""
    run_dir = _run_dir_from_ctx(ctx)
    ranked = load_ranked_map(run_dir, target_id)
    for endpoint in ranked.endpoints.values():
        classify_endpoint(endpoint)
    path = save_ranked_map(run_dir, ranked)
    return _dump_json(
        {
            "success": True,
            "target_id": target_id,
            "run_dir": str(run_dir),
            "endpoints": len(ranked.endpoints),
            "path": str(path),
        },
    )


@function_tool(timeout=60)
async def spray_inventory_params(
    ctx: RunContextWrapper,
    target_id: str,
) -> str:
    """Return deterministic spray values for every classified parameter on the map."""
    run_dir = _run_dir_from_ctx(ctx)
    ranked = load_ranked_map(run_dir, target_id)
    spray_plan: dict[str, dict[str, list[str]]] = {}
    for key, endpoint in ranked.endpoints.items():
        spray_plan[key] = {
            param.name: spray_values_for_param(param)
            for param in endpoint.params.values()
            if param.class_evidence is not None
        }
    return _dump_json(
        {
            "success": True,
            "target_id": target_id,
            "run_dir": str(run_dir),
            "spray_plan": spray_plan,
        },
    )


def _merge_extracted_into_endpoints(
    endpoints: dict[str, Any],
    extracted: dict[str, ParamObservation],
) -> None:
    for name, obs in extracted.items():
        for endpoint in endpoints.values():
            if name in endpoint.params:
                existing = endpoint.params[name]
                existing.provenance |= set(obs.provenance)
                existing.example_values |= set(obs.example_values)
            else:
                endpoint.params[name] = _param_from_observation(obs)


@function_tool(timeout=60)
async def enrich_inventory_from_openapi(
    ctx: RunContextWrapper,
    spec: dict[str, Any],
    target_id: str,
) -> str:
    """Extract parameter candidates from an OpenAPI spec and merge into the saved map."""
    run_dir = _run_dir_from_ctx(ctx)
    extracted = extract_openapi_params(spec)
    ranked = load_ranked_map(run_dir, target_id)
    _merge_extracted_into_endpoints(ranked.endpoints, extracted)
    path = save_ranked_map(run_dir, ranked)
    return _dump_json(
        {
            "success": True,
            "target_id": target_id,
            "run_dir": str(run_dir),
            "extracted_params": len(extracted),
            "path": str(path),
        },
    )


@function_tool(timeout=60)
async def enrich_inventory_from_js(
    ctx: RunContextWrapper,
    source: str,
    target_id: str,
) -> str:
    """Extract parameter candidates from JS source and merge into the saved map."""
    run_dir = _run_dir_from_ctx(ctx)
    extracted = extract_js_params(source)
    ranked = load_ranked_map(run_dir, target_id)
    _merge_extracted_into_endpoints(ranked.endpoints, extracted)
    path = save_ranked_map(run_dir, ranked)
    return _dump_json(
        {
            "success": True,
            "target_id": target_id,
            "run_dir": str(run_dir),
            "extracted_params": len(extracted),
            "path": str(path),
        },
    )


@function_tool(timeout=60)
async def enrich_inventory_from_forms(
    ctx: RunContextWrapper,
    html: str,
    target_id: str,
) -> str:
    """Extract parameter candidates from HTML forms and merge into the saved map."""
    run_dir = _run_dir_from_ctx(ctx)
    extracted = extract_form_params(html)
    ranked = load_ranked_map(run_dir, target_id)
    _merge_extracted_into_endpoints(ranked.endpoints, extracted)
    path = save_ranked_map(run_dir, ranked)
    return _dump_json(
        {
            "success": True,
            "target_id": target_id,
            "run_dir": str(run_dir),
            "extracted_params": len(extracted),
            "path": str(path),
        },
    )


def _observation_to_json(obs: EndpointObservation) -> dict[str, Any]:
    return obs.model_dump()
