import json
import logging
import re
import subprocess
import threading
from collections.abc import Callable
from datetime import UTC, datetime
from importlib.metadata import PackageNotFoundError, version
from pathlib import Path
from typing import TYPE_CHECKING, Any, Optional, cast
from uuid import uuid4

from strix.config import opencode
from strix.config.loader import load_settings
from strix.core.paths import run_dir_for, runtime_state_dir
from strix.report.coverage import write_coverage
from strix.report.pricing import resolve_litellm_model
from strix.report.sarif import write_sarif
from strix.report.writer import (
    read_run_record,
    write_executive_report,
    write_run_record,
    write_vulnerabilities,
)
from strix.telemetry import posthog, scarf


if TYPE_CHECKING:
    from agents.usage import Usage


logger = logging.getLogger(__name__)

_global_report_state: Optional["ReportState"] = None

_CONTROL_CHARS = re.compile(r"[\x00-\x1f\x7f]+")


def _strix_version() -> str | None:
    """Best-effort package version for the SARIF tool.driver.version field."""
    try:
        return version("strix-agent")
    except PackageNotFoundError:
        return None


def _clean_title(title: str) -> str:
    """Return a single-line finding title.

    A title quotes text from the scanned target, so it can carry newlines, tabs or
    other control characters. Those break every artifact that renders the title on
    one line, such as the markdown heading, the CSV cell and the TUI list. Control
    characters become spaces and runs of whitespace collapse to one space.
    """
    return " ".join(_CONTROL_CHARS.sub(" ", title).split())


def _number(value: Any) -> int | float:
    try:
        return float(value or 0)
    except (TypeError, ValueError):
        return 0


def _parse_repo_full_name(uri: str) -> str | None:
    """Extract ``owner/repo`` from a git URL or slug, else None."""
    text = uri.strip().removesuffix(".git")
    if not text:
        return None
    if "@" in text and ":" in text.split("@", 1)[1]:
        # scp-style: git@host:owner/repo
        text = text.split("@", 1)[1].split(":", 1)[1]
    elif "://" in text:
        # https://host/owner/repo
        host_and_path = text.split("://", 1)[1]
        text = host_and_path.split("/", 1)[1] if "/" in host_and_path else host_and_path
    parts = [p for p in text.split("/") if p]
    if len(parts) >= 2:
        return "/".join(parts[-2:])
    return None


def _git_head(repo_path: str) -> tuple[str | None, str | None]:
    """Best-effort ``(commit_sha, branch)`` for a cloned repo, or ``(None, None)``.

    Used to populate SARIF versionControlProvenance. Failures (missing git,
    non-repo path, detached HEAD, timeout) degrade to None so the SARIF
    emit is never blocked by a provenance lookup.
    """
    path = Path(repo_path)
    if not path.is_dir():
        return None, None

    def _run(args: list[str]) -> str | None:
        try:
            result = subprocess.run(  # noqa: S603
                ["git", "-C", str(path), *args],  # noqa: S607
                capture_output=True,
                text=True,
                check=False,
                timeout=5,
            )
        except (OSError, subprocess.SubprocessError):
            return None
        if result.returncode != 0:
            return None
        return result.stdout.strip() or None

    commit = _run(["rev-parse", "HEAD"])
    branch = _run(["rev-parse", "--abbrev-ref", "HEAD"])
    if branch == "HEAD":  # detached HEAD carries no branch name
        branch = None
    return commit, branch


def get_global_report_state() -> Optional["ReportState"]:
    return _global_report_state


def set_global_report_state(report_state: "ReportState") -> None:
    global _global_report_state  # noqa: PLW0603
    _global_report_state = report_state
    # New run: drop any streamed-cost entries a prior run left unconsumed.
    streamed_openrouter_costs.clear()


class ReportState:
    """Per-scan product artifact state plus artifact writer.

    The Agents SDK owns model/tool execution, tracing, and conversation
    persistence. This store keeps only Strix-owned scan artifacts and
    report metadata. Live UI projections belong to the interface layer.

    It does not consume SDK tracing processors.
    """

    def __init__(self, run_name: str | None = None):
        self.run_name = run_name
        self.run_id = run_name or f"run-{uuid4().hex[:8]}"
        self.start_time = datetime.now(UTC).isoformat()
        self.process_start_time = self.start_time
        self.end_time: str | None = None

        self.vulnerability_reports: list[dict[str, Any]] = []
        self.final_scan_result: str | None = None

        self.scan_results: dict[str, Any] | None = None
        self.scan_config: dict[str, Any] | None = None
        # Imported here so importing this module never enters the agents SDK
        # package (which the warm-up thread may be initializing concurrently).
        from strix.report.usage import LLMUsageLedger

        self._llm_usage = LLMUsageLedger()
        self._telemetry_llm_usage_baseline: dict[str, Any] = {}
        auth_mode = opencode.auth_mode(load_settings().llm.model)
        oc = opencode.subscription_model(load_settings().llm.model)
        # A flat subscription has no per-run charge to report. Zen bills prepaid
        # credits per request, so its cost is real and stays tracked.
        self._llm_usage.zero_cost = auth_mode == "subscription" and not (
            oc is not None and oc.metered
        )
        self.run_record: dict[str, Any] = {
            "run_id": self.run_id,
            "run_name": self.run_name,
            "start_time": self.start_time,
            "end_time": None,
            "status": "running",
            "auth_mode": auth_mode,
            "subscription_provider": opencode.subscription_provider(load_settings().llm.model),
            "subscription_plan": opencode.subscription_plan(load_settings().llm.model),
            "targets_info": [],
            "llm_usage": self._build_llm_usage_record(),
        }
        self._run_dir: Path | None = None
        self._saved_vuln_ids: set[str] = set()

        self.caido_url: str | None = None
        self.vulnerability_found_callback: Callable[[dict[str, Any]], None] | None = None

        self._sarif_repo_ctx: dict[str, Any] | None = None
        self._sarif_repo_ctx_ready: bool = False

        self.posthog_scan_ended_sent: bool = False
        self.scarf_scan_ended_sent: bool = False
        self.scan_ended_exit_reason: str | None = None

    def get_run_dir(self) -> Path:
        if self._run_dir is None:
            run_dir_name = self.run_name if self.run_name else self.run_id
            self._run_dir = run_dir_for(run_dir_name)
            self._run_dir.mkdir(parents=True, exist_ok=True)

        return self._run_dir

    def hydrate_from_run_dir(self) -> None:
        """Reload prior-scan state from ``{run_dir}/`` for resume.

        Restores:

        - ``vulnerability_reports`` from ``vulnerabilities.json`` so
          :meth:`add_vulnerability_report` doesn't allocate a colliding
          ``vuln-0001`` and overwrite the prior on-disk MD.
        - ``run_record`` from ``run.json`` so timestamps, run inputs,
          status, and final report state have one public source of truth.

        Idempotent on missing files (fresh runs land here too via the
        same code path). **Raises on corruption** — silently swallowing
        a corrupt ``vulnerabilities.json`` would let the next vuln
        allocate ``vuln-0001`` and overwrite the prior MD on disk
        (data loss). Caller is expected to fail the run loud and let
        the user inspect ``{run_dir}`` or pick a fresh ``--run-name``.
        """
        run_dir = self.get_run_dir()

        data = read_run_record(run_dir)
        if data:
            self.run_record.update(data)
            if isinstance(data.get("start_time"), str):
                self.start_time = data["start_time"]
            if isinstance(data.get("end_time"), str):
                self.end_time = data["end_time"]
            scan_results = data.get("scan_results")
            if isinstance(scan_results, dict):
                self.scan_results = scan_results
                self.final_scan_result = self._format_final_scan_result(scan_results)
            self._hydrate_llm_usage(data.get("llm_usage"))
            self._telemetry_llm_usage_baseline = self._build_llm_usage_record()
            logger.info("report state hydrated run.json from %s", run_dir)

        json_path = run_dir / "vulnerabilities.json"
        if json_path.exists():
            try:
                data = json.loads(json_path.read_text(encoding="utf-8"))
            except (OSError, json.JSONDecodeError) as exc:
                raise RuntimeError(
                    f"vulnerabilities.json at {json_path} is corrupt ({exc}); "
                    f"refusing to start fresh — that would overwrite prior "
                    f"vulnerability MDs on disk. Inspect or delete the run dir.",
                ) from exc
            if not isinstance(data, list):
                raise RuntimeError(
                    f"vulnerabilities.json at {json_path} is not a list",
                )
            self.vulnerability_reports = [r for r in data if isinstance(r, dict)]
            for r in self.vulnerability_reports:
                title = r.get("title")
                stale_md = False
                if isinstance(title, str):
                    r["title"] = _clean_title(title)
                    stale_md = r["title"] != title
                rid = r.get("id")
                # A finding already on disk keeps its markdown, unless cleaning
                # changed the title: the heading on disk then needs a rewrite.
                if isinstance(rid, str) and not stale_md:
                    self._saved_vuln_ids.add(rid)
            logger.info(
                "report state hydrated %d vulnerability report(s)",
                len(self.vulnerability_reports),
            )

    def add_vulnerability_report(
        self,
        title: str,
        severity: str,
        description: str | None = None,
        impact: str | None = None,
        target: str | None = None,
        technical_analysis: str | None = None,
        poc_description: str | None = None,
        poc_script_code: str | None = None,
        remediation_steps: str | None = None,
        evidence: str | None = None,
        assumptions: str | None = None,
        counterevidence: str | None = None,
        confidence: str | None = None,
        confidence_rationale: str | None = None,
        severity_change_conditions: str | None = None,
        fix_effort: str | None = None,
        cvss: float | None = None,
        cvss_breakdown: dict[str, str] | None = None,
        endpoint: str | None = None,
        method: str | None = None,
        cve: str | None = None,
        cwe: str | None = None,
        code_locations: list[dict[str, Any]] | None = None,
        fix_verification: str | None = None,
        fix_pr_body: str | None = None,
        finding_class: str | None = None,
        dependency_metadata: dict[str, str] | None = None,
        agent_id: str | None = None,
        agent_name: str | None = None,
    ) -> str:
        report_id = f"vuln-{len(self.vulnerability_reports) + 1:04d}"

        report: dict[str, Any] = {
            "id": report_id,
            "title": _clean_title(title),
            "severity": severity.lower().strip(),
            "timestamp": datetime.now(UTC).strftime("%Y-%m-%d %H:%M:%S UTC"),
        }

        if description:
            report["description"] = description.strip()
        if impact:
            report["impact"] = impact.strip()
        if target:
            report["target"] = target.strip()
        if technical_analysis:
            report["technical_analysis"] = technical_analysis.strip()
        if poc_description:
            report["poc_description"] = poc_description.strip()
        if poc_script_code:
            report["poc_script_code"] = poc_script_code.strip()
        if remediation_steps:
            report["remediation_steps"] = remediation_steps.strip()
        if evidence:
            report["evidence"] = evidence.strip()
        if assumptions:
            report["assumptions"] = assumptions.strip()
        if counterevidence:
            report["counterevidence"] = counterevidence.strip()
        if confidence:
            report["confidence"] = confidence.strip().lower()
        if confidence_rationale:
            report["confidence_rationale"] = confidence_rationale.strip()
        if severity_change_conditions:
            report["severity_change_conditions"] = severity_change_conditions.strip()
        if fix_effort:
            report["fix_effort"] = fix_effort.strip().lower()
        if cvss is not None:
            report["cvss"] = cvss
        if cvss_breakdown:
            report["cvss_breakdown"] = cvss_breakdown
        if endpoint:
            report["endpoint"] = endpoint.strip()
        if method:
            report["method"] = method.strip()
        if cve:
            report["cve"] = cve.strip()
        if cwe:
            report["cwe"] = cwe.strip()
        if code_locations:
            report["code_locations"] = code_locations
        if fix_verification:
            report["fix_verification"] = fix_verification.strip()
        if fix_pr_body:
            report["fix_pr_body"] = fix_pr_body.strip()
        report["finding_class"] = (finding_class or "dynamic").strip().lower()
        if dependency_metadata:
            report["dependency_metadata"] = dependency_metadata
        if agent_id:
            report["agent_id"] = agent_id
        if agent_name:
            report["agent_name"] = agent_name

        self.vulnerability_reports.append(report)
        logger.info(f"Added vulnerability report: {report_id} - {title}")
        posthog.finding(severity, cwe=cwe, is_cve=bool(cve))
        scarf.finding(severity, cwe=cwe, is_cve=bool(cve))

        if self.vulnerability_found_callback:
            self.vulnerability_found_callback(report)

        self.save_run_data()
        return report_id

    def get_existing_vulnerabilities(self) -> list[dict[str, Any]]:
        return list(self.vulnerability_reports)

    def record_sdk_usage(
        self,
        *,
        agent_id: str,
        usage: "Usage | None",
        agent_name: str | None = None,
        model: str | None = None,
    ) -> None:
        """Record SDK-native token usage for one completed model run/cycle."""
        if self._llm_usage.record(
            agent_id=agent_id,
            agent_name=agent_name,
            model=model,
            usage=usage,
        ):
            self.save_run_data()

    def record_observed_llm_cost(self, cost: float) -> None:
        self._llm_usage.record_observed_cost(cost)

    def get_total_llm_usage(self) -> dict[str, Any]:
        return dict(self.run_record.get("llm_usage") or self._build_llm_usage_record())

    def get_process_llm_usage(self) -> dict[str, int | float]:
        """Return LLM usage accumulated since this process started."""
        usage = self._llm_usage.to_record()
        return {
            key: max(
                0, _number(usage.get(key)) - _number(self._telemetry_llm_usage_baseline.get(key))
            )
            for key in ("requests", "input_tokens", "output_tokens", "total_tokens", "cost")
        }

    def get_process_duration_seconds(self) -> float:
        """Return this process's elapsed wall time for telemetry."""
        try:
            start = datetime.fromisoformat(self.process_start_time.replace("Z", "+00:00"))
            duration = (datetime.now(start.tzinfo) - start).total_seconds()
            return max(0.0, duration)
        except (ValueError, TypeError, AttributeError):
            return 0.0

    def get_total_llm_cost(self) -> float:
        """Live accumulated LLM cost, independent of the persisted run-record snapshot."""
        return self._llm_usage.total_cost

    def update_scan_final_fields(
        self,
        executive_summary: str,
        methodology: str,
        technical_analysis: str,
        recommendations: str,
    ) -> None:
        self.scan_results = {
            "scan_completed": True,
            "executive_summary": executive_summary.strip(),
            "methodology": methodology.strip(),
            "technical_analysis": technical_analysis.strip(),
            "recommendations": recommendations.strip(),
            "success": True,
        }

        self.final_scan_result = self._format_final_scan_result(self.scan_results)
        self.run_record["scan_results"] = self.scan_results

        logger.info("Updated scan final fields")
        self.save_run_data(mark_complete=True)
        posthog.end(self, exit_reason="finished_by_tool")
        scarf.end(self, exit_reason="finished_by_tool")

    def record_mcp_connections(self, names: list[str]) -> None:
        """Note the MCP servers this run connected, and persist it.

        Saved as soon as the run connects rather than at the end, so an interface
        reading the record mid-run can already attribute a tool call to the
        server it went out to.
        """
        if self.run_record.get("mcp_connections") == names:
            return
        self.run_record["mcp_connections"] = names
        self.save_run_data()

    def record_mcp_connection_status(self, status: list[dict[str, Any]]) -> None:
        """Persist the run's non-secret MCP connection status roster.

        ``status`` is one entry per connection carrying only ``name``,
        ``provider``, ``tool_count``, and ``dead`` (no config, url, token, or
        auth). Saved as soon as the run connects and rewritten each time a
        connection dies, so the viewer, which rebuilds its display by re-reading
        the run's files from disk, can show a live connections panel and health
        without any in-memory event sink. Kept separate from the
        ``mcp_connections`` name list so neither field repurposes the other.
        """
        if self.run_record.get("mcp_connection_status") == status:
            return
        self.run_record["mcp_connection_status"] = status
        self.save_run_data()

    def set_scan_config(self, config: dict[str, Any]) -> None:
        self.scan_config = config
        self.run_record["status"] = "running"
        self.run_record["end_time"] = None
        self.run_record.pop("scan_results", None)
        self.end_time = None
        self.scan_results = None
        self.final_scan_result = None
        self.run_record.update(
            {
                "targets_info": config.get("targets", []),
                "instruction": config.get("user_instructions", ""),
                "scan_mode": config.get("scan_mode", "deep"),
                "diff_scope": config.get("diff_scope", {"active": False}),
                "non_interactive": bool(config.get("non_interactive", False)),
                "local_sources": config.get("local_sources", []),
                "scope_mode": config.get("scope_mode", "auto"),
                "diff_base": config.get("diff_base"),
            }
        )

    def save_run_data(self, mark_complete: bool = False, status: str | None = None) -> None:
        if mark_complete:
            self.end_time = datetime.now(UTC).isoformat()
            self.run_record["end_time"] = self.end_time
            self.run_record["status"] = "completed"
        elif status and self.run_record.get("status") != "completed":
            current_status = self.run_record.get("status")
            if status == "stopped" and current_status in {"failed", "interrupted"}:
                status = str(current_status)
            if self.end_time is None:
                self.end_time = datetime.now(UTC).isoformat()
            self.run_record["end_time"] = self.end_time
            self.run_record["status"] = status

        self._sync_llm_usage_record()
        self._save_artifacts()

    def cleanup(self, status: str = "stopped") -> None:
        self.save_run_data(status=status)

    def _format_final_scan_result(self, scan_results: dict[str, Any]) -> str:
        return f"""# Executive Summary

{str(scan_results.get("executive_summary", "")).strip()}

# Methodology

{str(scan_results.get("methodology", "")).strip()}

# Technical Analysis

{str(scan_results.get("technical_analysis", "")).strip()}

# Recommendations

{str(scan_results.get("recommendations", "")).strip()}
"""

    def _coverage_document(self) -> dict[str, Any] | None:
        """Assemble the coverage record, or None when it can't be built.

        Coverage is a secondary artifact: a failure here must not cost the
        caller its findings, so this swallows and logs rather than raising
        into :meth:`_save_artifacts`.
        """
        try:
            from strix.report.coverage import build_coverage_document, read_agent_graph
            from strix.tools.coverage.tools import get_coverage_entries

            return build_coverage_document(
                run_record=self.run_record,
                entries=get_coverage_entries(),
                agent_graph=read_agent_graph(runtime_state_dir(self.get_run_dir())),
                vulnerability_reports=self.vulnerability_reports,
                exit_reason=self.scan_ended_exit_reason,
            )
        except Exception:
            logger.exception("coverage document build failed (non-fatal)")
            return None

    def _save_artifacts(self) -> None:
        """Write scan artifacts under ``run_dir``."""
        run_dir = self.get_run_dir()
        try:
            run_dir.mkdir(parents=True, exist_ok=True)

            coverage = self._coverage_document()
            if coverage is not None:
                try:
                    write_coverage(run_dir, coverage)
                except OSError:
                    logger.exception("coverage.json write failed (non-fatal)")

            if self.final_scan_result:
                write_executive_report(run_dir, self.final_scan_result)

            if self.vulnerability_reports:
                write_vulnerabilities(run_dir, self.vulnerability_reports, self._saved_vuln_ids)

            # SARIF 2.1.0 emitter for CI / ASPM integration. Always emit (even
            # empty) so a clean run overwrites a prior findings.sarif rather than
            # leaving a stale one — codeql-action's "absent from new submission →
            # fixed" needs the fresh empty doc to auto-resolve alerts. Isolated
            # in its own try: a SARIF-build error must NEVER break the CSV/MD/
            # run-record path (the emitter's own contract).
            try:
                write_sarif(
                    run_dir,
                    self.vulnerability_reports,
                    tool_version=_strix_version(),
                    repository_context=self._sarif_repository_context(),
                    coverage=coverage,
                )
            except Exception:
                logger.exception("SARIF emit failed (non-fatal; CSV/MD unaffected)")

            write_run_record(run_dir, self.run_record)

            logger.info("Essential scan data saved to: %s", run_dir)
        except (OSError, RuntimeError):
            logger.exception("Failed to save scan data")

    def _sarif_repository_context(self) -> dict[str, Any] | None:
        """Repo/commit/branch context for SARIF provenance (repo scans only).

        Cached after first derivation — ``_save_artifacts`` runs on every
        state save, and the git lookup only needs to happen once per run.
        Returns None for URL / IP (DAST) targets that have no repository.
        """
        if not self._sarif_repo_ctx_ready:
            self._sarif_repo_ctx = self._derive_repository_context()
            self._sarif_repo_ctx_ready = True
        return self._sarif_repo_ctx

    def _derive_repository_context(self) -> dict[str, Any] | None:
        targets = self.run_record.get("targets_info") or []
        if not isinstance(targets, list):
            return None
        repo_targets = [
            target
            for target in targets
            if isinstance(target, dict) and target.get("type") == "repository"
        ]
        # Provenance binds the whole run to one repo; with multiple repo targets
        # that's ambiguous, so omit it rather than mis-attributing later repos'
        # findings to the first repo's URI/commit.
        if len(repo_targets) != 1:
            return None
        target = repo_targets[0]
        details = target.get("details") or {}
        if not isinstance(details, dict):
            return None
        uri = details.get("target_repo")
        if not isinstance(uri, str) or not uri.strip():
            return None

        context: dict[str, Any] = {"repositoryUri": uri.strip()}
        full_name = _parse_repo_full_name(uri)
        if full_name:
            context["repositoryFullName"] = full_name
        cloned = details.get("cloned_repo_path")
        if isinstance(cloned, str) and cloned.strip():
            commit, branch = _git_head(cloned.strip())
            if commit:
                context["commitSha"] = commit
            if branch:
                context["branch"] = branch
                context["ref"] = f"refs/heads/{branch}"
        return context

    def _sync_llm_usage_record(self) -> None:
        self.run_record["llm_usage"] = self._build_llm_usage_record()

    def _build_llm_usage_record(self) -> dict[str, Any]:
        return self._llm_usage.to_record()

    def _hydrate_llm_usage(self, raw_usage: Any) -> None:
        self._llm_usage.hydrate(raw_usage)
        self._sync_llm_usage_record()


def openrouter_stream_cost(usage: Any) -> float | None:
    """Total OpenRouter-reported cost from a raw stream ``usage`` block, or None.

    Non-BYOK responses bill everything to ``usage.cost``. BYOK responses put the
    OpenRouter fee in ``usage.cost`` (often 0) and the provider charge in
    ``usage.cost_details.upstream_inference_cost``, so BYOK totals sum the two.
    """
    if not isinstance(usage, dict):
        return None
    total = 0.0
    cost = usage.get("cost")
    if isinstance(cost, int | float) and cost > 0:
        total += float(cost)
    if bool(usage.get("is_byok")):
        details = usage.get("cost_details")
        upstream = details.get("upstream_inference_cost") if isinstance(details, dict) else None
        if isinstance(upstream, int | float) and upstream > 0:
            total += float(upstream)
    return total if total > 0 else None


def _response_id(completion_response: Any) -> str | None:
    response_id = getattr(completion_response, "id", None)
    if response_id is None and isinstance(completion_response, dict):
        response_id = cast("dict[str, Any]", completion_response).get("id")
    return response_id if isinstance(response_id, str) and response_id else None


class StreamedOpenRouterCosts:
    """Correlates OpenRouter's per-stream cost from the parser to the cost callback.

    LiteLLM rebuilds streamed responses from token-only chunks and drops the
    ``usage.cost`` OpenRouter reports in its final stream chunk (its non-streamed
    path preserves it; streaming snapshots hidden params at stream start). Every
    scan streams, so the OpenRouter streaming handler (see strix.config.models)
    records the cost here keyed by response id, and the callback takes it back out
    for the matching rebuilt response. Entries are removed on read; ``clear()``
    runs per scan so nothing accumulates across runs.
    """

    def __init__(self) -> None:
        self._costs: dict[str, float] = {}
        self._lock = threading.Lock()

    def remember(self, response_id: Any, usage: Any) -> None:
        cost = openrouter_stream_cost(usage)
        if cost is None or not (isinstance(response_id, str) and response_id):
            return
        with self._lock:
            self._costs[response_id] = cost

    def take(self, completion_response: Any) -> float | None:
        response_id = _response_id(completion_response)
        if response_id is None:
            return None
        with self._lock:
            return self._costs.pop(response_id, None)

    def clear(self) -> None:
        with self._lock:
            self._costs.clear()


streamed_openrouter_costs = StreamedOpenRouterCosts()


def litellm_cost_callback(
    kwargs: Any,
    completion_response: Any,
    _start_time: Any = None,
    _end_time: Any = None,
) -> None:
    """LiteLLM ``success_callback`` adapter; forwards observed cost to the active scan."""
    cost: float | None = None
    raw = kwargs.get("response_cost") if isinstance(kwargs, dict) else None
    if isinstance(raw, int | float) and raw > 0:
        cost = float(raw)

    if cost is None:
        hidden = getattr(completion_response, "_hidden_params", None) or {}
        candidate = hidden.get("response_cost") if isinstance(hidden, dict) else None
        if isinstance(candidate, int | float) and candidate > 0:
            cost = float(candidate)
        else:
            headers = hidden.get("additional_headers") or {} if isinstance(hidden, dict) else {}
            raw = (
                headers.get("llm_provider-x-litellm-response-cost")
                if isinstance(headers, dict)
                else None
            )
            try:
                value = float(raw) if raw is not None else None
            except (TypeError, ValueError):
                value = None
            if value is not None and value > 0:
                cost = value

    if cost is None:
        cost = _usage_reported_cost(completion_response)

    # Recover the exact OpenRouter cost the streaming handler stashed for this
    # response — LiteLLM drops it from streamed usage, so nothing above sees it.
    if cost is None:
        cost = streamed_openrouter_costs.take(completion_response)

    if cost is None:
        cost = _estimate_response_cost(kwargs, completion_response)

    if cost is None or cost <= 0:
        return
    report_state = get_global_report_state()
    if report_state is None:
        return
    try:
        report_state.record_observed_llm_cost(cost)
    except Exception:
        logger.exception("Failed to record observed LiteLLM cost")


def _usage_reported_cost(completion_response: Any) -> float | None:
    """Provider-reported cost from the ``usage`` block (e.g. OpenRouter).

    Non-BYOK responses charge everything to ``usage.cost``. BYOK responses
    charge only the OpenRouter fee to ``usage.cost`` (often 0) and report the
    provider charge in ``usage.cost_details.upstream_inference_cost``, so the
    true BYOK total is the sum of the two.
    """
    usage: Any = getattr(completion_response, "usage", None)
    if usage is None and isinstance(completion_response, dict):
        usage = cast("dict[str, Any]", completion_response).get("usage")
    if usage is None:
        return None

    def _field(container: Any, name: str) -> Any:
        if isinstance(container, dict):
            return cast("dict[str, Any]", container).get(name)
        return getattr(container, name, None)

    total = 0.0
    usage_cost = _field(usage, "cost")
    if isinstance(usage_cost, int | float) and usage_cost > 0:
        total += float(usage_cost)

    if bool(_field(usage, "is_byok")):
        upstream = _field(_field(usage, "cost_details"), "upstream_inference_cost")
        if isinstance(upstream, int | float) and upstream > 0:
            total += float(upstream)

    return total if total > 0 else None


def _estimate_response_cost(kwargs: Any, completion_response: Any) -> float | None:
    """Best-effort LiteLLM cost-map estimate when no provider-reported cost exists.

    LiteLLM strips provider cost fields when rebuilding streamed responses and
    returns no ``response_cost`` for models missing from its cost map, so try
    the provider-prefixed name, the raw name, and the bare model name.
    """
    from litellm import completion_cost

    model = kwargs.get("model") if isinstance(kwargs, dict) else None
    if not isinstance(model, str) or not model:
        if isinstance(completion_response, dict):
            model = cast("dict[str, Any]", completion_response).get("model")
        else:
            model = getattr(completion_response, "model", None)
    if not isinstance(model, str) or not model:
        return None

    provider = None
    litellm_params = kwargs.get("litellm_params") if isinstance(kwargs, dict) else None
    if isinstance(litellm_params, dict):
        provider = litellm_params.get("custom_llm_provider")

    usage_payload = _usage_payload(completion_response)
    if usage_payload is None:
        return None

    candidates: list[str] = []
    if isinstance(provider, str) and provider and not model.startswith(f"{provider}/"):
        candidates.append(f"{provider}/{model}")
    candidates.append(model)
    if "/" in model:
        candidates.append(model.rsplit("/", 1)[-1])

    for candidate in candidates:
        resolved = resolve_litellm_model(candidate)
        if not resolved:
            continue
        try:
            value = completion_cost(
                completion_response={"model": resolved, "usage": usage_payload},
                model=resolved,
            )
        except Exception:  # nosec B112  # noqa: BLE001, S112
            continue
        if isinstance(value, int | float) and value > 0:
            return float(value)
    return None


def _usage_payload(completion_response: Any) -> dict[str, Any] | None:
    """Token counts as a plain dict, detached from the response's provider metadata."""
    usage: Any = getattr(completion_response, "usage", None)
    if usage is None and isinstance(completion_response, dict):
        usage = cast("dict[str, Any]", completion_response).get("usage")
    if usage is None:
        return None
    if hasattr(usage, "model_dump"):
        usage = usage.model_dump()
    if not isinstance(usage, dict):
        return None
    payload = cast("dict[str, Any]", usage)
    if not payload.get("total_tokens") and not (
        payload.get("prompt_tokens") or payload.get("completion_tokens")
    ):
        return None
    return payload
