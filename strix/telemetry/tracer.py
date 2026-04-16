import json
import logging
import threading
from collections.abc import Callable
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Optional
from uuid import uuid4

from opentelemetry import trace
from opentelemetry.trace import SpanContext, SpanKind

from strix.config import Config
from strix.telemetry import posthog
from strix.telemetry.flags import is_otel_enabled
from strix.telemetry.utils import (
    TelemetrySanitizer,
    append_jsonl_record,
    bootstrap_otel,
    format_span_id,
    format_trace_id,
    get_events_write_lock,
)


try:
    from traceloop.sdk import Traceloop
except ImportError:  # pragma: no cover - exercised when dependency is absent
    Traceloop = None  # type: ignore[assignment,unused-ignore]


logger = logging.getLogger(__name__)

_global_tracer: Optional["Tracer"] = None

_OTEL_BOOTSTRAP_LOCK = threading.Lock()
_OTEL_BOOTSTRAPPED = False
_OTEL_REMOTE_ENABLED = False


def get_global_tracer() -> Optional["Tracer"]:
    return _global_tracer


def set_global_tracer(tracer: "Tracer") -> None:
    global _global_tracer  # noqa: PLW0603
    _global_tracer = tracer


class Tracer:
    def __init__(self, run_name: str | None = None):
        self.run_name = run_name
        self.run_id = run_name or f"run-{uuid4().hex[:8]}"
        self.start_time = datetime.now(UTC).isoformat()
        self.end_time: str | None = None

        self.agents: dict[str, dict[str, Any]] = {}
        self.tool_executions: dict[int, dict[str, Any]] = {}
        self.chat_messages: list[dict[str, Any]] = []
        self.streaming_content: dict[str, str] = {}
        self.interrupted_content: dict[str, str] = {}

        self.vulnerability_reports: list[dict[str, Any]] = []
        self.final_scan_result: str | None = None

        self.scan_results: dict[str, Any] | None = None
        self.scan_config: dict[str, Any] | None = None
        self.run_metadata: dict[str, Any] = {
            "run_id": self.run_id,
            "run_name": self.run_name,
            "start_time": self.start_time,
            "end_time": None,
            "targets": [],
            "status": "running",
        }
        self._run_dir: Path | None = None
        self._events_file_path: Path | None = None
        self._next_execution_id = 1
        self._next_message_id = 1
        self._saved_vuln_ids: set[str] = set()
        self._run_completed_emitted = False
        self._telemetry_enabled = is_otel_enabled()
        self._sanitizer = TelemetrySanitizer()

        self._otel_tracer: Any = None
        self._remote_export_enabled = False

        self.caido_url: str | None = None
        self.vulnerability_found_callback: Callable[[dict[str, Any]], None] | None = None

        self._setup_telemetry()
        self._emit_run_started_event()

    @property
    def events_file_path(self) -> Path:
        if self._events_file_path is None:
            self._events_file_path = self.get_run_dir() / "events.jsonl"
        return self._events_file_path

    def _active_events_file_path(self) -> Path:
        active = get_global_tracer()
        if active and active._events_file_path is not None:
            return active._events_file_path
        return self.events_file_path

    def _get_events_write_lock(self, output_path: Path | None = None) -> threading.Lock:
        path = output_path or self.events_file_path
        return get_events_write_lock(path)

    def _active_run_metadata(self) -> dict[str, Any]:
        active = get_global_tracer()
        if active:
            return active.run_metadata
        return self.run_metadata

    def _setup_telemetry(self) -> None:
        global _OTEL_BOOTSTRAPPED, _OTEL_REMOTE_ENABLED

        if not self._telemetry_enabled:
            self._otel_tracer = None
            self._remote_export_enabled = False
            return

        run_dir = self.get_run_dir()
        self._events_file_path = run_dir / "events.jsonl"
        base_url = (Config.get("traceloop_base_url") or "").strip()
        api_key = (Config.get("traceloop_api_key") or "").strip()
        headers_raw = Config.get("traceloop_headers") or ""

        (
            self._otel_tracer,
            self._remote_export_enabled,
            _OTEL_BOOTSTRAPPED,
            _OTEL_REMOTE_ENABLED,
        ) = bootstrap_otel(
            bootstrapped=_OTEL_BOOTSTRAPPED,
            remote_enabled_state=_OTEL_REMOTE_ENABLED,
            bootstrap_lock=_OTEL_BOOTSTRAP_LOCK,
            traceloop=Traceloop,
            base_url=base_url,
            api_key=api_key,
            headers_raw=headers_raw,
            output_path_getter=self._active_events_file_path,
            run_metadata_getter=self._active_run_metadata,
            sanitizer=self._sanitize_data,
            write_lock_getter=self._get_events_write_lock,
            tracer_name="strix.telemetry.tracer",
        )

    def _set_association_properties(self, properties: dict[str, Any]) -> None:
        if Traceloop is None:
            return
        sanitized = self._sanitize_data(properties)
        try:
            Traceloop.set_association_properties(sanitized)
        except Exception:  # noqa: BLE001
            logger.debug("Failed to set Traceloop association properties")

    def _sanitize_data(self, data: Any, key_hint: str | None = None) -> Any:
        return self._sanitizer.sanitize(data, key_hint=key_hint)

    def _append_event_record(self, record: dict[str, Any]) -> None:
        try:
            append_jsonl_record(self.events_file_path, record)
        except OSError:
            logger.exception("Failed to append JSONL event record")

    def _enrich_actor(self, actor: dict[str, Any] | None) -> dict[str, Any] | None:
        if not actor:
            return None

        enriched = dict(actor)
        if "agent_name" in enriched:
            return enriched

        agent_id = enriched.get("agent_id")
        if not isinstance(agent_id, str):
            return enriched

        agent_data = self.agents.get(agent_id, {})
        agent_name = agent_data.get("name")
        if isinstance(agent_name, str) and agent_name:
            enriched["agent_name"] = agent_name

        return enriched

    def _emit_event(
        self,
        event_type: str,
        actor: dict[str, Any] | None = None,
        payload: Any | None = None,
        status: str | None = None,
        error: Any | None = None,
        source: str = "strix.tracer",
        include_run_metadata: bool = False,
    ) -> None:
        if not self._telemetry_enabled:
            return

        enriched_actor = self._enrich_actor(actor)
        sanitized_actor = self._sanitize_data(enriched_actor) if enriched_actor else None
        sanitized_payload = self._sanitize_data(payload) if payload is not None else None
        sanitized_error = self._sanitize_data(error) if error is not None else None

        trace_id: str | None = None
        span_id: str | None = None
        parent_span_id: str | None = None

        current_context = trace.get_current_span().get_span_context()
        if isinstance(current_context, SpanContext) and current_context.is_valid:
            parent_span_id = format_span_id(current_context.span_id)

        if self._otel_tracer is not None:
            try:
                with self._otel_tracer.start_as_current_span(
                    f"strix.{event_type}",
                    kind=SpanKind.INTERNAL,
                ) as span:
                    span_context = span.get_span_context()
                    trace_id = format_trace_id(span_context.trace_id)
                    span_id = format_span_id(span_context.span_id)

                    span.set_attribute("strix.event_type", event_type)
                    span.set_attribute("strix.source", source)
                    span.set_attribute("strix.run_id", self.run_id)
                    span.set_attribute("strix.run_name", self.run_name or "")

                    if status:
                        span.set_attribute("strix.status", status)
                    if sanitized_actor is not None:
                        span.set_attribute(
                            "strix.actor",
                            json.dumps(sanitized_actor, ensure_ascii=False),
                        )
                    if sanitized_payload is not None:
                        span.set_attribute(
                            "strix.payload",
                            json.dumps(sanitized_payload, ensure_ascii=False),
                        )
                    if sanitized_error is not None:
                        span.set_attribute(
                            "strix.error",
                            json.dumps(sanitized_error, ensure_ascii=False),
                        )
            except Exception:  # noqa: BLE001
                logger.debug("Failed to create OTEL span for event type '%s'", event_type)

        if trace_id is None:
            trace_id = format_trace_id(uuid4().int & ((1 << 128) - 1)) or uuid4().hex
        if span_id is None:
            span_id = format_span_id(uuid4().int & ((1 << 64) - 1)) or uuid4().hex[:16]

        record = {
            "timestamp": datetime.now(UTC).isoformat(),
            "event_type": event_type,
            "run_id": self.run_id,
            "trace_id": trace_id,
            "span_id": span_id,
            "parent_span_id": parent_span_id,
            "actor": sanitized_actor,
            "payload": sanitized_payload,
            "status": status,
            "error": sanitized_error,
            "source": source,
        }
        if include_run_metadata:
            record["run_metadata"] = self._sanitize_data(self.run_metadata)
        self._append_event_record(record)

    def set_run_name(self, run_name: str) -> None:
        self.run_name = run_name
        self.run_id = run_name
        self.run_metadata["run_name"] = run_name
        self.run_metadata["run_id"] = run_name
        self._run_dir = None
        self._events_file_path = None
        self._run_completed_emitted = False
        self._set_association_properties({"run_id": self.run_id, "run_name": self.run_name or ""})
        self._emit_run_started_event()

    def _emit_run_started_event(self) -> None:
        if not self._telemetry_enabled:
            return

        self._emit_event(
            "run.started",
            payload={
                "run_name": self.run_name,
                "start_time": self.start_time,
                "local_jsonl_path": str(self.events_file_path),
                "remote_export_enabled": self._remote_export_enabled,
            },
            status="running",
            include_run_metadata=True,
        )

    def get_run_dir(self) -> Path:
        if self._run_dir is None:
            runs_dir = Path.cwd() / "strix_runs"
            runs_dir.mkdir(exist_ok=True)

            run_dir_name = self.run_name if self.run_name else self.run_id
            self._run_dir = runs_dir / run_dir_name
            self._run_dir.mkdir(exist_ok=True)

        return self._run_dir

    def add_vulnerability_report(  # noqa: PLR0912
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
        cvss: float | None = None,
        cvss_breakdown: dict[str, str] | None = None,
        endpoint: str | None = None,
        method: str | None = None,
        cve: str | None = None,
        cwe: str | None = None,
        code_locations: list[dict[str, Any]] | None = None,
    ) -> str:
        report_id = f"vuln-{len(self.vulnerability_reports) + 1:04d}"

        report: dict[str, Any] = {
            "id": report_id,
            "title": title.strip(),
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

        self.vulnerability_reports.append(report)
        logger.info(f"Added vulnerability report: {report_id} - {title}")
        posthog.finding(severity)
        self._emit_event(
            "finding.created",
            payload={"report": report},
            status=report["severity"],
            source="strix.findings",
        )

        if self.vulnerability_found_callback:
            self.vulnerability_found_callback(report)

        self.save_run_data()
        return report_id

    def get_existing_vulnerabilities(self) -> list[dict[str, Any]]:
        return list(self.vulnerability_reports)

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

        self.final_scan_result = f"""# Executive Summary

{executive_summary.strip()}

# Methodology

{methodology.strip()}

# Technical Analysis

{technical_analysis.strip()}

# Recommendations

{recommendations.strip()}
"""

        logger.info("Updated scan final fields")
        self._emit_event(
            "finding.reviewed",
            payload={
                "scan_completed": True,
                "vulnerability_count": len(self.vulnerability_reports),
            },
            status="completed",
            source="strix.findings",
        )
        self.save_run_data(mark_complete=True)
        posthog.end(self, exit_reason="finished_by_tool")

    def log_agent_creation(
        self,
        agent_id: str,
        name: str,
        task: str,
        parent_id: str | None = None,
    ) -> None:
        agent_data: dict[str, Any] = {
            "id": agent_id,
            "name": name,
            "task": task,
            "status": "running",
            "parent_id": parent_id,
            "created_at": datetime.now(UTC).isoformat(),
            "updated_at": datetime.now(UTC).isoformat(),
            "tool_executions": [],
        }

        self.agents[agent_id] = agent_data
        self._emit_event(
            "agent.created",
            actor={"agent_id": agent_id, "agent_name": name},
            payload={"task": task, "parent_id": parent_id},
            status="running",
            source="strix.agents",
        )

    def log_chat_message(
        self,
        content: str,
        role: str,
        agent_id: str | None = None,
        metadata: dict[str, Any] | None = None,
    ) -> int:
        message_id = self._next_message_id
        self._next_message_id += 1

        message_data = {
            "message_id": message_id,
            "content": content,
            "role": role,
            "agent_id": agent_id,
            "timestamp": datetime.now(UTC).isoformat(),
            "metadata": metadata or {},
        }

        self.chat_messages.append(message_data)
        self._emit_event(
            "chat.message",
            actor={"agent_id": agent_id, "role": role},
            payload={"message_id": message_id, "content": content, "metadata": metadata or {}},
            status="logged",
            source="strix.chat",
        )
        return message_id

    def log_tool_execution_start(
        self,
        agent_id: str,
        tool_name: str,
        args: dict[str, Any],
    ) -> int:
        execution_id = self._next_execution_id
        self._next_execution_id += 1

        now = datetime.now(UTC).isoformat()
        execution_data = {
            "execution_id": execution_id,
            "agent_id": agent_id,
            "tool_name": tool_name,
            "args": args,
            "status": "running",
            "result": None,
            "timestamp": now,
            "started_at": now,
            "completed_at": None,
        }

        self.tool_executions[execution_id] = execution_data

        if agent_id in self.agents:
            self.agents[agent_id]["tool_executions"].append(execution_id)

        self._emit_event(
            "tool.execution.started",
            actor={
                "agent_id": agent_id,
                "tool_name": tool_name,
                "execution_id": execution_id,
            },
            payload={"args": args},
            status="running",
            source="strix.tools",
        )

        return execution_id

    def update_tool_execution(
        self,
        execution_id: int,
        status: str,
        result: Any | None = None,
    ) -> None:
        if execution_id not in self.tool_executions:
            return

        tool_data = self.tool_executions[execution_id]
        tool_data["status"] = status
        tool_data["result"] = result
        tool_data["completed_at"] = datetime.now(UTC).isoformat()

        tool_name = str(tool_data.get("tool_name", "unknown"))
        agent_id = str(tool_data.get("agent_id", "unknown"))
        error_payload = result if status in {"error", "failed"} else None

        self._emit_event(
            "tool.execution.updated",
            actor={
                "agent_id": agent_id,
                "tool_name": tool_name,
                "execution_id": execution_id,
            },
            payload={"result": result},
            status=status,
            error=error_payload,
            source="strix.tools",
        )

        if tool_name == "create_vulnerability_report":
            finding_status = "reviewed" if status == "completed" else "rejected"
            self._emit_event(
                "finding.reviewed",
                actor={"agent_id": agent_id, "tool_name": tool_name},
                payload={"execution_id": execution_id, "result": result},
                status=finding_status,
                error=error_payload,
                source="strix.findings",
            )

    def update_agent_status(
        self,
        agent_id: str,
        status: str,
        error_message: str | None = None,
    ) -> None:
        if agent_id in self.agents:
            self.agents[agent_id]["status"] = status
            self.agents[agent_id]["updated_at"] = datetime.now(UTC).isoformat()
            if error_message:
                self.agents[agent_id]["error_message"] = error_message

        self._emit_event(
            "agent.status.updated",
            actor={"agent_id": agent_id},
            payload={"error_message": error_message},
            status=status,
            error=error_message,
            source="strix.agents",
        )

    def set_scan_config(self, config: dict[str, Any]) -> None:
        self.scan_config = config
        self.run_metadata.update(
            {
                "targets": config.get("targets", []),
                "user_instructions": config.get("user_instructions", ""),
                "max_iterations": config.get("max_iterations", 200),
            }
        )
        self._set_association_properties(
            {
                "run_id": self.run_id,
                "run_name": self.run_name or "",
                "targets": config.get("targets", []),
                "max_iterations": config.get("max_iterations", 200),
            }
        )
        self._emit_event(
            "run.configured",
            payload={"scan_config": config},
            status="configured",
            source="strix.run",
        )

    def save_run_data(self, mark_complete: bool = False) -> None:
        try:
            run_dir = self.get_run_dir()
            if mark_complete:
                if self.end_time is None:
                    self.end_time = datetime.now(UTC).isoformat()
                self.run_metadata["end_time"] = self.end_time
                self.run_metadata["status"] = "completed"

            if self.final_scan_result:
                penetration_test_report_file = run_dir / "penetration_test_report.md"
                with penetration_test_report_file.open("w", encoding="utf-8") as f:
                    f.write("# Security Penetration Test Report\n\n")
                    f.write(
                        f"**Generated:** {datetime.now(UTC).strftime('%Y-%m-%d %H:%M:%S UTC')}\n\n"
                    )
                    f.write(f"{self.final_scan_result}\n")
                logger.info(
                    "Saved final penetration test report to: %s",
                    penetration_test_report_file,
                )

            if self.vulnerability_reports:
                vuln_dir = run_dir / "vulnerabilities"
                vuln_dir.mkdir(exist_ok=True)

                new_reports = [
                    report
                    for report in self.vulnerability_reports
                    if report["id"] not in self._saved_vuln_ids
                ]

                severity_order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
                sorted_reports = sorted(
                    self.vulnerability_reports,
                    key=lambda report: (
                        severity_order.get(report["severity"], 5),
                        report["timestamp"],
                    ),
                )

                for report in new_reports:
                    vuln_file = vuln_dir / f"{report['id']}.md"
                    with vuln_file.open("w", encoding="utf-8") as f:
                        f.write(f"# {report.get('title', 'Untitled Vulnerability')}\n\n")
                        f.write(f"**ID:** {report.get('id', 'unknown')}\n")
                        f.write(f"**Severity:** {report.get('severity', 'unknown').upper()}\n")
                        f.write(f"**Found:** {report.get('timestamp', 'unknown')}\n")

                        metadata_fields: list[tuple[str, Any]] = [
                            ("Target", report.get("target")),
                            ("Endpoint", report.get("endpoint")),
                            ("Method", report.get("method")),
                            ("CVE", report.get("cve")),
                            ("CWE", report.get("cwe")),
                        ]
                        cvss_score = report.get("cvss")
                        if cvss_score is not None:
                            metadata_fields.append(("CVSS", cvss_score))

                        for label, value in metadata_fields:
                            if value:
                                f.write(f"**{label}:** {value}\n")

                        f.write("\n## Description\n\n")
                        description = report.get("description") or "No description provided."
                        f.write(f"{description}\n\n")

                        if report.get("impact"):
                            f.write("## Impact\n\n")
                            f.write(f"{report['impact']}\n\n")

                        if report.get("technical_analysis"):
                            f.write("## Technical Analysis\n\n")
                            f.write(f"{report['technical_analysis']}\n\n")

                        if report.get("poc_description") or report.get("poc_script_code"):
                            f.write("## Proof of Concept\n\n")
                            if report.get("poc_description"):
                                f.write(f"{report['poc_description']}\n\n")
                            if report.get("poc_script_code"):
                                f.write("```\n")
                                f.write(f"{report['poc_script_code']}\n")
                                f.write("```\n\n")

                        if report.get("code_locations"):
                            f.write("## Code Analysis\n\n")
                            for i, loc in enumerate(report["code_locations"]):
                                prefix = f"**Location {i + 1}:**"
                                file_ref = loc.get("file", "unknown")
                                line_ref = ""
                                if loc.get("start_line") is not None:
                                    if loc.get("end_line") and loc["end_line"] != loc["start_line"]:
                                        line_ref = f" (lines {loc['start_line']}-{loc['end_line']})"
                                    else:
                                        line_ref = f" (line {loc['start_line']})"
                                f.write(f"{prefix} `{file_ref}`{line_ref}\n")
                                if loc.get("label"):
                                    f.write(f"  {loc['label']}\n")
                                if loc.get("snippet"):
                                    f.write(f"  ```\n  {loc['snippet']}\n  ```\n")
                                if loc.get("fix_before") or loc.get("fix_after"):
                                    f.write("\n  **Suggested Fix:**\n")
                                    f.write("```diff\n")
                                    if loc.get("fix_before"):
                                        for line in loc["fix_before"].splitlines():
                                            f.write(f"- {line}\n")
                                    if loc.get("fix_after"):
                                        for line in loc["fix_after"].splitlines():
                                            f.write(f"+ {line}\n")
                                    f.write("```\n")
                                f.write("\n")

                        if report.get("remediation_steps"):
                            f.write("## Remediation\n\n")
                            f.write(f"{report['remediation_steps']}\n\n")

                    self._saved_vuln_ids.add(report["id"])

                vuln_csv_file = run_dir / "vulnerabilities.csv"
                with vuln_csv_file.open("w", encoding="utf-8", newline="") as f:
                    import csv

                    fieldnames = ["id", "title", "severity", "timestamp", "file"]
                    writer = csv.DictWriter(f, fieldnames=fieldnames)
                    writer.writeheader()

                    for report in sorted_reports:
                        writer.writerow(
                            {
                                "id": report["id"],
                                "title": report["title"],
                                "severity": report["severity"].upper(),
                                "timestamp": report["timestamp"],
                                "file": f"vulnerabilities/{report['id']}.md",
                            }
                        )

                if new_reports:
                    logger.info(
                        "Saved %d new vulnerability report(s) to: %s",
                        len(new_reports),
                        vuln_dir,
                    )
                logger.info("Updated vulnerability index: %s", vuln_csv_file)

            logger.info("📊 Essential scan data saved to: %s", run_dir)
            if mark_complete and not self._run_completed_emitted:
                self._emit_event(
                    "run.completed",
                    payload={
                        "duration_seconds": self._calculate_duration(),
                        "vulnerability_count": len(self.vulnerability_reports),
                    },
                    status="completed",
                    source="strix.run",
                    include_run_metadata=True,
                )
                self._run_completed_emitted = True

        except (OSError, RuntimeError):
            logger.exception("Failed to save scan data")

    def _calculate_duration(self) -> float:
        try:
            start = datetime.fromisoformat(self.start_time.replace("Z", "+00:00"))
            if self.end_time:
                end = datetime.fromisoformat(self.end_time.replace("Z", "+00:00"))
                return (end - start).total_seconds()
        except (ValueError, TypeError):
            pass
        return 0.0

    def get_agent_tools(self, agent_id: str) -> list[dict[str, Any]]:
        return [
            exec_data
            for exec_data in list(self.tool_executions.values())
            if exec_data.get("agent_id") == agent_id
        ]

    def get_real_tool_count(self) -> int:
        return sum(
            1
            for exec_data in list(self.tool_executions.values())
            if exec_data.get("tool_name") not in ["scan_start_info", "subagent_start_info"]
        )

    def get_total_llm_stats(self) -> dict[str, Any]:
        from strix.tools.agents_graph.agents_graph_actions import (
            _agent_instances,
            _completed_agent_llm_totals,
            _agent_llm_stats_lock,
        )

        with _agent_llm_stats_lock:
            completed_totals = dict(_completed_agent_llm_totals)
            active_agents = list(_agent_instances.values())

        total_stats = {
            "input_tokens": int(completed_totals.get("input_tokens", 0) or 0),
            "output_tokens": int(completed_totals.get("output_tokens", 0) or 0),
            "cached_tokens": int(completed_totals.get("cached_tokens", 0) or 0),
            "cost": float(completed_totals.get("cost", 0.0) or 0.0),
            "requests": int(completed_totals.get("requests", 0) or 0),
        }

        for agent_instance in active_agents:
            if hasattr(agent_instance, "llm") and hasattr(agent_instance.llm, "_total_stats"):
                agent_stats = agent_instance.llm._total_stats
                total_stats["input_tokens"] += agent_stats.input_tokens
                total_stats["output_tokens"] += agent_stats.output_tokens
                total_stats["cached_tokens"] += agent_stats.cached_tokens
                total_stats["cost"] += agent_stats.cost
                total_stats["requests"] += agent_stats.requests

        total_stats["cost"] = round(total_stats["cost"], 4)

        return {
            "total": total_stats,
            "total_tokens": total_stats["input_tokens"] + total_stats["output_tokens"],
        }

    def update_streaming_content(self, agent_id: str, content: str) -> None:
        self.streaming_content[agent_id] = content

    def clear_streaming_content(self, agent_id: str) -> None:
        self.streaming_content.pop(agent_id, None)

    def get_streaming_content(self, agent_id: str) -> str | None:
        return self.streaming_content.get(agent_id)

    def finalize_streaming_as_interrupted(self, agent_id: str) -> str | None:
        content = self.streaming_content.pop(agent_id, None)
        if content and content.strip():
            self.interrupted_content[agent_id] = content
            self.log_chat_message(
                content=content,
                role="assistant",
                agent_id=agent_id,
                metadata={"interrupted": True},
            )
            return content

        return self.interrupted_content.pop(agent_id, None)

    def cleanup(self) -> None:
        self.save_run_data(mark_complete=True)
