import csv
import json
import logging
import re
import threading
import time
from collections.abc import Callable, Sequence
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any, Optional
from uuid import uuid4

from opentelemetry import trace
from opentelemetry.sdk.trace import ReadableSpan, TracerProvider
from opentelemetry.sdk.trace.export import (
    BatchSpanProcessor,
    SimpleSpanProcessor,
    SpanExporter,
    SpanExportResult,
    SpanProcessor,
)
from opentelemetry.trace import SpanContext, SpanKind

from strix.config import Config
from strix.telemetry import posthog


try:
    from traceloop.sdk import Traceloop
except ImportError:  # pragma: no cover - exercised when dependency is absent
    Traceloop = None  # type: ignore[assignment]


logger = logging.getLogger(__name__)

_global_tracer: Optional["Tracer"] = None

_OTEL_BOOTSTRAP_LOCK = threading.Lock()
_OTEL_BOOTSTRAPPED = False
_OTEL_REMOTE_ENABLED = False

_REDACTED = "[REDACTED]"
_SENSITIVE_KEY_PATTERN = re.compile(
    r"(api[_-]?key|token|secret|password|authorization|cookie|session|credential|private[_-]?key)",
    re.IGNORECASE,
)
_SENSITIVE_BEARER_PATTERN = re.compile(r"(?i)\bbearer\s+[a-z0-9._-]+\b")
_SENSITIVE_GENERIC_TOKEN_PATTERN = re.compile(
    r"(?i)\b(sk-[a-z0-9_-]{8,}|gh[pousr]_[a-z0-9_-]{12,}|xox[baprs]-[a-z0-9-]{12,})\b"
)

_PROXY_TOOL_NAMES = {
    "list_requests",
    "view_request",
    "repeat_request",
    "send_request",
    "list_sitemap",
    "view_sitemap_entry",
}

_STREAMING_EVENT_MIN_LENGTH_DELTA = 64
_STREAMING_EVENT_MIN_INTERVAL_SECONDS = 1.0
_DEFAULT_EVENTS_RETENTION_DAYS = 30


def get_global_tracer() -> Optional["Tracer"]:
    return _global_tracer


def set_global_tracer(tracer: "Tracer") -> None:
    global _global_tracer  # noqa: PLW0603
    _global_tracer = tracer


def _format_trace_id(trace_id: int | None) -> str | None:
    if trace_id is None or trace_id == 0:
        return None
    return f"{trace_id:032x}"


def _format_span_id(span_id: int | None) -> str | None:
    if span_id is None or span_id == 0:
        return None
    return f"{span_id:016x}"


def _iso_from_unix_ns(unix_ns: int | None) -> str | None:
    if unix_ns is None:
        return None
    try:
        return datetime.fromtimestamp(unix_ns / 1_000_000_000, tz=UTC).isoformat()
    except (OSError, OverflowError, ValueError):
        return None


class JsonlSpanExporter(SpanExporter):
    """Append OTEL spans to JSONL for local run artifacts."""

    def __init__(
        self,
        output_path_getter: Callable[[], Path],
        run_metadata_getter: Callable[[], dict[str, Any]],
        sanitizer: Callable[[Any], Any],
    ):
        self._output_path_getter = output_path_getter
        self._run_metadata_getter = run_metadata_getter
        self._sanitize = sanitizer
        self._lock = threading.Lock()

    def export(self, spans: Sequence[ReadableSpan]) -> SpanExportResult:
        records: list[dict[str, Any]] = []
        for span in spans:
            attributes = dict(span.attributes or {})
            if "strix.event_type" in attributes:
                # Tracer events are written directly in Tracer._emit_event.
                continue
            records.append(self._span_to_record(span, attributes))

        if not records:
            return SpanExportResult.SUCCESS

        try:
            output_path = self._output_path_getter()
            output_path.parent.mkdir(parents=True, exist_ok=True)
            with self._lock, output_path.open("a", encoding="utf-8") as f:
                for record in records:
                    f.write(json.dumps(record, ensure_ascii=False) + "\n")
        except OSError:
            logger.exception("Failed to write OTEL span records to JSONL")
            return SpanExportResult.FAILURE

        return SpanExportResult.SUCCESS

    def shutdown(self) -> None:
        return None

    def force_flush(self, timeout_millis: int = 30_000) -> bool:  # noqa: ARG002
        return True

    def _span_to_record(
        self,
        span: ReadableSpan,
        attributes: dict[str, Any],
    ) -> dict[str, Any]:
        span_context = span.get_span_context()
        parent_context = span.parent

        status = None
        if span.status and span.status.status_code:
            status = span.status.status_code.name.lower()

        event_type = str(attributes.get("gen_ai.operation.name", span.name))
        run_metadata = self._run_metadata_getter()
        run_id_attr = attributes.get("strix.run_id") or span.resource.attributes.get("strix.run_id")

        record: dict[str, Any] = {
            "timestamp": _iso_from_unix_ns(span.end_time) or datetime.now(UTC).isoformat(),
            "event_type": event_type,
            "run_id": str(run_id_attr or run_metadata.get("run_id") or ""),
            "trace_id": _format_trace_id(span_context.trace_id),
            "span_id": _format_span_id(span_context.span_id),
            "parent_span_id": _format_span_id(parent_context.span_id if parent_context else None),
            "actor": None,
            "payload": None,
            "status": status,
            "error": None,
            "source": "otel.span",
            "span_name": span.name,
            "span_kind": span.kind.name.lower(),
            "attributes": self._sanitize(attributes),
        }

        if span.events:
            record["otel_events"] = self._sanitize(
                [
                    {
                        "name": event.name,
                        "timestamp": _iso_from_unix_ns(event.timestamp),
                        "attributes": dict(event.attributes or {}),
                    }
                    for event in span.events
                ]
            )

        return record


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
        self._last_streaming_event_ts: dict[str, float] = {}
        self._last_streaming_event_len: dict[str, int] = {}
        self._events_retention_days = self._resolve_events_retention_days()
        self._events_retention_pruned = False

        self._otel_tracer: Any = None
        self._remote_export_enabled = False

        self.caido_url: str | None = None
        self.vulnerability_found_callback: Callable[[dict[str, Any]], None] | None = None

        self._setup_telemetry()
        self._emit_event(
            "run.started",
            payload={
                "run_name": self.run_name,
                "start_time": self.start_time,
                "local_jsonl_path": str(self.events_file_path),
                "remote_export_enabled": self._remote_export_enabled,
                "local_retention_days": self._events_retention_days,
            },
            status="running",
        )

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

    def _active_run_metadata(self) -> dict[str, Any]:
        active = get_global_tracer()
        if active:
            return active.run_metadata
        return self.run_metadata

    def _resource_attributes(self) -> dict[str, Any]:
        return {
            "service.name": "strix-agent",
            "service.namespace": "strix",
            "strix.run_id": self.run_id,
            "strix.run_name": self.run_name or "",
            "strix.start_time": self.start_time,
        }

    def _parse_traceloop_headers(self) -> dict[str, str]:
        raw_headers = (Config.get("traceloop_headers") or "").strip()
        if not raw_headers:
            return {}

        if raw_headers.startswith("{"):
            try:
                parsed = json.loads(raw_headers)
            except json.JSONDecodeError:
                logger.warning("Invalid TRACELOOP_HEADERS JSON, ignoring custom headers")
                return {}
            if isinstance(parsed, dict):
                return {str(k): str(v) for k, v in parsed.items() if v is not None}
            logger.warning("TRACELOOP_HEADERS JSON must be an object, ignoring custom headers")
            return {}

        result: dict[str, str] = {}
        for part in raw_headers.split(","):
            key, sep, value = part.partition("=")
            if not sep:
                continue
            key = key.strip()
            value = value.strip()
            if key and value:
                result[key] = value
        return result

    def _setup_telemetry(self) -> None:
        global _OTEL_BOOTSTRAPPED, _OTEL_REMOTE_ENABLED  # noqa: PLW0603

        self.get_run_dir()
        self._events_file_path = self.get_run_dir() / "events.jsonl"

        with _OTEL_BOOTSTRAP_LOCK:
            if _OTEL_BOOTSTRAPPED:
                self._otel_tracer = trace.get_tracer("strix.telemetry.tracer")
                self._remote_export_enabled = _OTEL_REMOTE_ENABLED
                return

            local_exporter = JsonlSpanExporter(
                output_path_getter=self._active_events_file_path,
                run_metadata_getter=self._active_run_metadata,
                sanitizer=self._sanitize_data,
            )
            local_processor = SimpleSpanProcessor(local_exporter)
            processors: list[SpanProcessor] = [local_processor]

            base_url = (Config.get("traceloop_base_url") or "").strip()
            api_key = (Config.get("traceloop_api_key") or "").strip()
            headers = self._parse_traceloop_headers()

            remote_enabled = bool(base_url and api_key)
            if remote_enabled and not headers:
                headers = {"Authorization": f"Bearer {api_key}"}

            if Traceloop:
                if remote_enabled:
                    try:
                        remote_processor = Traceloop.get_default_span_processor(
                            api_endpoint=base_url,
                            api_key=api_key,
                            headers=headers,
                        )
                        processors.append(remote_processor)
                    except Exception:
                        logger.exception("Failed to configure Traceloop remote exporter")
                        remote_enabled = False

                try:
                    Traceloop.init(
                        app_name="strix-agent",
                        api_endpoint=base_url or "https://api.traceloop.com",
                        api_key=api_key or None,
                        headers=headers,
                        processor=processors if len(processors) > 1 else processors[0],
                        telemetry_enabled=False,
                        resource_attributes=self._resource_attributes(),
                    )
                except Exception:
                    logger.exception("Failed to initialize Traceloop/OpenLLMetry")
            else:
                from opentelemetry.sdk.resources import Resource

                provider = TracerProvider(resource=Resource.create(self._resource_attributes()))
                provider.add_span_processor(local_processor)
                if remote_enabled:
                    try:
                        from opentelemetry.exporter.otlp.proto.http.trace_exporter import (
                            OTLPSpanExporter,
                        )

                        endpoint = base_url.rstrip("/") + "/v1/traces"
                        provider.add_span_processor(
                            BatchSpanProcessor(OTLPSpanExporter(endpoint=endpoint, headers=headers))
                        )
                    except Exception:
                        logger.exception("Failed to configure OTLP HTTP exporter")
                        remote_enabled = False

                try:
                    trace.set_tracer_provider(provider)
                except Exception:
                    logger.exception("Failed to set OpenTelemetry tracer provider")

            self._otel_tracer = trace.get_tracer("strix.telemetry.tracer")
            self._remote_export_enabled = remote_enabled
            _OTEL_REMOTE_ENABLED = remote_enabled
            _OTEL_BOOTSTRAPPED = True

    def _resolve_events_retention_days(self) -> int:
        raw_value = (Config.get("strix_events_retention_days") or "").strip()
        if not raw_value:
            return _DEFAULT_EVENTS_RETENTION_DAYS

        try:
            value = int(raw_value)
        except ValueError:
            logger.warning(
                "Invalid STRIX_EVENTS_RETENTION_DAYS value '%s'; defaulting to %d days",
                raw_value,
                _DEFAULT_EVENTS_RETENTION_DAYS,
            )
            return _DEFAULT_EVENTS_RETENTION_DAYS

        return max(value, 0)

    def _prune_expired_event_logs(self, runs_dir: Path) -> None:
        if self._events_retention_pruned:
            return

        self._events_retention_pruned = True
        retention_days = self._events_retention_days
        if retention_days == 0:
            return

        cutoff = datetime.now(UTC) - timedelta(days=retention_days)
        removed_files = 0

        for events_file in runs_dir.glob("*/events.jsonl"):
            try:
                modified_at = datetime.fromtimestamp(events_file.stat().st_mtime, tz=UTC)
            except OSError:
                continue

            if modified_at >= cutoff:
                continue

            try:
                events_file.unlink()
                removed_files += 1
            except OSError:
                logger.debug("Failed to remove expired telemetry file: %s", events_file)

        if removed_files:
            logger.info(
                "Removed %d telemetry log file(s) older than %d days from %s",
                removed_files,
                retention_days,
                runs_dir,
            )

    def _set_association_properties(self, properties: dict[str, Any]) -> None:
        if Traceloop is None:
            return
        sanitized = self._sanitize_data(properties)
        try:
            Traceloop.set_association_properties(sanitized)
        except Exception:  # noqa: BLE001
            logger.debug("Failed to set Traceloop association properties")

    def _sanitize_data(self, data: Any, key_hint: str | None = None) -> Any:  # noqa: PLR0911
        if data is None:
            return None

        if isinstance(data, dict):
            sanitized: dict[str, Any] = {}
            for key, value in data.items():
                key_str = str(key)
                if _SENSITIVE_KEY_PATTERN.search(key_str):
                    sanitized[key_str] = _REDACTED
                else:
                    sanitized[key_str] = self._sanitize_data(value, key_hint=key_str)
            return sanitized

        if isinstance(data, list):
            return [self._sanitize_data(item, key_hint=key_hint) for item in data]

        if isinstance(data, tuple):
            return [self._sanitize_data(item, key_hint=key_hint) for item in data]

        if isinstance(data, str):
            if key_hint and _SENSITIVE_KEY_PATTERN.search(key_hint):
                return _REDACTED

            return _SENSITIVE_GENERIC_TOKEN_PATTERN.sub(
                _REDACTED,
                _SENSITIVE_BEARER_PATTERN.sub(_REDACTED, data),
            )

        if isinstance(data, int | float | bool):
            return data

        return str(data)

    def _append_event_record(self, record: dict[str, Any]) -> None:
        try:
            output_path = self.events_file_path
            output_path.parent.mkdir(parents=True, exist_ok=True)
            with output_path.open("a", encoding="utf-8") as f:
                f.write(json.dumps(self._sanitize_data(record), ensure_ascii=False) + "\n")
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
    ) -> None:
        enriched_actor = self._enrich_actor(actor)
        sanitized_actor = self._sanitize_data(enriched_actor) if enriched_actor else None
        sanitized_payload = self._sanitize_data(payload) if payload is not None else None
        sanitized_error = self._sanitize_data(error) if error is not None else None

        trace_id: str | None = None
        span_id: str | None = None
        parent_span_id: str | None = None

        current_context = trace.get_current_span().get_span_context()
        if isinstance(current_context, SpanContext) and current_context.is_valid:
            parent_span_id = _format_span_id(current_context.span_id)

        if self._otel_tracer is not None:
            try:
                with self._otel_tracer.start_as_current_span(
                    f"strix.{event_type}",
                    kind=SpanKind.INTERNAL,
                ) as span:
                    span_context = span.get_span_context()
                    trace_id = _format_trace_id(span_context.trace_id)
                    span_id = _format_span_id(span_context.span_id)

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
            trace_id = _format_trace_id(uuid4().int & ((1 << 128) - 1)) or uuid4().hex
        if span_id is None:
            span_id = _format_span_id(uuid4().int & ((1 << 64) - 1)) or uuid4().hex[:16]

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
            "run_metadata": self._sanitize_data(self.run_metadata),
        }
        self._append_event_record(record)

    def set_run_name(self, run_name: str) -> None:
        self.run_name = run_name
        self.run_id = run_name
        self.run_metadata["run_name"] = run_name
        self.run_metadata["run_id"] = run_name

    def get_run_dir(self) -> Path:
        if self._run_dir is None:
            runs_dir = Path.cwd() / "strix_runs"
            runs_dir.mkdir(exist_ok=True)
            self._prune_expired_event_logs(runs_dir)

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

        if tool_name in _PROXY_TOOL_NAMES and status == "completed":
            self._emit_event(
                "traffic.intercepted",
                actor={"agent_id": agent_id, "tool_name": tool_name},
                payload={"execution_id": execution_id, "result": result},
                status="captured",
                source="strix.proxy",
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
        self.get_run_dir()
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

    def save_run_data(self, mark_complete: bool = False) -> None:  # noqa: PLR0912, PLR0915
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
                    f"Saved final penetration test report to: {penetration_test_report_file}"
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
                    key=lambda x: (severity_order.get(x["severity"], 5), x["timestamp"]),
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
                        desc = report.get("description") or "No description provided."
                        f.write(f"{desc}\n\n")

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
                        f"Saved {len(new_reports)} new vulnerability report(s) to: {vuln_dir}"
                    )
                logger.info(f"Updated vulnerability index: {vuln_csv_file}")

            logger.info(f"📊 Essential scan data saved to: {run_dir}")
            if mark_complete and not self._run_completed_emitted:
                self._emit_event(
                    "run.completed",
                    payload={
                        "duration_seconds": self._calculate_duration(),
                        "vulnerability_count": len(self.vulnerability_reports),
                    },
                    status="completed",
                    source="strix.run",
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
        from strix.tools.agents_graph.agents_graph_actions import _agent_instances

        total_stats = {
            "input_tokens": 0,
            "output_tokens": 0,
            "cached_tokens": 0,
            "cost": 0.0,
            "requests": 0,
        }

        for agent_instance in _agent_instances.values():
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

    def _should_emit_streaming_update(self, agent_id: str, content_length: int) -> bool:
        previous_length = self._last_streaming_event_len.get(agent_id)
        previous_timestamp = self._last_streaming_event_ts.get(agent_id)
        now = time.monotonic()

        if previous_length is None or previous_timestamp is None:
            return True

        if content_length < previous_length:
            return True

        if (content_length - previous_length) >= _STREAMING_EVENT_MIN_LENGTH_DELTA:
            return True

        return (now - previous_timestamp) >= _STREAMING_EVENT_MIN_INTERVAL_SECONDS

    def _emit_streaming_update(
        self,
        agent_id: str,
        content_length: int,
        force: bool = False,
    ) -> None:
        if not force and not self._should_emit_streaming_update(agent_id, content_length):
            return

        now = time.monotonic()
        self._last_streaming_event_ts[agent_id] = now
        self._last_streaming_event_len[agent_id] = content_length
        self._emit_event(
            "agent.streaming.updated",
            actor={"agent_id": agent_id},
            payload={"content_length": content_length},
            status="streaming",
            source="strix.agents",
        )

    def update_streaming_content(self, agent_id: str, content: str) -> None:
        self.streaming_content[agent_id] = content
        self._emit_streaming_update(agent_id, len(content))

    def clear_streaming_content(self, agent_id: str) -> None:
        content = self.streaming_content.pop(agent_id, None)
        if content:
            content_length = len(content)
            last_length = self._last_streaming_event_len.get(agent_id)
            if last_length != content_length:
                self._emit_streaming_update(agent_id, content_length, force=True)

        self._last_streaming_event_ts.pop(agent_id, None)
        self._last_streaming_event_len.pop(agent_id, None)
        self._emit_event(
            "agent.streaming.cleared",
            actor={"agent_id": agent_id},
            status="cleared",
            source="strix.agents",
        )

    def get_streaming_content(self, agent_id: str) -> str | None:
        return self.streaming_content.get(agent_id)

    def finalize_streaming_as_interrupted(self, agent_id: str) -> str | None:
        content = self.streaming_content.pop(agent_id, None)
        if content and content.strip():
            self._emit_streaming_update(agent_id, len(content), force=True)
            self._last_streaming_event_ts.pop(agent_id, None)
            self._last_streaming_event_len.pop(agent_id, None)
            self.interrupted_content[agent_id] = content
            self.log_chat_message(
                content=content,
                role="assistant",
                agent_id=agent_id,
                metadata={"interrupted": True},
            )
            self._emit_event(
                "agent.streaming.interrupted",
                actor={"agent_id": agent_id},
                payload={"content_length": len(content)},
                status="interrupted",
                source="strix.agents",
            )
            return content

        return self.interrupted_content.pop(agent_id, None)

    def cleanup(self) -> None:
        self.save_run_data(mark_complete=True)
