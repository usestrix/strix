import csv
import json
import logging
import re
import threading
import zlib
from collections.abc import Callable, Sequence
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from opentelemetry import trace
from opentelemetry.sdk.trace import ReadableSpan, TracerProvider
from opentelemetry.sdk.trace.export import (
    BatchSpanProcessor,
    SimpleSpanProcessor,
    SpanExporter,
    SpanExportResult,
)
from scrubadub import Scrubber
from scrubadub.detectors import RegexDetector
from scrubadub.filth import Filth


logger = logging.getLogger(__name__)

_REDACTED = "[REDACTED]"
_SENSITIVE_KEY_PATTERN = re.compile(
    r"(api[_-]?key|token|secret|password|authorization|cookie|session|credential|private[_-]?key)",
    re.IGNORECASE,
)
_SENSITIVE_TOKEN_PATTERN = re.compile(
    r"(?i)\b("
    r"bearer\s+[a-z0-9._-]+|"
    r"sk-[a-z0-9_-]{8,}|"
    r"gh[pousr]_[a-z0-9_-]{12,}|"
    r"xox[baprs]-[a-z0-9-]{12,}"
    r")\b"
)
_SCRUBADUB_PLACEHOLDER_PATTERN = re.compile(r"\{\{[^}]+\}\}")
_EVENTS_FILE_LOCKS_LOCK = threading.Lock()
_EVENTS_FILE_LOCKS: dict[str, threading.Lock] = {}


class _SecretFilth(Filth):
    type = "secret"


class _SecretTokenDetector(RegexDetector):
    name = "strix_secret_token_detector"
    filth_cls = _SecretFilth
    regex = _SENSITIVE_TOKEN_PATTERN


class TelemetrySanitizer:
    def __init__(self) -> None:
        self._scrubber = Scrubber(detector_list=[_SecretTokenDetector])

    def sanitize(self, data: Any, key_hint: str | None = None) -> Any:  # noqa: PLR0911
        if data is None:
            return None

        if isinstance(data, dict):
            sanitized: dict[str, Any] = {}
            for key, value in data.items():
                key_str = str(key)
                if _SENSITIVE_KEY_PATTERN.search(key_str):
                    sanitized[key_str] = _REDACTED
                else:
                    sanitized[key_str] = self.sanitize(value, key_hint=key_str)
            return sanitized

        if isinstance(data, list):
            return [self.sanitize(item, key_hint=key_hint) for item in data]

        if isinstance(data, tuple):
            return [self.sanitize(item, key_hint=key_hint) for item in data]

        if isinstance(data, str):
            if key_hint and _SENSITIVE_KEY_PATTERN.search(key_hint):
                return _REDACTED

            cleaned = self._scrubber.clean(data)
            return _SCRUBADUB_PLACEHOLDER_PATTERN.sub(_REDACTED, cleaned)

        if isinstance(data, int | float | bool):
            return data

        return str(data)


def format_trace_id(trace_id: int | None) -> str | None:
    if trace_id is None or trace_id == 0:
        return None
    return f"{trace_id:032x}"


def format_span_id(span_id: int | None) -> str | None:
    if span_id is None or span_id == 0:
        return None
    return f"{span_id:016x}"


def iso_from_unix_ns(unix_ns: int | None) -> str | None:
    if unix_ns is None:
        return None
    try:
        return datetime.fromtimestamp(unix_ns / 1_000_000_000, tz=UTC).isoformat()
    except (OSError, OverflowError, ValueError):
        return None


def sanitize_run_dir_name(run_dir_name: str) -> str:
    normalized = run_dir_name.strip()
    digest = f"{zlib.crc32(normalized.encode('utf-8')):08x}"

    sanitized = re.sub(r"[^A-Za-z0-9._-]+", "-", normalized).strip(".-")
    if not sanitized:
        sanitized = f"run-{digest}"
    elif sanitized != normalized:
        sanitized = f"{sanitized}-{digest}"

    if len(sanitized) > 80:
        prefix = sanitized[:71].rstrip(".-")
        sanitized = f"{prefix}-{digest}" if prefix else f"run-{digest}"

    return sanitized


def get_events_write_lock(output_path: Path) -> threading.Lock:
    path_key = str(output_path.resolve(strict=False))
    with _EVENTS_FILE_LOCKS_LOCK:
        lock = _EVENTS_FILE_LOCKS.get(path_key)
        if lock is None:
            lock = threading.Lock()
            _EVENTS_FILE_LOCKS[path_key] = lock
        return lock


def reset_events_write_locks() -> None:
    with _EVENTS_FILE_LOCKS_LOCK:
        _EVENTS_FILE_LOCKS.clear()


def append_jsonl_record(output_path: Path, record: dict[str, Any]) -> None:
    output_path.parent.mkdir(parents=True, exist_ok=True)
    with get_events_write_lock(output_path), output_path.open("a", encoding="utf-8") as f:
        f.write(json.dumps(record, ensure_ascii=False) + "\n")


def default_resource_attributes() -> dict[str, str]:
    return {
        "service.name": "strix-agent",
        "service.namespace": "strix",
    }


def parse_traceloop_headers(raw_headers: str) -> dict[str, str]:
    headers = raw_headers.strip()
    if not headers:
        return {}

    if headers.startswith("{"):
        try:
            parsed = json.loads(headers)
        except json.JSONDecodeError:
            logger.warning("Invalid TRACELOOP_HEADERS JSON, ignoring custom headers")
            return {}
        if isinstance(parsed, dict):
            return {str(key): str(value) for key, value in parsed.items() if value is not None}
        logger.warning("TRACELOOP_HEADERS JSON must be an object, ignoring custom headers")
        return {}

    result: dict[str, str] = {}
    for part in headers.split(","):
        key, sep, value = part.partition("=")
        if not sep:
            continue
        key = key.strip()
        value = value.strip()
        if key and value:
            result[key] = value
    return result


class JsonlSpanExporter(SpanExporter):
    """Append OTEL spans to JSONL for local run artifacts."""

    def __init__(
        self,
        output_path_getter: Callable[[], Path],
        run_metadata_getter: Callable[[], dict[str, Any]],
        sanitizer: Callable[[Any], Any],
        write_lock_getter: Callable[[Path], threading.Lock],
    ):
        self._output_path_getter = output_path_getter
        self._run_metadata_getter = run_metadata_getter
        self._sanitize = sanitizer
        self._write_lock_getter = write_lock_getter

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
            with self._write_lock_getter(output_path), output_path.open("a", encoding="utf-8") as f:
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
        run_id_attr = (
            attributes.get("strix.run_id")
            or attributes.get("strix_run_id")
            or run_metadata.get("run_id")
            or span.resource.attributes.get("strix.run_id")
        )

        record: dict[str, Any] = {
            "timestamp": iso_from_unix_ns(span.end_time) or datetime.now(UTC).isoformat(),
            "event_type": event_type,
            "run_id": str(run_id_attr or run_metadata.get("run_id") or ""),
            "trace_id": format_trace_id(span_context.trace_id),
            "span_id": format_span_id(span_context.span_id),
            "parent_span_id": format_span_id(parent_context.span_id if parent_context else None),
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
                        "timestamp": iso_from_unix_ns(event.timestamp),
                        "attributes": dict(event.attributes or {}),
                    }
                    for event in span.events
                ]
            )

        return record


def bootstrap_otel(
    *,
    bootstrapped: bool,
    remote_enabled_state: bool,
    bootstrap_lock: threading.Lock,
    traceloop: Any,
    base_url: str,
    api_key: str,
    headers_raw: str,
    output_path_getter: Callable[[], Path],
    run_metadata_getter: Callable[[], dict[str, Any]],
    sanitizer: Callable[[Any], Any],
    write_lock_getter: Callable[[Path], threading.Lock],
    tracer_name: str = "strix.telemetry.tracer",
) -> tuple[Any, bool, bool, bool]:
    with bootstrap_lock:
        if bootstrapped:
            return (
                trace.get_tracer(tracer_name),
                remote_enabled_state,
                bootstrapped,
                remote_enabled_state,
            )

        local_exporter = JsonlSpanExporter(
            output_path_getter=output_path_getter,
            run_metadata_getter=run_metadata_getter,
            sanitizer=sanitizer,
            write_lock_getter=write_lock_getter,
        )
        local_processor = SimpleSpanProcessor(local_exporter)

        headers = parse_traceloop_headers(headers_raw)
        remote_enabled = bool(base_url and api_key)
        otlp_headers = headers
        if remote_enabled:
            otlp_headers = {"Authorization": f"Bearer {api_key}"}
            otlp_headers.update(headers)

        otel_init_ok = False
        if traceloop:
            try:
                init_kwargs: dict[str, Any] = {
                    "app_name": "strix-agent",
                    "processor": local_processor,
                    "telemetry_enabled": False,
                    "resource_attributes": default_resource_attributes(),
                }
                if remote_enabled:
                    init_kwargs.update(
                        {
                            "api_endpoint": base_url,
                            "api_key": api_key,
                            "headers": headers,
                        }
                    )
                traceloop.init(**init_kwargs)
                otel_init_ok = True
            except Exception:
                logger.exception("Failed to initialize Traceloop/OpenLLMetry")
                remote_enabled = False

        if not otel_init_ok:
            from opentelemetry.sdk.resources import Resource

            provider = TracerProvider(resource=Resource.create(default_resource_attributes()))
            provider.add_span_processor(local_processor)
            if remote_enabled:
                try:
                    from opentelemetry.exporter.otlp.proto.http.trace_exporter import (
                        OTLPSpanExporter,
                    )

                    endpoint = base_url.rstrip("/") + "/v1/traces"
                    provider.add_span_processor(
                        BatchSpanProcessor(
                            OTLPSpanExporter(endpoint=endpoint, headers=otlp_headers)
                        )
                    )
                except Exception:
                    logger.exception("Failed to configure OTLP HTTP exporter")
                    remote_enabled = False

            try:
                trace.set_tracer_provider(provider)
                otel_init_ok = True
            except Exception:
                logger.exception("Failed to set OpenTelemetry tracer provider")
                remote_enabled = False

        otel_tracer = trace.get_tracer(tracer_name)
        if otel_init_ok:
            return otel_tracer, remote_enabled, True, remote_enabled

        return otel_tracer, remote_enabled, bootstrapped, remote_enabled_state


def calculate_duration_seconds(start_time: str, end_time: str | None) -> float:
    try:
        start = datetime.fromisoformat(start_time.replace("Z", "+00:00"))
        if end_time:
            end = datetime.fromisoformat(end_time.replace("Z", "+00:00"))
            return (end - start).total_seconds()
    except (ValueError, TypeError):
        pass
    return 0.0


def save_run_artifacts(
    run_dir: Path,
    final_scan_result: str | None,
    vulnerability_reports: list[dict[str, Any]],
    saved_vuln_ids: set[str],
) -> int:
    if final_scan_result:
        penetration_test_report_file = run_dir / "penetration_test_report.md"
        with penetration_test_report_file.open("w", encoding="utf-8") as f:
            f.write("# Security Penetration Test Report\n\n")
            f.write(f"**Generated:** {datetime.now(UTC).strftime('%Y-%m-%d %H:%M:%S UTC')}\n\n")
            f.write(f"{final_scan_result}\n")
        logger.info("Saved final penetration test report to: %s", penetration_test_report_file)

    if not vulnerability_reports:
        return 0

    vuln_dir = run_dir / "vulnerabilities"
    vuln_dir.mkdir(exist_ok=True)

    new_reports = [report for report in vulnerability_reports if report["id"] not in saved_vuln_ids]

    severity_order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
    sorted_reports = sorted(
        vulnerability_reports,
        key=lambda report: (severity_order.get(report["severity"], 5), report["timestamp"]),
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
                for index, location in enumerate(report["code_locations"]):
                    prefix = f"**Location {index + 1}:**"
                    file_ref = location.get("file", "unknown")
                    line_ref = ""
                    if location.get("start_line") is not None:
                        if (
                            location.get("end_line")
                            and location["end_line"] != location["start_line"]
                        ):
                            line_ref = f" (lines {location['start_line']}-{location['end_line']})"
                        else:
                            line_ref = f" (line {location['start_line']})"
                    f.write(f"{prefix} `{file_ref}`{line_ref}\n")
                    if location.get("label"):
                        f.write(f"  {location['label']}\n")
                    if location.get("snippet"):
                        f.write(f"  ```\n  {location['snippet']}\n  ```\n")
                    if location.get("fix_before") or location.get("fix_after"):
                        f.write("\n  **Suggested Fix:**\n")
                        f.write("```diff\n")
                        if location.get("fix_before"):
                            for line in location["fix_before"].splitlines():
                                f.write(f"- {line}\n")
                        if location.get("fix_after"):
                            for line in location["fix_after"].splitlines():
                                f.write(f"+ {line}\n")
                        f.write("```\n")
                    f.write("\n")

            if report.get("remediation_steps"):
                f.write("## Remediation\n\n")
                f.write(f"{report['remediation_steps']}\n\n")

        saved_vuln_ids.add(report["id"])

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
        logger.info("Saved %d new vulnerability report(s) to: %s", len(new_reports), vuln_dir)
    logger.info("Updated vulnerability index: %s", vuln_csv_file)
    return len(new_reports)
