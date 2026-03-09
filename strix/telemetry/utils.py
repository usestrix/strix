import json
import logging
import re
import threading
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
_SCREENSHOT_OMITTED = "[SCREENSHOT_OMITTED]"
_SCREENSHOT_KEY_PATTERN = re.compile(r"screenshot", re.IGNORECASE)
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
_NOISY_OTEL_CONTENT_PREFIXES = (
    "gen_ai.prompt.",
    "gen_ai.completion.",
    "llm.input_messages.",
    "llm.output_messages.",
)
_NOISY_OTEL_EXACT_KEYS = {
    "llm.input",
    "llm.output",
    "llm.prompt",
    "llm.completion",
}


class _SecretFilth(Filth):  # type: ignore[misc]
    type = "secret"


class _SecretTokenDetector(RegexDetector):  # type: ignore[misc]
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
                if _SCREENSHOT_KEY_PATTERN.search(key_str):
                    sanitized[key_str] = _SCREENSHOT_OMITTED
                elif _SENSITIVE_KEY_PATTERN.search(key_str):
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


def prune_otel_span_attributes(attributes: dict[str, Any]) -> dict[str, Any]:
    """Drop high-volume LLM payload attributes to keep JSONL event files compact."""
    filtered: dict[str, Any] = {}
    filtered_count = 0

    for key, value in attributes.items():
        key_str = str(key)
        if key_str in _NOISY_OTEL_EXACT_KEYS:
            filtered_count += 1
            continue

        if key_str.endswith(".content") and key_str.startswith(_NOISY_OTEL_CONTENT_PREFIXES):
            filtered_count += 1
            continue

        filtered[key_str] = value

    if filtered_count:
        filtered["strix.filtered_attributes_count"] = filtered_count

    return filtered


class JsonlSpanExporter(SpanExporter):  # type: ignore[misc]
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
            attributes = prune_otel_span_attributes(dict(span.attributes or {}))
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
                from traceloop.sdk.instruments import Instruments

                init_kwargs: dict[str, Any] = {
                    "app_name": "strix-agent",
                    "processor": local_processor,
                    "telemetry_enabled": False,
                    "resource_attributes": default_resource_attributes(),
                    "block_instruments": {
                        Instruments.URLLIB3,
                        Instruments.REQUESTS,
                    },
                }
                if remote_enabled:
                    init_kwargs.update(
                        {
                            "api_endpoint": base_url,
                            "api_key": api_key,
                            "headers": headers,
                        }
                    )
                import io
                import sys

                _stdout = sys.stdout
                sys.stdout = io.StringIO()
                try:
                    traceloop.init(**init_kwargs)
                finally:
                    sys.stdout = _stdout
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
