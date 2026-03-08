import re
import zlib
from datetime import UTC, datetime
from typing import Any

from scrubadub import Scrubber
from scrubadub.detectors import RegexDetector
from scrubadub.filth import Filth


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
