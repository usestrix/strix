"""SecretSanitizer — Redacts sensitive credentials, API keys, and tokens from report artifacts."""

from __future__ import annotations

import re
from typing import Any

# Regex patterns matching common secret formats
_SECRET_PATTERNS: tuple[re.Pattern[str], ...] = (
    # OpenAI API Keys
    re.compile(r"sk-[a-zA-Z0-9]{20,T}[a-zA-Z0-9_-]*"),
    # Anthropic API Keys
    re.compile(r"sk-ant-api[0-9]{2}-[a-zA-Z0-9_-]{40,}"),
    # GitHub Personal Access Tokens / App Tokens
    re.compile(r"(?:ghp|gho|ghu|ghs|ghr|github_pat)_[a-zA-Z0-9_]{36,100}"),
    # AWS Access Key ID
    re.compile(r"(?:A3T[A-Z0-9]|AKIA|AGPA|AIDA|AROA|AIPA|ANPA|ANVA|ASIA)[A-Z0-9]{16}"),
    # AWS Secret Access Key (heuristic pairing)
    re.compile(r"(?i)(?:aws_secret_access_key|aws_secret_key)\s*[:=]\s*['\"]?([a-zA-Z0-9/+=]{40})['\"]?"),
    # Private Key blocks
    re.compile(r"-----BEGIN (?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----[\s\S]*?-----END (?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----"),
    # Bearer Tokens
    re.compile(r"Bearer\s+[a-zA-Z0-9_\-\.=]{20,}"),
    # Generic Password / Secret Key Value assignments in text or .env format
    re.compile(r"(?i)\b(?:api[_-]?key|secret|password|passwd|auth[_-]?token|access[_-]?token|private[_-]?key)\s*[:=]\s*['\"]?([^\s'\";,#]{8,})['\"]?"),
    # Database connection strings with credentials
    re.compile(r"(?i)(?:postgres|postgresql|mysql|mongodb|redis|mssql)://[^:\s]+:([^@\s]+)@[^/\s]+"),
)

_REDACTION_SUBSTITUTE = "[REDACTED_SECRET]"


class SecretSanitizer:
    """Sanitizes text and structured data by replacing recognized secrets with [REDACTED_SECRET]."""

    @classmethod
    def sanitize_text(cls, text: str) -> str:
        if not text or not isinstance(text, str):
            return text

        sanitized = text
        for pattern in _SECRET_PATTERNS:
            # If pattern has a capture group (e.g. for secret values in key=val), replace group
            if pattern.groups > 0:
                sanitized = pattern.sub(lambda m: m.group(0).replace(m.group(1), _REDACTION_SUBSTITUTE), sanitized)
            else:
                sanitized = pattern.sub(_REDACTION_SUBSTITUTE, sanitized)

        return sanitized

    @classmethod
    def sanitize_data(cls, data: Any) -> Any:
        """Recursively sanitize nested dicts, lists, and strings."""
        if isinstance(data, str):
            return cls.sanitize_text(data)
        if isinstance(data, dict):
            return {key: cls.sanitize_data(value) for key, value in data.items()}
        if isinstance(data, list):
            return [cls.sanitize_data(item) for item in data]
        if isinstance(data, tuple):
            return tuple(cls.sanitize_data(item) for item in data)
        return data
