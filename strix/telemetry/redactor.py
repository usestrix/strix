"""
Secret Redaction Utility for Live Tracing.

Identifies and redacts sensitive information like:
- API keys and tokens
- Passwords and credentials
- Authorization headers
- Environment variable values containing secrets
"""

import re
from typing import Any


class SecretRedactor:
    """
    Redacts sensitive information from trace data.
    
    Identifies secrets through:
    - Known key patterns (api_key, password, token, etc.)
    - Value patterns (Bearer tokens, base64-looking strings, etc.)
    - Environment variable patterns
    """

    # Patterns for keys that typically contain secrets
    SECRET_KEY_PATTERNS = [
        re.compile(r"(?i)(api[_-]?key|apikey)"),
        re.compile(r"(?i)(secret[_-]?key|secretkey)"),
        re.compile(r"(?i)(access[_-]?token|accesstoken)"),
        re.compile(r"(?i)(auth[_-]?token|authtoken)"),
        re.compile(r"(?i)(bearer[_-]?token)"),
        re.compile(r"(?i)(refresh[_-]?token)"),
        re.compile(r"(?i)^password$"),
        re.compile(r"(?i)^passwd$"),
        re.compile(r"(?i)(private[_-]?key|privatekey)"),
        re.compile(r"(?i)(client[_-]?secret|clientsecret)"),
        re.compile(r"(?i)(aws[_-]?secret)"),
        re.compile(r"(?i)(database[_-]?password|db[_-]?password)"),
        re.compile(r"(?i)(encryption[_-]?key)"),
        re.compile(r"(?i)(signing[_-]?key)"),
        re.compile(r"(?i)(jwt[_-]?secret)"),
        re.compile(r"(?i)(session[_-]?secret)"),
        re.compile(r"(?i)(cookie[_-]?secret)"),
        re.compile(r"(?i)^credentials?$"),
        re.compile(r"(?i)(sandbox[_-]?token)"),
        re.compile(r"(?i)(perplexity[_-]?api[_-]?key)"),
        re.compile(r"(?i)(openai[_-]?api[_-]?key)"),
        re.compile(r"(?i)(anthropic[_-]?api[_-]?key)"),
    ]

    # Patterns for values that look like secrets
    SECRET_VALUE_PATTERNS = [
        # Bearer tokens
        re.compile(r"Bearer\s+[A-Za-z0-9\-_=]+\.?[A-Za-z0-9\-_=]*\.?[A-Za-z0-9\-_=]*"),
        # API keys (common formats)
        re.compile(r"sk-[A-Za-z0-9]{20,}"),  # OpenAI style
        re.compile(r"sk-ant-[A-Za-z0-9\-]{20,}"),  # Anthropic style
        re.compile(r"pplx-[A-Za-z0-9]{20,}"),  # Perplexity style
        re.compile(r"gsk_[A-Za-z0-9]{20,}"),  # Groq style
        # AWS keys
        re.compile(r"AKIA[0-9A-Z]{16}"),
        # Generic long alphanumeric strings (likely tokens)
        re.compile(r"[A-Za-z0-9]{40,}"),
    ]

    # Environment variables that contain secrets
    SECRET_ENV_VARS = {
        "LLM_API_KEY",
        "OPENAI_API_KEY",
        "ANTHROPIC_API_KEY",
        "PERPLEXITY_API_KEY",
        "AWS_SECRET_ACCESS_KEY",
        "AWS_SESSION_TOKEN",
        "GITHUB_TOKEN",
        "DATABASE_PASSWORD",
        "DB_PASSWORD",
        "SECRET_KEY",
        "JWT_SECRET",
        "SESSION_SECRET",
    }

    REDACTED = "[REDACTED]"

    def __init__(self, additional_patterns: list[re.Pattern[str]] | None = None):
        """
        Initialize the redactor.
        
        Args:
            additional_patterns: Additional regex patterns for secret keys
        """
        self._key_patterns = list(self.SECRET_KEY_PATTERNS)
        if additional_patterns:
            self._key_patterns.extend(additional_patterns)

    def redact(self, data: Any) -> Any:
        """
        Recursively redact secrets from data.
        
        Args:
            data: Data to redact (dict, list, str, or primitive)
            
        Returns:
            Data with secrets redacted
        """
        if data is None:
            return None
        
        if isinstance(data, dict):
            return self._redact_dict(data)
        
        if isinstance(data, list):
            return [self.redact(item) for item in data]
        
        if isinstance(data, str):
            return self._redact_string(data)
        
        # Primitives (int, float, bool) pass through unchanged
        return data

    def _redact_dict(self, data: dict[str, Any]) -> dict[str, Any]:
        """Redact secrets from a dictionary."""
        result = {}
        
        for key, value in data.items():
            # Check if the key indicates a secret
            if self._is_secret_key(key):
                result[key] = self.REDACTED
            else:
                result[key] = self.redact(value)
        
        return result

    def _redact_string(self, value: str) -> str:
        """Redact secrets from a string value."""
        if not value:
            return value
        
        result = value
        
        # Check for Bearer tokens and API keys in the string
        for pattern in self.SECRET_VALUE_PATTERNS:
            result = pattern.sub(self.REDACTED, result)
        
        # Check for Authorization headers
        result = re.sub(
            r'(Authorization["\']?\s*[:=]\s*["\']?)(Bearer\s+)?[A-Za-z0-9\-_.=]+',
            rf"\1{self.REDACTED}",
            result,
            flags=re.IGNORECASE,
        )
        
        # Redact env var values that look like secrets
        for env_var in self.SECRET_ENV_VARS:
            # Match patterns like: ENV_VAR=value or "ENV_VAR": "value"
            result = re.sub(
                rf'({env_var}["\']?\s*[:=]\s*["\']?)([^"\'\s,}}]+)',
                rf"\1{self.REDACTED}",
                result,
            )
        
        return result

    def _is_secret_key(self, key: str) -> bool:
        """Check if a key name indicates it contains a secret."""
        if not key:
            return False
        
        key_lower = key.lower()
        
        # Check against known secret env vars
        if key.upper() in self.SECRET_ENV_VARS:
            return True
        
        # Check against patterns
        for pattern in self._key_patterns:
            if pattern.search(key_lower):
                return True
        
        return False

    def redact_headers(self, headers: dict[str, str]) -> dict[str, str]:
        """
        Specifically redact HTTP headers.
        
        Args:
            headers: HTTP headers dict
            
        Returns:
            Headers with sensitive values redacted
        """
        sensitive_headers = {
            "authorization",
            "x-api-key",
            "api-key",
            "x-auth-token",
            "cookie",
            "set-cookie",
            "x-csrf-token",
            "x-access-token",
        }
        
        result = {}
        for key, value in headers.items():
            if key.lower() in sensitive_headers:
                result[key] = self.REDACTED
            else:
                result[key] = value
        
        return result
