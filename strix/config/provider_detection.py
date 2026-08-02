"""Credential and environment detection helpers for LLM providers.

Pure predicates over exception chains, installed modules, environment
variables, and on-disk credential files. They hold no provider registry
state, so both the provider registry and the auth-status logic can use them.
"""

from __future__ import annotations

import configparser
import importlib.util
import json
import logging
import os
from pathlib import Path


logger = logging.getLogger(__name__)


def _exception_chain_messages(exc: BaseException) -> tuple[str, ...]:
    messages: list[str] = []
    seen: set[int] = set()
    stack = [exc]
    while stack:
        current = stack.pop()
        if id(current) in seen:
            continue
        seen.add(id(current))
        messages.append(type(current).__name__)
        messages.append(str(current))
        status_code = getattr(current, "status_code", None)
        if status_code is not None:
            messages.append(f"HTTP {status_code}")
        response = getattr(current, "response", None)
        response_status = getattr(response, "status_code", None)
        if response_status is not None:
            messages.append(f"HTTP {response_status}")
        if current.__cause__ is not None:
            stack.append(current.__cause__)
        if current.__context__ is not None:
            stack.append(current.__context__)
    return tuple(messages)


def provider_authentication_error(exc: BaseException) -> bool:
    """Return whether an exception definitively indicates rejected credentials."""
    joined = " ".join(_exception_chain_messages(exc)).lower()
    markers = (
        "http 401",
        "error code: 401",
        "status code: 401",
        "401 unauthorized",
        "authenticationerror",
        "authentication error",
        "invalid api key",
        "incorrect api key",
        "invalid x-api-key",
        "invalid authentication",
        "invalid bearer token",
    )
    return any(marker in joined for marker in markers)


def _module_available(name: str) -> bool:
    try:
        return importlib.util.find_spec(name) is not None
    except (ImportError, ModuleNotFoundError, ValueError):
        return False


def _process_environment_value(name: str) -> str | None:
    target = name.upper()
    return next(
        (value for key, value in os.environ.items() if key.upper() == target and value),
        None,
    )


def _json_object_file(path: Path) -> bool:
    try:
        payload: object = json.loads(path.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, OSError):
        return False
    return isinstance(payload, dict)


def _vertex_credentials_detected() -> bool:
    explicit = os.environ.get("GOOGLE_APPLICATION_CREDENTIALS", "").strip()
    if explicit and _json_object_file(Path(explicit).expanduser()):
        return True

    raw_credentials = os.environ.get("VERTEXAI_CREDENTIALS", "").strip()
    if raw_credentials:
        try:
            payload: object = json.loads(raw_credentials)
        except json.JSONDecodeError:
            return _json_object_file(Path(raw_credentials).expanduser())
        return isinstance(payload, dict)

    cloud_config = os.environ.get("CLOUDSDK_CONFIG", "").strip()
    adc_path = (
        Path(cloud_config).expanduser() if cloud_config else Path.home() / ".config" / "gcloud"
    ) / "application_default_credentials.json"
    return _json_object_file(adc_path)


def _aws_profile_detected() -> bool:
    profile = (
        os.environ.get("AWS_PROFILE", "").strip()
        or os.environ.get("AWS_DEFAULT_PROFILE", "").strip()
        or "default"
    )
    credentials_path = Path(
        os.environ.get("AWS_SHARED_CREDENTIALS_FILE", "~/.aws/credentials")
    ).expanduser()
    config_path = Path(os.environ.get("AWS_CONFIG_FILE", "~/.aws/config")).expanduser()
    for path, section, is_config in (
        (credentials_path, profile, False),
        (config_path, profile if profile == "default" else f"profile {profile}", True),
    ):
        parser = configparser.RawConfigParser()
        try:
            parser.read(path, encoding="utf-8")
        except (configparser.Error, OSError):
            continue
        if not parser.has_section(section):
            continue
        values = {key: value.strip() for key, value in parser.items(section) if value.strip()}
        if values.get("aws_access_key_id") and values.get("aws_secret_access_key"):
            return True
        if not is_config:
            continue
        if values.get("credential_process") or values.get("sso_session"):
            return True
        if values.get("sso_start_url") and values.get("sso_account_id"):
            return True
        if values.get("role_arn") and any(
            values.get(name)
            for name in ("source_profile", "credential_source", "web_identity_token_file")
        ):
            return True
    return False


def _aws_credentials_detected(*, allow_bedrock_token: bool) -> bool:
    access_key = os.environ.get("AWS_ACCESS_KEY_ID", "").strip()
    secret_key = os.environ.get("AWS_SECRET_ACCESS_KEY", "").strip()
    if access_key and secret_key:
        return True
    if allow_bedrock_token and os.environ.get("AWS_BEARER_TOKEN_BEDROCK", "").strip():
        return True
    token_file = os.environ.get("AWS_WEB_IDENTITY_TOKEN_FILE", "").strip()
    role_arn = os.environ.get("AWS_ROLE_ARN", "").strip()
    if token_file and role_arn and Path(token_file).expanduser().is_file():
        return True
    if os.environ.get("AWS_CONTAINER_CREDENTIALS_RELATIVE_URI", "").strip():
        return True
    if os.environ.get("AWS_CONTAINER_CREDENTIALS_FULL_URI", "").strip():
        return True
    return _aws_profile_detected()
