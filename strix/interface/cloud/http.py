"""HTTP client for the managed Strix platform API (app.strix.ai)."""

from __future__ import annotations

import ipaddress
import math
import os
import re
from typing import TYPE_CHECKING, Any, cast
from urllib.parse import SplitResult, urlsplit

import requests

from strix.config import load_settings
from strix.interface.platform_cli import read_record


if TYPE_CHECKING:
    from pathlib import Path


_DEFAULT_TIMEOUT_S = 120
_SUPABASE_STORAGE_HOST = re.compile(r"^[a-z0-9-]+\.supabase\.co$")
_STORAGE_PATH_PREFIX = "/storage/v1/"
_app_url_override: str | None = None
_token_override_active = False
_workspace_id_override: str | None = None
_timeout_s: float = _DEFAULT_TIMEOUT_S

EXIT_OK = 0
EXIT_ERROR = 1
EXIT_USAGE = 2
EXIT_AUTH = 4
EXIT_PAYMENT = 5


class CloudError(Exception):
    """A failed cloud command. Carries the process exit code."""

    def __init__(self, message: str, *, exit_code: int = EXIT_ERROR, payload: Any = None) -> None:
        super().__init__(message)
        self.exit_code = exit_code
        self.payload = payload


class CloudTransportError(CloudError):
    """A request may have reached the platform, but no response was received."""


def configure(
    *,
    base_url: str | None = None,
    timeout: float | None = None,
    token_override: bool = False,
    workspace_id: str | None = None,
) -> None:
    """Set the platform URL and the request timeout for this process."""
    global _app_url_override, _timeout_s, _token_override_active  # noqa: PLW0603
    global _workspace_id_override  # noqa: PLW0603
    _app_url_override = base_url.rstrip("/") if base_url else None
    _token_override_active = token_override
    explicit_workspace = workspace_id or os.environ.get("STRIX_WORKSPACE_ID")
    if explicit_workspace:
        _workspace_id_override = explicit_workspace.strip()
    elif not token_override and not os.environ.get("STRIX_API_TOKEN"):
        record = read_record()
        stored_workspace = record.get("organization_id") if record is not None else None
        _workspace_id_override = (
            stored_workspace.strip()
            if isinstance(stored_workspace, str) and stored_workspace.strip()
            else None
        )
    else:
        _workspace_id_override = None
    if timeout is not None:
        if not math.isfinite(timeout) or timeout <= 0:
            raise CloudError(
                "request timeout must be a finite number greater than 0.",
                exit_code=EXIT_USAGE,
            )
        _timeout_s = timeout


def app_url() -> str:
    if _app_url_override:
        return _app_url_override
    viewer = load_settings().viewer
    configured = viewer.app_url.rstrip("/")
    explicitly_configured = bool(os.environ.get("STRIX_APP_URL")) or "app_url" in getattr(
        viewer, "model_fields_set", set[str]()
    )
    if explicitly_configured or _token_override_active or os.environ.get("STRIX_API_TOKEN"):
        return configured
    record = read_record()
    stored = record.get("app_url") if record is not None else None
    if isinstance(stored, str) and stored:
        try:
            _parse_origin_url(stored, label="stored platform URL")
        except CloudError:
            pass
        else:
            return stored.rstrip("/")
    return configured


def api_token(override: str | None = None) -> str:
    token = override or os.environ.get("STRIX_API_TOKEN")
    if not token:
        record = read_record()
        if record is not None:
            stored = record.get("api_token")
            if isinstance(stored, str):
                _validate_stored_token_origin(record)
                token = stored
    if not token or not token.strip():
        raise CloudError(
            "not signed in. Run `strix cloud login`, or set STRIX_API_TOKEN.",
            exit_code=EXIT_AUTH,
        )
    return token.strip()


def _validate_stored_token_origin(record: dict[str, Any]) -> None:
    """Never send a stored bearer token to an origin other than its issuer."""
    stored_url = record.get("app_url")
    if not isinstance(stored_url, str) or not stored_url:
        raise CloudError(
            "the stored sign-in is not bound to a trusted platform. Run `strix cloud login` "
            "again before using it.",
            exit_code=EXIT_AUTH,
        )
    try:
        stored_origin = _origin(_parse_origin_url(stored_url, label="stored platform URL"))
        active_origin = _origin(_parse_origin_url(app_url(), label="configured platform URL"))
    except CloudError as exc:
        raise CloudError(
            "the stored sign-in has an invalid platform binding. Run `strix cloud login` again.",
            exit_code=EXIT_AUTH,
        ) from exc
    if stored_origin != active_origin:
        raise CloudError(
            "the stored sign-in belongs to a different platform. Refusing to send its token; "
            "run `strix cloud login` for the configured platform or supply an explicit token.",
            exit_code=EXIT_AUTH,
        )


def request(
    method: str,
    path: str,
    *,
    token: str | None = None,
    query: dict[str, Any] | None = None,
    body: dict[str, Any] | None = None,
    stream: bool = False,
    idempotency_key: str | None = None,
) -> requests.Response:
    url = f"{app_url()}/api/v1{path}"
    headers = {
        "Authorization": f"Bearer {api_token(token)}",
    }
    workspace_id = expected_workspace_id(token_override=token is not None)
    if workspace_id:
        headers["X-Strix-Workspace"] = workspace_id
    if idempotency_key is not None:
        headers["Idempotency-Key"] = idempotency_key
    try:
        response = requests.request(
            method,
            url,
            headers=headers,
            params={
                key: ("true" if value else "false") if isinstance(value, bool) else value
                for key, value in (query or {}).items()
                if value is not None
            }
            or None,
            json=body,
            timeout=_timeout_s,
            stream=stream,
            allow_redirects=False,
        )
    except requests.RequestException as exc:
        raise CloudTransportError(f"could not reach {app_url()}: {exc}") from exc
    return response


def expected_workspace_id(*, token_override: bool) -> str | None:
    """Pin every request in this process to the workspace selected at startup."""
    if _workspace_id_override:
        return _workspace_id_override
    if token_override or _token_override_active or os.environ.get("STRIX_API_TOKEN"):
        return None
    return None


def upload_file(signed_url: str, upload_token: str, path: Path) -> None:
    """Stream a file to a platform-issued storage URL."""
    _validate_upload_url(signed_url)
    response: requests.Response | None = None
    try:
        with path.open("rb") as stream:
            response = requests.put(
                signed_url,
                data=stream,
                headers={
                    "Authorization": f"Bearer {upload_token}",
                    "Content-Type": "application/zip",
                },
                timeout=_timeout_s,
                allow_redirects=False,
            )
    except (OSError, requests.RequestException) as exc:
        raise CloudError(f"source upload failed: {exc}") from exc
    try:
        if 300 <= response.status_code < 400:
            raise CloudError("source upload refused an unexpected redirect")
        if not response.ok:
            detail = ""
            try:
                payload = response.json()
                if isinstance(payload, dict):
                    fields = cast("dict[str, Any]", payload)
                    detail = str(fields.get("message") or fields.get("error") or "")
            except ValueError:
                pass
            raise CloudError(detail or f"source upload failed (HTTP {response.status_code})")
    finally:
        response.close()


def _validate_upload_url(signed_url: str) -> None:
    """Allow uploads only to the trusted app origin or managed Supabase storage."""
    # Supabase signed upload URLs carry their signature in the query string.
    # Keep every origin/path restriction below, but allow that opaque query on
    # this one platform-issued URL type.
    target = _parse_origin_url(
        signed_url,
        label="source upload URL",
        allow_query=True,
    )
    if not target.path.startswith(_STORAGE_PATH_PREFIX):
        raise CloudError("source upload refused a URL outside the storage API")

    configured_app = _parse_origin_url(app_url(), label="configured platform URL")
    if _origin(target) == _origin(configured_app):
        return
    if _is_loopback_host(configured_app.hostname or "") and _is_loopback_host(
        target.hostname or ""
    ):
        return

    hostname = target.hostname or ""
    if (
        target.scheme == "https"
        and target.port in (None, 443)
        and _SUPABASE_STORAGE_HOST.fullmatch(hostname)
    ):
        return
    raise CloudError(
        "source upload refused an untrusted storage origin; only the configured platform "
        "origin and managed Supabase storage are allowed"
    )


def _parse_origin_url(
    value: str,
    *,
    label: str,
    allow_query: bool = False,
) -> SplitResult:
    try:
        parsed = urlsplit(value)
        port = parsed.port
    except (TypeError, ValueError) as exc:
        raise CloudError(f"{label} is invalid") from exc
    hostname = parsed.hostname
    if (
        parsed.scheme not in {"http", "https"}
        or not hostname
        or parsed.username is not None
        or parsed.password is not None
        or (parsed.query and not allow_query)
        or parsed.fragment
        or "\\" in value
        or any(character.isspace() for character in value)
        or "%" in parsed.netloc
    ):
        raise CloudError(f"{label} is invalid")
    try:
        hostname.encode("ascii")
    except UnicodeEncodeError as exc:
        raise CloudError(f"{label} contains a non-ASCII hostname") from exc
    if port is not None and not 1 <= port <= 65535:
        raise CloudError(f"{label} is invalid")
    return parsed


def _origin(parsed: SplitResult) -> tuple[str, str, int]:
    default_port = 443 if parsed.scheme == "https" else 80
    return parsed.scheme, (parsed.hostname or "").lower(), parsed.port or default_port


def _is_loopback_host(hostname: str) -> bool:
    normalized = hostname.lower().rstrip(".")
    if normalized == "localhost" or normalized.endswith(".localhost"):
        return True
    try:
        return ipaddress.ip_address(normalized).is_loopback
    except ValueError:
        return False


def parsed(response: requests.Response) -> Any:
    content_type = response.headers.get("content-type", "")
    if "application/json" in content_type:
        try:
            return response.json()
        except ValueError:
            return response.text
    return response.text


def check(response: requests.Response) -> Any:
    data = parsed(response)
    if 200 <= response.status_code < 300:
        content_type = response.headers.get("content-type", "").lower()
        if "application/json" not in content_type:
            raise CloudError(
                "the server returned a non-JSON response. Check STRIX_APP_URL and preview "
                "access, then retry."
            )
        try:
            return response.json()
        except ValueError as exc:
            raise CloudError(
                "the server returned malformed JSON. Check STRIX_APP_URL and preview "
                "access, then retry."
            ) from exc
    detail = ""
    error_code = ""
    if isinstance(data, dict):
        raw = cast("dict[str, Any]", data)
        detail = str(raw.get("detail") or raw.get("error") or "")
        error_code = str(raw.get("code") or raw.get("error_code") or "")
        nested_error = raw.get("error")
        if isinstance(nested_error, dict):
            nested = cast("dict[str, Any]", nested_error)
            error_code = error_code or str(nested.get("code") or "")
            detail = str(nested.get("message") or detail)
    message = detail or f"HTTP {response.status_code}"
    if error_code == "scan_credit_limit_reached":
        raise CloudError(message, exit_code=EXIT_PAYMENT, payload=data)
    if response.status_code in (401, 403):
        raise CloudError(message, exit_code=EXIT_AUTH, payload=data)
    if response.status_code == 402:
        hint = detail or (
            "not enough credits. Run `strix cloud billing topup --credits N` to buy credits."
        )
        raise CloudError(hint, exit_code=EXIT_PAYMENT, payload=data)
    raise CloudError(message, exit_code=EXIT_ERROR, payload=data)
