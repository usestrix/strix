"""Tests for the OrcaRouter provider: API-key and OAuth 2.0 + PKCE sign-in, routing,
credential lifecycle, and the model catalog.

A local fake of the OrcaRouter auth and API origins stands in for the network,
so the sign-in runs end to end: authorize URL -> loopback callback or pasted
code -> key exchange -> stored key -> an ``orcarouter/`` model bound to it.
"""

from __future__ import annotations

import base64
import hashlib
import json
import threading
import urllib.parse
import urllib.request
from http.server import BaseHTTPRequestHandler, HTTPServer
from typing import TYPE_CHECKING, Any

import pytest

from strix.config import codex, loader, orcarouter
from strix.config.models import StrixProvider
from strix.config.settings import DedupeSettings
from strix.interface import auth_cli, environment
from strix.interface.main import _orcarouter_error_hint
from strix.report.dedupe import resolve_dedupe_model


if TYPE_CHECKING:
    from collections.abc import Iterator
    from pathlib import Path


ISSUED_KEY = "sk-orca-issued-by-login-0001"
ENV_KEY = "sk-orca-from-env-0002"
LLM_KEY = "sk-orca-from-llm-api-key-0003"

_ENV_VARS = (
    "STRIX_LLM",
    "LLM_API_KEY",
    "OPENAI_API_KEY",
    "LLM_API_BASE",
    "OPENAI_API_BASE",
    "OPENAI_BASE_URL",
    "LITELLM_BASE_URL",
    "OLLAMA_API_BASE",
    orcarouter.API_KEY_ENV,
    orcarouter.SHARED_BASE_ENV,
    orcarouter.AUTH_BASE_ENV,
    orcarouter.API_BASE_ENV,
)


def _b64url_sha256(value: str) -> str:
    return base64.urlsafe_b64encode(hashlib.sha256(value.encode()).digest()).rstrip(b"=").decode()


class FakeOrcaRouter:
    """Both OrcaRouter origins on one loopback server."""

    def __init__(self) -> None:
        self.requests: list[tuple[str, str, dict[str, Any]]] = []
        self.pending: dict[str, str] = {}  # code -> challenge
        self.exchange_status: int | None = None
        self.exchange_body: dict[str, Any] | None = None
        self.catalog: Any = {
            "data": [
                {"id": "openai/gpt-5.5", "supported_endpoint_types": ["openai", "anthropic"]},
                {"id": "deepseek/deepseek-v4-pro", "supported_endpoint_types": ["openai"]},
                {"id": "vendor/image-only", "supported_endpoint_types": ["image-generation"]},
                {"id": "", "supported_endpoint_types": ["openai"]},
                {"id": 42},
                "not-an-object",
            ]
        }
        fake = self

        class Handler(BaseHTTPRequestHandler):
            def log_message(self, *args: Any) -> None:
                pass

            def _reply(self, status: int, payload: Any) -> None:
                body = payload if isinstance(payload, bytes) else json.dumps(payload).encode()
                self.send_response(status)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

            def do_GET(self) -> None:
                fake.requests.append(("GET", self.path, dict(self.headers)))
                if self.path == "/v1/models":
                    self._reply(200, fake.catalog)
                    return
                self._reply(404, {"error": "not found"})

            def do_POST(self) -> None:
                length = int(self.headers.get("Content-Length") or 0)
                body = json.loads(self.rfile.read(length) or b"{}")
                fake.requests.append(("POST", self.path, body))
                if self.path != orcarouter.EXCHANGE_PATH:
                    self._reply(404, {"error": "not found"})
                    return
                if fake.exchange_status is not None:
                    self._reply(fake.exchange_status, fake.exchange_body or {})
                    return
                challenge = fake.pending.pop(body.get("code"), None)  # single use
                if challenge is None or body.get("code_challenge_method") != "S256":
                    self._reply(403, {"error": "invalid code"})
                    return
                if _b64url_sha256(body.get("code_verifier", "")) != challenge:
                    self._reply(403, {"error": "verifier mismatch"})
                    return
                self._reply(200, {"key": ISSUED_KEY, "user_id": 42, "scope": "api"})

        self._httpd = HTTPServer(("127.0.0.1", 0), Handler)
        self.base = f"http://127.0.0.1:{self._httpd.server_address[1]}"
        self._thread = threading.Thread(target=self._httpd.serve_forever, daemon=True)
        self._thread.start()

    def approve(self, authorize_url: str, code: str = "auth-code-1") -> dict[str, str]:
        """What the consent screen does: mint a code bound to the challenge."""
        parsed = urllib.parse.urlparse(authorize_url)
        assert f"{parsed.scheme}://{parsed.netloc}" == self.base
        assert parsed.path == orcarouter.AUTHORIZE_PATH
        params = {k: v[0] for k, v in urllib.parse.parse_qs(parsed.query).items()}
        self.pending[code] = params["code_challenge"]
        return params

    def close(self) -> None:
        self._httpd.shutdown()
        self._httpd.server_close()


@pytest.fixture(autouse=True)
def _isolate(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    for name in _ENV_VARS:
        monkeypatch.delenv(name, raising=False)
    monkeypatch.setattr(codex, "AUTH_PATH", tmp_path / ".strix" / "subscription-auth.json")
    monkeypatch.setattr(loader, "_cached", None)
    monkeypatch.setattr(loader, "_override", tmp_path / "no-cli-config.json")
    monkeypatch.setattr(orcarouter, "_active", None)


@pytest.fixture
def fake(monkeypatch: pytest.MonkeyPatch) -> Iterator[FakeOrcaRouter]:
    server = FakeOrcaRouter()
    monkeypatch.setenv(orcarouter.AUTH_BASE_ENV, server.base)
    monkeypatch.setenv(orcarouter.API_BASE_ENV, f"{server.base}/v1")
    try:
        yield server
    finally:
        server.close()


def _stored_record(key: str = ISSUED_KEY, **extra: Any) -> dict[str, Any]:
    return {"type": "api_key", "provider": "orcarouter", "key": key, "scope": "api", **extra}


def _unwrap(model: object) -> object:
    while hasattr(model, "_inner"):
        model = model._inner
    return model


# --- Route and origins -------------------------------------------------------


@pytest.mark.parametrize(
    ("model", "expected"),
    [
        ("orcarouter/openai/gpt-5.5", "openai/gpt-5.5"),
        ("OrcaRouter/orcarouter/auto", "orcarouter/auto"),
        ("orcarouter/", None),
        ("openrouter/openai/gpt-5.5", None),
        (None, None),
    ],
)
def test_route_model(model: str | None, expected: str | None) -> None:
    assert orcarouter.route_model(model) == expected


def test_default_origins_keep_auth_and_inference_apart() -> None:
    assert orcarouter.auth_base() == "https://www.orcarouter.ai"
    assert orcarouter.api_base() == "https://api.orcarouter.ai/v1"


def test_shared_base_with_explicit_overrides_taking_precedence(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv(orcarouter.SHARED_BASE_ENV, "https://orca.internal/")
    assert orcarouter.auth_base() == "https://orca.internal"
    assert orcarouter.api_base() == "https://orca.internal/v1"
    monkeypatch.setenv(orcarouter.AUTH_BASE_ENV, "https://auth.internal")
    monkeypatch.setenv(orcarouter.API_BASE_ENV, "https://api.internal/v1")
    assert orcarouter.auth_base() == "https://auth.internal"
    assert orcarouter.api_base() == "https://api.internal/v1"


@pytest.mark.parametrize("url", ["http://orca.example.com", "ftp://127.0.0.1", "orca"])
def test_remote_origins_must_be_https(url: str, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv(orcarouter.AUTH_BASE_ENV, url)
    with pytest.raises(orcarouter.OrcaRouterAuthError) as exc:
        orcarouter.auth_base()
    assert exc.value.code == "insecure_origin"


@pytest.mark.parametrize("url", ["http://127.0.0.1:8080", "http://localhost:3000", "http://[::1]"])
def test_http_allowed_for_loopback(url: str, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv(orcarouter.API_BASE_ENV, url)
    assert orcarouter.api_base() == url


# --- PKCE --------------------------------------------------------------------


def test_pkce_is_fresh_s256_and_unpadded() -> None:
    first = orcarouter.generate_pkce()
    second = orcarouter.generate_pkce()
    assert first != second
    for verifier, challenge in (first, second):
        assert 43 <= len(verifier) <= 128
        assert "=" not in challenge
        assert challenge == _b64url_sha256(verifier)
    assert orcarouter.create_state() != orcarouter.create_state()


def test_authorize_url_uses_auth_origin_and_carries_only_the_challenge() -> None:
    verifier, challenge = orcarouter.generate_pkce()
    url = orcarouter.build_authorize_url(challenge, "st4te", "oob")
    parsed = urllib.parse.urlparse(url)
    params = {k: v[0] for k, v in urllib.parse.parse_qs(parsed.query).items()}
    assert f"{parsed.scheme}://{parsed.netloc}{parsed.path}" == "https://www.orcarouter.ai/auth"
    assert params == {
        "callback_url": "oob",
        "code_challenge": challenge,
        "code_challenge_method": "S256",
        "state": "st4te",
        "app_name": "Strix",
        "scope": "api",
    }
    assert verifier not in url


def test_state_comparison() -> None:
    assert orcarouter.state_matches("abc", "abc")
    assert not orcarouter.state_matches("abd", "abc")
    assert not orcarouter.state_matches(None, "abc")


# --- Key exchange ------------------------------------------------------------


def test_exchange_posts_code_and_verifier_to_the_auth_origin(fake: FakeOrcaRouter) -> None:
    verifier, challenge = orcarouter.generate_pkce()
    fake.pending["c1"] = challenge
    record = orcarouter.exchange_code("c1", verifier)
    assert record["key"] == ISSUED_KEY
    assert record["scope"] == "api"
    assert record["user_id"] == "42"
    assert record["needs_reauth"] is False
    method, path, body = fake.requests[-1]
    assert (method, path) == ("POST", "/api/v1/auth/keys")
    assert body == {"code": "c1", "code_verifier": verifier, "code_challenge_method": "S256"}


def test_reused_code_is_rejected(fake: FakeOrcaRouter) -> None:
    verifier, challenge = orcarouter.generate_pkce()
    fake.pending["c1"] = challenge
    orcarouter.exchange_code("c1", verifier)
    with pytest.raises(orcarouter.OrcaRouterAuthError) as exc:
        orcarouter.exchange_code("c1", verifier)
    assert exc.value.code == "invalid_code"


def test_wrong_verifier_is_rejected_without_leaking_it(fake: FakeOrcaRouter) -> None:
    _verifier, challenge = orcarouter.generate_pkce()
    fake.pending["c1"] = challenge
    with pytest.raises(orcarouter.OrcaRouterAuthError) as exc:
        orcarouter.exchange_code("c1", "wrong-verifier-value")
    assert exc.value.code == "invalid_code"
    assert "wrong-verifier-value" not in str(exc.value)


@pytest.mark.parametrize(
    ("status", "code"),
    [
        (400, "bad_request"),
        (403, "invalid_code"),
        (429, "rate_limited"),
        (500, "exchange_http_error"),
    ],
)
def test_exchange_http_errors(status: int, code: str, fake: FakeOrcaRouter) -> None:
    fake.exchange_status = status
    with pytest.raises(orcarouter.OrcaRouterAuthError) as exc:
        orcarouter.exchange_code("c1", "verifier")
    assert exc.value.code == code


@pytest.mark.parametrize(
    ("body", "code"),
    [
        ({"key": ISSUED_KEY, "scope": "connector-lite"}, "scope_mismatch"),
        ({"scope": "api"}, "bad_response"),
        ({"key": "   "}, "bad_response"),
    ],
)
def test_exchange_rejects_unusable_grants(
    body: dict[str, Any], code: str, fake: FakeOrcaRouter
) -> None:
    fake.exchange_status = 200
    fake.exchange_body = body
    with pytest.raises(orcarouter.OrcaRouterAuthError) as exc:
        orcarouter.exchange_code("c1", "verifier")
    assert exc.value.code == code
    assert ISSUED_KEY not in str(exc.value)


def test_exchange_network_failure_hides_request_details(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv(orcarouter.AUTH_BASE_ENV, "http://127.0.0.1:9")  # discard port
    with pytest.raises(orcarouter.OrcaRouterAuthError) as exc:
        orcarouter.exchange_code("c1", "secret-verifier")
    assert exc.value.code == "unavailable"
    assert "secret-verifier" not in str(exc.value)


# --- Stored sign-in and credential resolution --------------------------------


def test_store_coexists_with_the_chatgpt_sign_in() -> None:
    codex_record = {"type": "oauth", "access": "a", "refresh": "r", "account_id": "acct"}
    codex.save_record(codex_record)
    orcarouter.save_record(_stored_record())
    assert orcarouter.read_record() == _stored_record()
    assert codex.read_record() == codex_record
    assert oct(codex.AUTH_PATH.stat().st_mode & 0o777) == "0o600"

    assert orcarouter.logout() is True
    assert orcarouter.read_record() is None
    assert codex.read_record() == codex_record
    assert orcarouter.logout() is False


def test_credential_resolution_order(monkeypatch: pytest.MonkeyPatch) -> None:
    with pytest.raises(orcarouter.OrcaRouterAuthError) as exc:
        orcarouter.resolve_credential(None)
    assert exc.value.code == "not_authenticated"
    assert "strix auth login orcarouter" in str(exc.value)
    assert orcarouter.API_KEY_ENV in str(exc.value)

    assert orcarouter.resolve_credential(LLM_KEY) == orcarouter.Credential(LLM_KEY, "llm_api_key")
    orcarouter.save_record(_stored_record())
    assert orcarouter.resolve_credential(LLM_KEY) == orcarouter.Credential(ISSUED_KEY, "login")
    monkeypatch.setenv(orcarouter.API_KEY_ENV, ENV_KEY)
    assert orcarouter.resolve_credential(LLM_KEY) == orcarouter.Credential(ENV_KEY, "env")


def test_credential_repr_hides_the_key() -> None:
    assert ENV_KEY not in repr(orcarouter.Credential(ENV_KEY, "env"))
    assert ENV_KEY not in orcarouter.mask_key(ENV_KEY)


def test_revoked_sign_in_requires_reauth_but_keeps_the_key() -> None:
    orcarouter.save_record(_stored_record())
    assert orcarouter.mark_needs_reauth(ISSUED_KEY) is True
    assert orcarouter.read_record()["key"] == ISSUED_KEY  # type: ignore[index]
    with pytest.raises(orcarouter.OrcaRouterAuthError) as exc:
        orcarouter.resolve_credential(None)
    assert exc.value.code == "needs_reauth"
    # An explicit API key still works while the sign-in is broken.
    assert orcarouter.resolve_credential(LLM_KEY).source == "llm_api_key"


def test_stale_rejection_never_flags_a_newer_sign_in() -> None:
    orcarouter.save_record(_stored_record("sk-orca-new-generation-9999"))
    assert orcarouter.mark_needs_reauth(ISSUED_KEY) is False
    assert not orcarouter.read_record().get("needs_reauth")  # type: ignore[union-attr]


def test_unauthorized_marks_only_the_signed_in_key() -> None:
    orcarouter.save_record(_stored_record())
    orcarouter.remember_active(orcarouter.Credential(ENV_KEY, "env"))
    assert orcarouter.API_KEY_ENV in orcarouter.handle_unauthorized()
    assert not orcarouter.read_record().get("needs_reauth")  # type: ignore[union-attr]

    orcarouter.remember_active(orcarouter.Credential(ISSUED_KEY, "login"))
    assert "strix auth login orcarouter" in orcarouter.handle_unauthorized()
    assert orcarouter.read_record()["needs_reauth"] is True  # type: ignore[index]


# --- Routing -----------------------------------------------------------------


def test_orcarouter_models_route_through_the_openai_compatible_client(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv(orcarouter.API_KEY_ENV, ENV_KEY)
    model = _unwrap(StrixProvider().get_model("orcarouter/openai/gpt-5.5"))
    assert model.model == "openai/openai/gpt-5.5"  # type: ignore[attr-defined]
    assert model.base_url == "https://api.orcarouter.ai/v1"  # type: ignore[attr-defined]
    assert model.api_key == ENV_KEY  # type: ignore[attr-defined]


def test_signed_in_key_is_used_over_a_stale_llm_api_key(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("LLM_API_KEY", "sk-or-another-providers-key")
    orcarouter.save_record(_stored_record())
    model = _unwrap(StrixProvider().get_model("orcarouter/deepseek/deepseek-v4-pro"))
    assert model.api_key == ISSUED_KEY  # type: ignore[attr-defined]
    assert orcarouter._active == orcarouter.Credential(ISSUED_KEY, "login")


def test_api_key_in_llm_api_key_works(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("LLM_API_KEY", LLM_KEY)
    model = _unwrap(StrixProvider().get_model("orcarouter/orcarouter/auto"))
    assert model.api_key == LLM_KEY  # type: ignore[attr-defined]
    assert model.model == "openai/orcarouter/auto"  # type: ignore[attr-defined]


def test_dedupe_model_on_orcarouter_uses_its_own_key(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv(orcarouter.API_KEY_ENV, ENV_KEY)
    dedupe = DedupeSettings(
        STRIX_DEDUPE_MODEL="orcarouter/deepseek/deepseek-v4-flash",
        DEDUPE_LLM_API_KEY="sk-orca-dedupe-0004",
    )
    model = _unwrap(resolve_dedupe_model(dedupe, "orcarouter/deepseek/deepseek-v4-flash"))
    assert model.api_key == "sk-orca-dedupe-0004"  # type: ignore[attr-defined]
    assert model.base_url == "https://api.orcarouter.ai/v1"  # type: ignore[attr-defined]


def test_other_prefixes_are_unchanged() -> None:
    model = _unwrap(StrixProvider().get_model("openrouter/z-ai/glm-5.3"))
    assert model.model == "openrouter/z-ai/glm-5.3"  # type: ignore[attr-defined]


# --- Model catalog -----------------------------------------------------------


def test_catalog_keeps_only_well_formed_chat_models(fake: FakeOrcaRouter) -> None:
    assert orcarouter.fetch_models("sk-orca-catalog") == [
        "openai/gpt-5.5",
        "deepseek/deepseek-v4-pro",
    ]
    _method, path, headers = fake.requests[-1]
    assert path == "/v1/models"
    assert headers["Authorization"] == "Bearer sk-orca-catalog"


def test_catalog_falls_back_to_the_seed(fake: FakeOrcaRouter) -> None:
    assert orcarouter.available_models() == (
        ["openai/gpt-5.5", "deepseek/deepseek-v4-pro"],
        True,
    )
    fake.catalog = {"data": "nope"}
    assert orcarouter.available_models() == (list(orcarouter.SEED_MODELS), False)


@pytest.mark.usefixtures("fake")
def test_oversized_catalog_is_discarded(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(orcarouter, "_CATALOG_MAX_BYTES", 64)
    assert orcarouter.fetch_models() == []


def test_unreachable_catalog_returns_nothing(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv(orcarouter.API_BASE_ENV, "http://127.0.0.1:9/v1")
    assert orcarouter.fetch_models() == []


def test_seed_keeps_the_verified_models() -> None:
    assert orcarouter.SEED_MODELS == (
        "openai/gpt-5.5",
        "anthropic/claude-opus-4.8",
        "google/gemini-3.5-flash",
        "deepseek/deepseek-v4-pro",
        "orcarouter/auto",
    )


# --- `strix auth login orcarouter` -------------------------------------------


def _browser_that_approves(fake: FakeOrcaRouter, seen: dict[str, Any], **overrides: str) -> Any:
    def _open(url: str) -> bool:
        params = fake.approve(url)
        seen["params"] = params
        query = {"code": "auth-code-1", "state": params["state"], **overrides}
        callback = f"{params['callback_url']}?{urllib.parse.urlencode(query)}"
        with urllib.request.urlopen(callback, timeout=5) as response:  # noqa: S310
            seen["page"] = response.read().decode()
        return True

    return _open


def test_login_via_loopback_redirect_stores_the_key(
    fake: FakeOrcaRouter, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    seen: dict[str, Any] = {}
    monkeypatch.setattr(auth_cli.webbrowser, "open", _browser_that_approves(fake, seen))

    assert auth_cli.run_auth(["login", "orcarouter"]) == 0

    callback = urllib.parse.urlparse(seen["params"]["callback_url"])
    assert (callback.scheme, callback.hostname, callback.path) == ("http", "127.0.0.1", "/callback")
    assert seen["params"]["code_challenge_method"] == "S256"
    assert "connected to OrcaRouter" in seen["page"]
    assert orcarouter.read_record()["key"] == ISSUED_KEY  # type: ignore[index]
    exchange = next(body for method, path, body in fake.requests if method == "POST")
    assert _b64url_sha256(exchange["code_verifier"]) == seen["params"]["code_challenge"]

    out = capsys.readouterr().out
    assert "orcarouter/openai/gpt-5.5" in out
    assert ISSUED_KEY not in out
    assert exchange["code_verifier"] not in out


def test_login_denied_in_the_browser_stores_nothing(
    fake: FakeOrcaRouter, monkeypatch: pytest.MonkeyPatch
) -> None:
    seen: dict[str, Any] = {}
    browser = _browser_that_approves(fake, seen, code="", error="access_denied")
    monkeypatch.setattr(auth_cli.webbrowser, "open", browser)
    assert auth_cli.run_auth(["login", "orcarouter"]) == 1
    assert "Sign-in cancelled" in seen["page"]
    assert orcarouter.read_record() is None
    assert not [r for r in fake.requests if r[0] == "POST"]


def test_login_rejects_a_forged_state(
    fake: FakeOrcaRouter, monkeypatch: pytest.MonkeyPatch
) -> None:
    seen: dict[str, Any] = {}
    monkeypatch.setattr(
        auth_cli.webbrowser, "open", _browser_that_approves(fake, seen, state="forged")
    )
    assert auth_cli.run_auth(["login", "orcarouter"]) == 1
    assert orcarouter.read_record() is None
    assert not [r for r in fake.requests if r[0] == "POST"]


def test_login_with_manual_out_of_band_code(
    fake: FakeOrcaRouter, monkeypatch: pytest.MonkeyPatch
) -> None:
    seen: dict[str, Any] = {}

    def _open(url: str) -> bool:
        seen["params"] = fake.approve(url, code="shown-code")
        return True

    monkeypatch.setattr(auth_cli.webbrowser, "open", _open)
    monkeypatch.setattr(auth_cli.Console, "input", lambda *_a, **_k: " shown-code \n")

    assert auth_cli.run_auth(["login", "orcarouter", "--manual"]) == 0
    assert seen["params"]["callback_url"] == "oob"
    assert seen["params"]["code_challenge_method"] == "S256"
    assert orcarouter.read_record()["key"] == ISSUED_KEY  # type: ignore[index]


def test_login_timeout_falls_back_to_pasting(
    fake: FakeOrcaRouter, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(auth_cli, "_CALLBACK_TIMEOUT_S", 0.05)
    monkeypatch.setattr(auth_cli.webbrowser, "open", lambda url: bool(fake.approve(url)))
    monkeypatch.setattr(auth_cli.Console, "input", lambda *_a, **_k: "auth-code-1")
    assert auth_cli.run_auth(["login", "orcarouter"]) == 0
    assert orcarouter.read_record() is not None


@pytest.mark.usefixtures("fake")
def test_login_with_an_expired_code_fails_cleanly(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(auth_cli.webbrowser, "open", lambda _url: True)
    monkeypatch.setattr(auth_cli.Console, "input", lambda *_a, **_k: "never-issued")
    assert auth_cli.run_auth(["login", "orcarouter", "--manual"]) == 1
    assert orcarouter.read_record() is None


def test_login_rate_limited(fake: FakeOrcaRouter, monkeypatch: pytest.MonkeyPatch) -> None:
    fake.exchange_status = 429
    monkeypatch.setattr(auth_cli.webbrowser, "open", lambda _url: True)
    monkeypatch.setattr(auth_cli.Console, "input", lambda *_a, **_k: "any")
    assert auth_cli.run_auth(["login", "orcarouter", "--manual"]) == 1


def test_login_replaces_a_revoked_sign_in(
    fake: FakeOrcaRouter, monkeypatch: pytest.MonkeyPatch
) -> None:
    orcarouter.save_record(_stored_record("sk-orca-revoked-0005", needs_reauth=True))
    seen: dict[str, Any] = {}
    monkeypatch.setattr(auth_cli.webbrowser, "open", _browser_that_approves(fake, seen))
    assert auth_cli.run_auth(["login", "orcarouter"]) == 0
    assert orcarouter.resolve_credential(None) == orcarouter.Credential(ISSUED_KEY, "login")


# --- status / logout ---------------------------------------------------------


def test_status_reports_the_active_source_without_the_key(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    assert auth_cli.run_auth(["status", "orcarouter"]) == 1
    orcarouter.save_record(_stored_record())
    assert auth_cli.run_auth(["status", "orcarouter"]) == 0
    out = capsys.readouterr().out
    assert "strix auth login orcarouter" in out
    assert ISSUED_KEY not in out

    monkeypatch.setenv(orcarouter.API_KEY_ENV, ENV_KEY)
    assert auth_cli.run_auth(["status", "orcarouter"]) == 0
    out = capsys.readouterr().out
    assert orcarouter.API_KEY_ENV in out
    assert ENV_KEY not in out


def test_bare_status_includes_orcarouter_when_signed_in() -> None:
    assert auth_cli.run_auth(["status"]) == 1
    orcarouter.save_record(_stored_record())
    assert auth_cli.run_auth(["status"]) == 0


def test_logout_orcarouter_leaves_chatgpt_alone() -> None:
    codex_record = {"type": "oauth", "access": "a", "refresh": "r", "account_id": "acct"}
    codex.save_record(codex_record)
    orcarouter.save_record(_stored_record())
    assert auth_cli.run_auth(["logout", "orcarouter"]) == 0
    assert orcarouter.read_record() is None
    assert codex.read_record() == codex_record
    assert auth_cli.run_auth(["logout", "gemini"]) == 2


# --- Startup checks and error hints ------------------------------------------


def test_environment_requires_an_orcarouter_credential(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.setenv("STRIX_LLM", "orcarouter/openai/gpt-5.5")
    monkeypatch.setattr(environment, "report_error", lambda *_a, **_k: None)
    with pytest.raises(SystemExit):
        environment.validate_environment()
    assert "strix auth login orcarouter" in capsys.readouterr().out


def test_401_hint_flags_the_signed_in_key_for_reauth() -> None:
    orcarouter.save_record(_stored_record())
    orcarouter.remember_active(orcarouter.Credential(ISSUED_KEY, "login"))
    exc = RuntimeError("litellm.AuthenticationError: Error code: 401 - Invalid API key")
    hint = _orcarouter_error_hint(exc, "orcarouter/openai/gpt-5.5")
    assert hint is not None
    assert "strix auth login orcarouter" in hint
    assert orcarouter.read_record()["needs_reauth"] is True  # type: ignore[index]


def test_error_hint_ignores_other_providers() -> None:
    exc = RuntimeError("Error code: 401")
    assert _orcarouter_error_hint(exc, "openrouter/z-ai/glm-5.3") is None


def test_usage_lists_both_providers_verbatim(capsys: pytest.CaptureFixture[str]) -> None:
    assert auth_cli.run_auth(["--help"]) == 0
    out = capsys.readouterr().out
    assert "strix auth login orcarouter [--manual]" in out
    assert "strix auth status [chatgpt|orcarouter]" in out
