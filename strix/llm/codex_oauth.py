import json
import os
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import requests


CODEX_BACKEND_BASE_URL = "https://chatgpt.com/backend-api/codex"
CODEX_OAUTH_TOKEN_URL = "https://auth.openai.com/oauth/token"  # noqa: S105
CODEX_OAUTH_CLIENT_ID = "app_EMoamEEZ73f0CkXaXp7hrann"


class CodexOAuthError(Exception):
    """Raised when Codex OAuth credentials or backend calls fail."""


@dataclass(frozen=True)
class CodexOAuthCredentials:
    access_token: str
    account_id: str | None = None


def default_codex_home() -> Path:
    configured = os.getenv("CODEX_HOME")
    if configured:
        return Path(configured).expanduser()
    return Path.home() / ".codex"


def load_codex_oauth_credentials(codex_home: Path | None = None) -> CodexOAuthCredentials:
    home = codex_home or default_codex_home()
    raw = _read_codex_auth_json(home)
    tokens = raw.get("tokens")
    if not isinstance(tokens, dict):
        raise CodexOAuthError("Codex auth file does not contain OAuth tokens.")

    access_token = tokens.get("access_token")
    if not isinstance(access_token, str) or not access_token.strip():
        raise CodexOAuthError("Codex auth file does not contain an access token.")

    account_id = tokens.get("account_id")
    if not isinstance(account_id, str) or not account_id.strip():
        account_id = raw.get("account_id")
    if not isinstance(account_id, str) or not account_id.strip():
        account_id = None

    return CodexOAuthCredentials(access_token=access_token, account_id=account_id)


def refresh_codex_oauth_credentials(
    codex_home: Path | None = None,
    post: Any = requests.post,
) -> CodexOAuthCredentials:
    home = codex_home or default_codex_home()
    auth_file = home / "auth.json"
    raw = _read_codex_auth_json(home)

    tokens = raw.get("tokens")
    if not isinstance(tokens, dict):
        raise CodexOAuthError("Codex auth file does not contain OAuth tokens.")

    refresh_token = tokens.get("refresh_token")
    if not isinstance(refresh_token, str) or not refresh_token.strip():
        raise CodexOAuthError("Codex auth file does not contain a refresh token.")

    try:
        response = post(
            CODEX_OAUTH_TOKEN_URL,
            headers={"Content-Type": "application/json"},
            json={
                "client_id": CODEX_OAUTH_CLIENT_ID,
                "grant_type": "refresh_token",
                "refresh_token": refresh_token,
            },
            timeout=30,
        )
    except requests.RequestException as exc:
        raise CodexOAuthError(f"Codex OAuth token refresh failed: {exc}") from exc

    if not response.ok:
        body = response.text[:1000]
        raise CodexOAuthError(
            f"Codex OAuth token refresh failed: HTTP {response.status_code}: {body}"
        )

    try:
        refreshed = response.json()
    except ValueError as exc:
        raise CodexOAuthError(f"Codex OAuth token refresh returned invalid JSON: {exc}") from exc

    for token_name in ("id_token", "access_token", "refresh_token"):
        token_value = refreshed.get(token_name)
        if isinstance(token_value, str) and token_value.strip():
            tokens[token_name] = token_value

    try:
        auth_file.write_text(json.dumps(raw, indent=2), encoding="utf-8")
    except OSError as exc:
        raise CodexOAuthError(f"Could not persist refreshed Codex OAuth tokens: {exc}") from exc

    return load_codex_oauth_credentials(home)


def codex_model_name(model_name: str) -> str:
    return model_name.removeprefix("codex/")


def build_codex_responses_payload(
    model: str,
    messages: list[dict[str, Any]],
    reasoning_effort: str | None,
) -> dict[str, Any]:
    instructions: list[str] = []
    input_items: list[dict[str, Any]] = []

    for message in messages:
        role = str(message.get("role", "user"))
        content = message.get("content", "")
        if role == "system":
            text = _content_to_text(content)
            if text:
                instructions.append(text)
            continue

        response_role = "assistant" if role == "assistant" else "user"
        input_items.append(
            {
                "type": "message",
                "role": response_role,
                "content": _content_to_responses_items(content, response_role),
            }
        )

    payload: dict[str, Any] = {
        "model": model,
        "instructions": "\n\n".join(instructions),
        "input": input_items,
        "tools": [],
        "tool_choice": "none",
        "parallel_tool_calls": False,
        "reasoning": {"effort": reasoning_effort} if reasoning_effort else None,
        "store": False,
        "stream": True,
        "include": [],
    }

    return payload


def complete_codex_oauth(
    model: str,
    messages: list[dict[str, Any]],
    reasoning_effort: str | None,
    timeout: int,
    codex_home: Path | None = None,
    base_url: str = CODEX_BACKEND_BASE_URL,
) -> tuple[str, dict[str, int]]:
    credentials = load_codex_oauth_credentials(codex_home)
    payload = build_codex_responses_payload(model, messages, reasoning_effort)
    response = _post_codex_responses(base_url, credentials, payload, timeout)

    if response.status_code == 401:
        credentials = refresh_codex_oauth_credentials(codex_home)
        response = _post_codex_responses(base_url, credentials, payload, timeout)
        if response.status_code == 401:
            raise CodexOAuthError("Codex OAuth request was unauthorized. Run `codex login` again.")
    if not response.ok:
        body = response.text[:1000]
        raise CodexOAuthError(f"Codex OAuth request failed: HTTP {response.status_code}: {body}")

    content_type = response.headers.get("content-type", "")
    if "application/json" in content_type:
        try:
            return parse_responses_json_response(response.json())
        except ValueError as exc:
            raise CodexOAuthError(f"Codex OAuth JSON response could not be parsed: {exc}") from exc

    return parse_responses_sse_events(response.iter_lines(decode_unicode=True))


def _read_codex_auth_json(codex_home: Path) -> dict[str, Any]:
    auth_file = codex_home / "auth.json"
    if not auth_file.exists():
        raise CodexOAuthError(
            f"Codex auth file not found at {auth_file}. Run `codex login` first."
        )

    try:
        raw = json.loads(auth_file.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise CodexOAuthError(f"Could not read Codex auth file at {auth_file}: {exc}") from exc
    if not isinstance(raw, dict):
        raise CodexOAuthError("Codex auth file is not a JSON object.")
    return raw


def _post_codex_responses(
    base_url: str,
    credentials: CodexOAuthCredentials,
    payload: dict[str, Any],
    timeout: int,
) -> requests.Response:
    headers = {
        "Authorization": f"Bearer {credentials.access_token}",
        "Accept": "text/event-stream",
        "Content-Type": "application/json",
        "version": "strix-codex-oauth",
    }
    if credentials.account_id:
        headers["ChatGPT-Account-ID"] = credentials.account_id

    try:
        return requests.post(
            f"{base_url.rstrip('/')}/responses",
            headers=headers,
            json=payload,
            stream=True,
            timeout=timeout,
        )
    except requests.RequestException as exc:
        raise CodexOAuthError(f"Codex OAuth request failed: {exc}") from exc


def parse_responses_sse_events(lines: Any) -> tuple[str, dict[str, int]]:
    deltas: list[str] = []
    completed_parts: list[str] = []
    usage: dict[str, int] = {}

    for raw_line in lines:
        event = _parse_sse_data_line(raw_line)
        if event is None:
            continue

        event_type = event.get("type")
        if event_type == "response.output_text.delta":
            delta = event.get("delta")
            if isinstance(delta, str):
                deltas.append(delta)
        elif event_type == "response.output_item.done" and not deltas:
            completed_parts.append(_extract_output_text(event.get("item")))
        elif event_type == "response.completed":
            response = event.get("response")
            if isinstance(response, dict):
                usage = _extract_usage(response.get("usage"))
                if not deltas and not completed_parts:
                    completed_parts.append(_extract_output_text(response))

    content = "".join(deltas) if deltas else "".join(completed_parts)
    return content, usage


def parse_responses_json_response(response: dict[str, Any]) -> tuple[str, dict[str, int]]:
    return _extract_output_text(response), _extract_usage(response.get("usage"))


def _parse_sse_data_line(raw_line: Any) -> dict[str, Any] | None:
    if isinstance(raw_line, bytes):
        parsed_line = raw_line.decode("utf-8", errors="replace")
    else:
        parsed_line = raw_line
    if not isinstance(parsed_line, str):
        return None

    line = parsed_line.strip()
    if not line.startswith("data:"):
        return None

    data = line[5:].strip()
    if not data or data == "[DONE]":
        return None

    try:
        event = json.loads(data)
    except json.JSONDecodeError:
        return None
    return event if isinstance(event, dict) else None


def _content_to_text(content: Any) -> str:
    if isinstance(content, str):
        return content
    if isinstance(content, list):
        parts = []
        for item in content:
            if isinstance(item, dict) and item.get("type") == "text":
                text = item.get("text")
                if isinstance(text, str):
                    parts.append(text)
        return "\n".join(parts)
    return str(content)


def _content_to_responses_items(content: Any, role: str) -> list[dict[str, Any]]:
    text_type = "output_text" if role == "assistant" else "input_text"

    if isinstance(content, str):
        return [{"type": text_type, "text": content}]

    if not isinstance(content, list):
        return [{"type": text_type, "text": str(content)}]

    result: list[dict[str, Any]] = []
    for item in content:
        if not isinstance(item, dict):
            continue
        if item.get("type") == "text":
            text = item.get("text")
            if isinstance(text, str):
                result.append({"type": text_type, "text": text})
        elif role == "user" and item.get("type") == "image_url":
            image_url = item.get("image_url")
            if isinstance(image_url, dict):
                image_url = image_url.get("url")
            if isinstance(image_url, str):
                result.append({"type": "input_image", "image_url": image_url})

    return result or [{"type": text_type, "text": ""}]


def _extract_output_text(value: Any) -> str:
    if not isinstance(value, dict):
        return ""

    output_text = value.get("output_text")
    if isinstance(output_text, str):
        return output_text

    parts: list[str] = []
    output = value.get("output")
    if isinstance(output, list):
        parts.extend(_extract_output_text(item) for item in output)

    content = value.get("content")
    if isinstance(content, list):
        for item in content:
            if isinstance(item, dict):
                text = item.get("text")
                if isinstance(text, str):
                    parts.append(text)

    return "".join(parts)


def _extract_usage(value: Any) -> dict[str, int]:
    if not isinstance(value, dict):
        return {}

    usage: dict[str, int] = {}
    input_tokens = value.get("input_tokens") or value.get("prompt_tokens")
    output_tokens = value.get("output_tokens") or value.get("completion_tokens")
    if isinstance(input_tokens, int):
        usage["input_tokens"] = input_tokens
    if isinstance(output_tokens, int):
        usage["output_tokens"] = output_tokens
    return usage
