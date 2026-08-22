"""Tests for the model retry policy used by every agent model call.

The SDK's built-in ``http_status`` policy only retries errors that carry a known
HTTP status code. Quota/billing (and other provider-side) failures often surface
*inside* a streamed response as a bare error with no status code, so Strix adds a
statusless retry policy to ``DEFAULT_MODEL_RETRY`` to keep them recoverable — the
behavior the pre-SDK engine had.
"""

from __future__ import annotations

import asyncio

from agents.retry import ModelRetryNormalizedError, RetryPolicyContext
from agents.run_internal.model_retry import _normalize_retry_error

from strix.config import claude_bridge, codex
from strix.config.models import DEFAULT_MODEL_RETRY, _retry_statusless_provider_errors


def _context(
    normalized: ModelRetryNormalizedError, error: Exception | None = None
) -> RetryPolicyContext:
    return RetryPolicyContext(
        error=error or RuntimeError("boom"),
        attempt=1,
        max_retries=5,
        stream=True,
        normalized=normalized,
        provider_advice=None,
    )


def _retries(normalized: ModelRetryNormalizedError, error: Exception | None = None) -> bool:
    """Evaluate the composed DEFAULT_MODEL_RETRY policy for a normalized error."""
    policy = DEFAULT_MODEL_RETRY.policy
    assert policy is not None
    decision = asyncio.run(policy(_context(normalized, error)))
    return bool(getattr(decision, "retry", decision))


def test_statusless_error_is_retried() -> None:
    # A mid-stream quota/billing error arrives with no HTTP status code.
    assert _retries(ModelRetryNormalizedError(status_code=None)) is True


def test_statusless_abort_is_not_retried() -> None:
    # A user/client cancellation must never be retried.
    assert _retries(ModelRetryNormalizedError(status_code=None, is_abort=True)) is False


def test_client_error_is_not_retried() -> None:
    # A definitive 4xx client error (bad request/auth) is not recoverable.
    assert _retries(ModelRetryNormalizedError(status_code=400)) is False


def test_rate_limit_and_server_errors_are_retried() -> None:
    for status in (429, 500, 502, 503, 504, 529):
        assert _retries(ModelRetryNormalizedError(status_code=status)) is True


def test_claude_code_overload_is_retried_end_to_end() -> None:
    # The Claude Code backend bypasses LiteLLM, so it is the only route that can
    # surface a bare 529 ("Overloaded"): LiteLLM's exception mapper folds 529 into
    # a 500 before any policy sees it. Assert the *outcome* through the normalizer
    # the runner actually uses for a custom Model, not just the tagging — tagging a
    # status the policy does not list turns a retryable overload into a dead scan.
    overloaded = claude_bridge.ClaudeStreamError("API Error: Overloaded", status_code=529)
    normalized = _normalize_retry_error(overloaded, None)
    assert normalized.status_code == 529
    assert _retries(normalized, overloaded) is True

    # A rate limit on the same path stays retryable.
    throttled = claude_bridge.ClaudeStreamError("API Error: 429", status_code=429)
    assert _retries(_normalize_retry_error(throttled, None), throttled) is True


def test_timeout_error_is_retried() -> None:
    # A stalled model stream trips the per-request read/inactivity timeout, which
    # the SDK normalizes as a timeout. DEFAULT_MODEL_RETRY must retry it so a hung
    # turn recovers instead of silently wedging the agent.
    assert _retries(ModelRetryNormalizedError(is_timeout=True)) is True
    assert _retries(ModelRetryNormalizedError(is_network_error=True)) is True


def test_content_guardrail_error_is_not_retried() -> None:
    # A guardrail block is status-less, so it would match the statusless policy;
    # the guard must keep it from being retried (retrying never clears it).
    guardrail = codex.CodexContentGuardrailError("gpt-5.6-sol")
    assert _retries(ModelRetryNormalizedError(status_code=None), guardrail) is False
    # A raw provider error carrying the backend's wording is excluded too.
    raw = RuntimeError("This content was flagged for possible cybersecurity risk.")
    assert _retries(ModelRetryNormalizedError(status_code=None), raw) is False


def test_policy_helper_matches_statusless_only() -> None:
    assert _retry_statusless_provider_errors(_context(ModelRetryNormalizedError())) is True
    assert (
        _retry_statusless_provider_errors(_context(ModelRetryNormalizedError(status_code=400)))
        is False
    )
    assert (
        _retry_statusless_provider_errors(
            _context(ModelRetryNormalizedError(status_code=None, is_abort=True))
        )
        is False
    )
