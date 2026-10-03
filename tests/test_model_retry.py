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

from strix.config import claude_bridge, claude_code, codex
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


def test_claude_code_entitlement_error_is_not_retried() -> None:
    # An org policy or plan change will not clear on a second attempt. Retrying it
    # burns the whole backoff ladder on every turn of every agent before the scan
    # gives up, and the user never sees the CLI's own actionable message.
    denied = claude_bridge.ClaudeStreamError(
        "Your organization has disabled Claude subscription access for Claude Code",
        status_code=403,
    )
    assert _retries(_normalize_retry_error(denied, None), denied) is False


def test_claude_code_missing_binary_is_not_retried() -> None:
    # It carries no status code, so without an explicit rule it lands in the
    # statusless fallback and burns five attempts plus roughly three minutes of
    # backoff, per turn and per agent, on a binary that is not installed.
    missing = claude_code.ClaudeCodeError(
        "STRIX_LLM=claude-code/... needs the Claude Code CLI on PATH.", retryable=False
    )
    assert _retries(_normalize_retry_error(missing, None), missing) is False

    # Wrapped by the SDK, it is still recognised.
    try:
        try:
            raise missing
        except claude_code.ClaudeCodeError as exc:
            raise RuntimeError("model call failed") from exc
    except RuntimeError as wrapped:
        assert _retries(_normalize_retry_error(wrapped, None), wrapped) is False


def test_claude_code_transient_transport_failures_still_retry() -> None:
    # A turn that timed out, crashed, or produced no result event may well clear
    # on the next attempt; vetoing those too would kill an agent outright the
    # first time one heavy turn ran past LLM_TIMEOUT.
    for message in (
        "claude -p timed out after 300s",
        "claude -p exited with code 1: (no stderr)",
        "claude -p produced no result event (stderr: (no stderr))",
        "could not launch claude -p: [Errno 24] Too many open files",
    ):
        failure = claude_code.ClaudeCodeError(message)
        assert _retries(_normalize_retry_error(failure, None), failure) is True

    # A genuine provider transient still carries a status and still retries.
    overloaded = claude_bridge.ClaudeStreamError("API Error: Overloaded", status_code=529)
    assert _retries(_normalize_retry_error(overloaded, None), overloaded) is True


def test_claude_code_context_overflow_skips_the_retry_ladder() -> None:
    # Retrying an overflow cannot clear it; only compacting can. Untagged it would
    # hit the statusless fallback and spend five full-context turns first, which
    # no other route does because they all see a typed 400 here.
    tagged = claude_bridge.ClaudeStreamError("prompt is too long", status_code=400)
    assert _retries(_normalize_retry_error(tagged, None), tagged) is False


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
